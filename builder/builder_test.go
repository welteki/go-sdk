package builder

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	hmac "github.com/alexellis/hmac/v2"
	"github.com/google/go-cmp/cmp"
	"github.com/openfaas/go-sdk/seal"
)

// readCloser wraps an io.ReadCloser and tracks when it's closed
type readCloser struct {
	io.ReadCloser
	closed bool
}

func (r *readCloser) Close() error {
	r.closed = true
	return r.ReadCloser.Close()
}

func Test_BuildResultStream_Results(t *testing.T) {
	// Open the test file
	file, err := os.Open("../testdata/buildlogs.ndjson")
	if err != nil {
		t.Fatalf("Failed to open test file: %v", err)
	}
	defer file.Close()

	// Create a BuildResultStream with the test file
	stream := &BuildResultStream{r: file}

	// Collect results from the stream
	var results []BuildResult
	for result, err := range stream.Results() {
		if err != nil {
			t.Fatalf("Unexpected error from stream: %v", err)
		}
		results = append(results, result)
	}

	// Verify we got the expected number of results
	if len(results) != 40 {
		t.Errorf("Expected 40 results, got %d", len(results))
	}

	// Verify the first result
	wantFirst := BuildResult{
		Log:    []string{"v: 2025-06-13T20:16:16Z [internal] load build definition from Dockerfile"},
		Status: "in_progress",
	}
	if diff := cmp.Diff(wantFirst, results[0]); diff != "" {
		t.Errorf("First result mismatch:\n%s", diff)
	}

	// Verify the last result
	wantLast := BuildResult{
		Image:  "ttl.sh/openfaas/test-image-hello:10m",
		Status: "success",
	}
	if diff := cmp.Diff(wantLast, results[39]); diff != "" {
		t.Errorf("Last result mismatch:\n%s", diff)
	}
}

func Test_BuildResultStream_ReaderClosed(t *testing.T) {
	t.Run("reader closed after normal completion", func(t *testing.T) {
		// Open the test file
		file, err := os.Open("../testdata/buildlogs.ndjson")
		if err != nil {
			t.Fatalf("Failed to open test file: %v", err)
		}
		defer file.Close()

		// Wrap the file in our readCloser
		cr := &readCloser{ReadCloser: file}

		// Create a BuildResultStream with the wrapped reader
		stream := &BuildResultStream{r: cr}

		// Iterate over results
		for result, err := range stream.Results() {
			if err != nil {
				t.Fatalf("Unexpected error from stream: %v", err)
			}
			// Verify we got a valid result
			if result.Status == "" {
				t.Error("Expected non-empty status in result")
			}
		}

		// Verify the reader was closed
		if !cr.closed {
			t.Error("Expected reader to be closed")
		}
	})

	t.Run("reader closed after early break", func(t *testing.T) {
		// Open the test file
		file, err := os.Open("../testdata/buildlogs.ndjson")
		if err != nil {
			t.Fatalf("Failed to open test file: %v", err)
		}
		defer file.Close()

		// Wrap the file in our readCloser
		cr := &readCloser{ReadCloser: file}

		// Create a BuildResultStream with the wrapped reader
		stream := &BuildResultStream{r: cr}

		// Iterate over results
		count := 0
		for result, err := range stream.Results() {
			if err != nil {
				t.Fatalf("Unexpected error from stream: %v", err)
			}
			// Verify we got a valid result
			if result.Status == "" {
				t.Error("Expected non-empty status in result")
			}
			count++

			if count >= 5 {
				break
			}
		}

		// Verify the reader was closed
		if !cr.closed {
			t.Error("Expected reader to be closed")
		}
	})
}

func TestBuildWithSecrets(t *testing.T) {
	pub, priv, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatalf("seal.GenerateKeyPair: %v", err)
	}

	buildTar := createTestTar(t)

	tmpFile, err := os.CreateTemp(t.TempDir(), "build-*.tar")
	if err != nil {
		t.Fatalf("os.CreateTemp returned error: %v", err)
	}
	if _, err := tmpFile.Write(buildTar); err != nil {
		t.Fatalf("tmpFile.Write returned error: %v", err)
	}
	tmpFile.Close()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("io.ReadAll returned error: %v", err)
		}

		// Verify HMAC
		wantDigest := hmac.Sign(body, []byte("payload-secret"), sha256.New)
		gotDigest := r.Header.Get("X-Build-Signature")
		if gotDigest != "sha256="+hex.EncodeToString(wantDigest) {
			t.Fatalf("unexpected signature: %s", gotDigest)
		}

		// Body should be a tar, not multipart
		if ct := r.Header.Get("Content-Type"); ct != "application/octet-stream" {
			t.Fatalf("unexpected content-type: %s", ct)
		}

		// Extract sealed secrets from tar
		tr := tar.NewReader(bytes.NewReader(body))
		var sealedData []byte
		for {
			hdr, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("tar.Next returned error: %v", err)
			}
			if hdr.Name == BuildSecretsFileName {
				sealedData, err = io.ReadAll(tr)
				if err != nil {
					t.Fatalf("io.ReadAll sealed secrets: %v", err)
				}
			}
		}

		if sealedData == nil {
			t.Fatal("sealed secrets file not found in tar")
		}

		// Unseal and verify
		secrets, err := seal.Unseal(priv, sealedData)
		if err != nil {
			t.Fatalf("seal.Unseal returned error: %v", err)
		}

		if got := string(secrets["pip_token"]); got != "s3cr3t" {
			t.Fatalf("want pip_token to be %q, got %q", "s3cr3t", got)
		}

		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"status":"success","image":"ttl.sh/test:latest"}`)
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("url.Parse returned error: %v", err)
	}

	builder := NewFunctionBuilder(serverURL, http.DefaultClient,
		WithHmacAuth("payload-secret"),
		WithBuildSecretsKey(pub))

	result, err := builder.BuildWithSecrets(tmpFile.Name(), map[string]string{
		"pip_token": "s3cr3t",
	})
	if err != nil {
		t.Fatalf("BuildWithSecrets returned error: %v", err)
	}

	if result.Status != BuildSuccess {
		t.Fatalf("want status %q, got %q", BuildSuccess, result.Status)
	}
}

// createTestTar creates a minimal valid tar for testing.
func createTestTar(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	data := []byte(`{"image":"test:latest"}`)
	if err := tw.WriteHeader(&tar.Header{
		Name: BuilderConfigFileName,
		Mode: 0600,
		Size: int64(len(data)),
	}); err != nil {
		t.Fatalf("tar.WriteHeader: %v", err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatalf("tar.Write: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar.Close: %v", err)
	}
	return buf.Bytes()
}

func TestHandlerFolderWithinScope(t *testing.T) {
	cases := []struct {
		name          string
		handlerFolder string
		err           bool
	}{
		{
			name:          "empty folder selects build root",
			handlerFolder: "",
		},
		{
			name:          "dot selects build root",
			handlerFolder: ".",
		},
		{
			name:          "nested handler folder stays in scope",
			handlerFolder: "src/function",
		},
		{
			name:          "internal traversal stays in scope",
			handlerFolder: "src/../function",
		},
		{
			name:          "default handler folder stays in scope",
			handlerFolder: "function",
			err:           false,
		},
		{
			name:          "path traversal escapes the build context",
			handlerFolder: "../../../../tmp/pro-poc-out",
			err:           true,
		},
		{
			name:          "hidden path traversal escapes the build context",
			handlerFolder: "./function/../../../../tmp/pro-poc-out",
			err:           true,
		},
		{
			name:          "absolute path is rejected",
			handlerFolder: "/tmp/pro-poc-out",
			err:           true,
		},
		{
			name:          "prefix sibling is rejected",
			handlerFolder: "../other",
			err:           true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buildRoot := filepath.Join(t.TempDir(), "build", "fn")

			dst, err := handlerFolderWithinScope(buildRoot, tc.handlerFolder)

			if tc.err && err == nil {
				t.Fatalf("expected an error for handler folder %q but got none (dst: %s)", tc.handlerFolder, dst)
			}

			if !tc.err && err != nil {
				t.Fatalf("unexpected error for handler folder %q: %s", tc.handlerFolder, err)
			}

			if !tc.err {
				want := filepath.Join(buildRoot, tc.handlerFolder)
				if dst != want {
					t.Fatalf("expected destination %s, got %s", want, dst)
				}
			}
		})
	}
}

func TestFunctionBuildContextPath(t *testing.T) {
	buildDir := filepath.Join("workspace", "build")
	cases := []struct {
		name         string
		functionName string
		want         string
		wantErr      bool
	}{
		{
			name:         "ordinary function name",
			functionName: "echo",
			want:         filepath.Join(buildDir, "echo"),
		},
		{
			name:         "filesystem-safe opaque name",
			functionName: "Function_Name",
			want:         filepath.Join(buildDir, "Function_Name"),
		},
		{name: "empty name", functionName: "", wantErr: true},
		{name: "current directory", functionName: ".", wantErr: true},
		{name: "parent directory", functionName: "..", wantErr: true},
		{name: "path traversal", functionName: "../outside", wantErr: true},
		{name: "nested slash path", functionName: "group/function", wantErr: true},
		{name: "nested backslash path", functionName: `group\function`, wantErr: true},
		{name: "absolute path", functionName: string(filepath.Separator) + "outside", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := functionBuildContextPath(buildDir, tc.functionName)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error for function name %q, got path %q", tc.functionName, got)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error for function name %q: %s", tc.functionName, err)
			}
			if got != tc.want {
				t.Fatalf("unexpected build context path: got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCreateBuildContextRejectsFunctionTraversalBeforeRemoveAll(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(root, "outside")
	if err := os.MkdirAll(outside, 0755); err != nil {
		t.Fatalf("error creating outside dir: %s", err)
	}

	want := []byte("must not be deleted\n")
	sentinel := filepath.Join(outside, "sentinel")
	if err := os.WriteFile(sentinel, want, 0644); err != nil {
		t.Fatalf("error writing outside sentinel: %s", err)
	}

	_, err := CreateBuildContext(
		filepath.Join("..", "outside"),
		filepath.Join(root, "handler"),
		"dockerfile",
		nil,
		WithBuildDir(filepath.Join(root, "build")),
	)
	if err == nil {
		t.Fatal("expected an error for a function name containing path traversal")
	}

	got, readErr := os.ReadFile(sentinel)
	if readErr != nil {
		t.Fatalf("outside sentinel was removed before function name validation: %s", readErr)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("outside sentinel changed: got %q, want %q", got, want)
	}
}

func TestCreateBuildContextDoesNotOverwriteOutsideFile(t *testing.T) {
	root := t.TempDir()

	handler := filepath.Join(root, "handler")
	if err := os.MkdirAll(handler, 0755); err != nil {
		t.Fatalf("error creating handler dir: %s", err)
	}
	if err := os.WriteFile(filepath.Join(handler, "fn.py"), []byte("attacker controlled\n"), 0644); err != nil {
		t.Fatalf("error writing handler file: %s", err)
	}

	templateDir := filepath.Join(root, "template")
	if err := os.MkdirAll(filepath.Join(templateDir, "python"), 0755); err != nil {
		t.Fatalf("error creating template dir: %s", err)
	}
	if err := os.WriteFile(filepath.Join(templateDir, "python", "Dockerfile"), []byte("FROM alpine\n"), 0644); err != nil {
		t.Fatalf("error writing template file: %s", err)
	}

	outside := filepath.Join(root, "outside")
	if err := os.MkdirAll(outside, 0755); err != nil {
		t.Fatalf("error creating outside dir: %s", err)
	}
	want := []byte("original content\n")
	outsideFile := filepath.Join(outside, "fn.py")
	if err := os.WriteFile(outsideFile, want, 0644); err != nil {
		t.Fatalf("error writing outside file: %s", err)
	}

	_, err := CreateBuildContext(
		"fn",
		handler,
		"python",
		nil,
		WithBuildDir(filepath.Join(root, "build")),
		WithTemplateDir(templateDir),
		WithHandlerOverlay(filepath.Join("..", "..", "outside")),
	)
	if err == nil {
		t.Fatal("expected an error for handler folder escaping the build context")
	}

	got, readErr := os.ReadFile(outsideFile)
	if readErr != nil {
		t.Fatalf("error reading outside file after rejected build context: %s", readErr)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("outside file was overwritten: got %q, want %q", got, want)
	}
}
