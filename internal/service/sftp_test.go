package service

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestParseSFTPRemoteSpec(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantHost string
		wantPath string
		wantErr  bool
	}{
		{name: "empty path", input: "prod:", wantHost: "prod", wantPath: "."},
		{name: "relative path", input: "prod:var/log", wantHost: "prod", wantPath: "var/log"},
		{name: "absolute path", input: "prod:/var//log", wantHost: "prod", wantPath: "/var/log"},
		{name: "missing colon", input: "prod", wantErr: true},
		{name: "missing host", input: ":/tmp", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSFTPRemoteSpec(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseSFTPRemoteSpec returned error: %v", err)
			}
			if got.Host != tt.wantHost || got.Path != tt.wantPath {
				t.Fatalf("ParseSFTPRemoteSpec() = %+v, want host=%q path=%q", got, tt.wantHost, tt.wantPath)
			}
		})
	}
}

func TestSFTPRemotePathHelpers(t *testing.T) {
	if got := JoinSFTPRemotePath(".", "file.txt"); got != "file.txt" {
		t.Fatalf("JoinSFTPRemotePath relative = %q", got)
	}
	if got := JoinSFTPRemotePath("/var/log", "../tmp/app.log"); got != "/var/tmp/app.log" {
		t.Fatalf("JoinSFTPRemotePath clean = %q", got)
	}
	if got := ParentSFTPRemotePath("/var/log"); got != "/var" {
		t.Fatalf("ParentSFTPRemotePath absolute = %q", got)
	}
	if got := ParentSFTPRemotePath("."); got != "." {
		t.Fatalf("ParentSFTPRemotePath dot = %q", got)
	}
	if got := BaseSFTPRemotePath("/"); got != "download" {
		t.Fatalf("BaseSFTPRemotePath root = %q", got)
	}
}

func TestResolveDownloadDestination(t *testing.T) {
	dir := t.TempDir()
	got, err := resolveDownloadDestination("/var/log/app.log", dir)
	if err != nil {
		t.Fatalf("resolveDownloadDestination returned error: %v", err)
	}
	want := filepath.Join(dir, "app.log")
	if got != want {
		t.Fatalf("destination = %q, want %q", got, want)
	}
	got, err = resolveDownloadDestination("/var/log/app.log", filepath.Join(dir, "custom.log"))
	if err != nil {
		t.Fatalf("resolveDownloadDestination file path returned error: %v", err)
	}
	if got != filepath.Join(dir, "custom.log") {
		t.Fatalf("destination = %q", got)
	}
}

func TestEnsureLocalDestinationWritableRequiresOverwrite(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "existing.txt")
	if err := os.WriteFile(target, []byte("old"), 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	if err := ensureLocalDestinationWritable(target, false); !errors.Is(err, ErrSFTPDestinationExists) {
		t.Fatalf("expected destination exists, got %v", err)
	}
	if err := ensureLocalDestinationWritable(target, true); err != nil {
		t.Fatalf("expected overwrite to allow destination, got %v", err)
	}
}

func TestUnsafeSFTPRemovalPath(t *testing.T) {
	for _, value := range []string{"", ".", "/"} {
		if !unsafeSFTPRemovalPath(value) {
			t.Fatalf("expected %q to be unsafe", value)
		}
	}
	for _, value := range []string{"tmp", "/tmp/file"} {
		if unsafeSFTPRemovalPath(value) {
			t.Fatalf("expected %q to be safe", value)
		}
	}
}

func TestCopyWithContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	n, err := copyWithContext(ctx, io.Discard, bytes.NewBufferString("hello"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got bytes=%d err=%v", n, err)
	}
	if n != 0 {
		t.Fatalf("copied bytes = %d, want 0", n)
	}
}
