package tlsconfig

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadACMEAccountWrappingKeyRawAndTextEncodings(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{name: "raw", data: bytes.Repeat([]byte{0x42}, 32)},
		{name: "hex", data: []byte("4242424242424242424242424242424242424242424242424242424242424242\n")},
		{name: "base64", data: []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32)) + "\n")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "wrapping-key")
			if err := os.WriteFile(path, tt.data, 0o600); err != nil {
				t.Fatal(err)
			}
			key, err := LoadACMEAccountWrappingKey(path)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(key)
			if !bytes.Equal(key, bytes.Repeat([]byte{0x42}, 32)) {
				t.Fatal("wrapping-key bytes did not match expected value")
			}
		})
	}
}

func TestLoadACMEAccountWrappingKeyRejectsBroadPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wrapping-key")
	if err := os.WriteFile(path, bytes.Repeat([]byte{1}, 32), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadACMEAccountWrappingKey(path); err == nil {
		t.Fatal("broad wrapping-key permissions unexpectedly accepted")
	}
}

func TestLoadACMEAccountWrappingKeyRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	realPath := filepath.Join(root, "real-key")
	linkPath := filepath.Join(root, "wrapping-key")
	if err := os.WriteFile(realPath, bytes.Repeat([]byte{2}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realPath, linkPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := LoadACMEAccountWrappingKey(linkPath); err == nil {
		t.Fatal("symlink wrapping-key file unexpectedly accepted")
	}
}

func TestLoadACMEAccountWrappingKeyRejectsSymlinkAncestor(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(realDir, "wrapping-key")
	if err := os.WriteFile(path, bytes.Repeat([]byte{3}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(root, "link")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := LoadACMEAccountWrappingKey(filepath.Join(linkDir, "wrapping-key")); err == nil {
		t.Fatal("wrapping-key path with symlink ancestor unexpectedly accepted")
	}
}

func TestLoadACMEAccountWrappingKeyRejectsInvalidLength(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wrapping-key")
	if err := os.WriteFile(path, []byte("not-a-256-bit-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadACMEAccountWrappingKey(path); err == nil {
		t.Fatal("invalid wrapping-key length unexpectedly accepted")
	}
}
