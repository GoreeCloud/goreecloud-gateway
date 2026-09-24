package tlsconfig

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const maxACMEWrappingKeyFileBytes = 4096

// LoadACMEAccountWrappingKey reads a 256-bit wrapping key from a protected
// regular file. The file may contain exactly 32 raw bytes, 64 hexadecimal
// characters, or standard/raw base64 that decodes to 32 bytes. A single
// trailing newline around textual encodings is tolerated.
//
// Callers should clear the returned byte slice as soon as the wrapping
// operation is complete. This loader intentionally does not read environment
// variables or command-line arguments, where secrets are easier to expose.
func LoadACMEAccountWrappingKey(path string) ([]byte, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("gateway tls: ACME account wrapping-key file path is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("gateway tls: resolve ACME account wrapping-key file: %w", err)
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return nil, fmt.Errorf("gateway tls: inspect ACME account wrapping-key file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("gateway tls: ACME account wrapping-key file must be a regular non-symlink file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("gateway tls: ACME account wrapping-key file permissions are too broad")
	}
	if info.Size() <= 0 || info.Size() > maxACMEWrappingKeyFileBytes {
		return nil, errors.New("gateway tls: ACME account wrapping-key file size is invalid")
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return nil, fmt.Errorf("gateway tls: resolve ACME account wrapping-key file symlinks: %w", err)
	}
	if filepath.Clean(resolved) != filepath.Clean(absolute) {
		return nil, errors.New("gateway tls: ACME account wrapping-key path contains a symbolic link")
	}

	data, err := os.ReadFile(absolute)
	if err != nil {
		return nil, fmt.Errorf("gateway tls: read ACME account wrapping-key file: %w", err)
	}
	defer clear(data)

	if len(data) == 32 {
		return append([]byte(nil), data...), nil
	}
	text := strings.TrimSpace(string(data))
	if text == "" {
		return nil, errors.New("gateway tls: ACME account wrapping-key file is empty")
	}

	if decoded, err := hex.DecodeString(text); err == nil {
		if len(decoded) == 32 {
			return decoded, nil
		}
		clear(decoded)
	}
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		decoded, err := encoding.DecodeString(text)
		if err != nil {
			continue
		}
		if len(decoded) == 32 {
			return decoded, nil
		}
		clear(decoded)
	}
	return nil, errors.New("gateway tls: ACME account wrapping-key file must resolve to exactly 32 bytes")
}
