package status

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// WriteFile atomically replaces path with a privacy-minimized status snapshot.
// Temporary and final files are owner-only. Callers must place path on an
// approved local filesystem shared only with the intended consumer.
func WriteFile(path string, snapshot Snapshot) (err error) {
	if path == "" {
		return fmt.Errorf("status path is empty")
	}

	payload, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal status: %w", err)
	}
	payload = append(payload, '\n')

	dir := filepath.Dir(path)
	if err = os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("prepare status directory: %w", err)
	}

	file, err := os.CreateTemp(dir, ".goreecloud-gateway-status-*")
	if err != nil {
		return fmt.Errorf("create temporary status file: %w", err)
	}
	tmp := file.Name()
	defer func() {
		_ = os.Remove(tmp)
	}()

	if err = file.Chmod(0o600); err != nil {
		_ = file.Close()
		return fmt.Errorf("secure temporary status file: %w", err)
	}
	if _, err = file.Write(payload); err != nil {
		_ = file.Close()
		return fmt.Errorf("write temporary status file: %w", err)
	}
	if err = file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync temporary status file: %w", err)
	}
	if err = file.Close(); err != nil {
		return fmt.Errorf("close temporary status file: %w", err)
	}
	if err = os.Rename(tmp, path); err != nil {
		return fmt.Errorf("replace status file: %w", err)
	}

	return nil
}
