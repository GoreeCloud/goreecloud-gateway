package status

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteFileAtomicallyWritesOwnerOnlyStatus(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "gateway-status.json")
	snapshot := DevelopmentSnapshot(time.Date(2026, 9, 1, 17, 30, 0, 0, time.UTC))

	if err := WriteFile(path, snapshot); err != nil {
		t.Fatalf("write status: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat status: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("status permissions = %o, want 600", got)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	var decoded Snapshot
	if err = json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if decoded.State != "development" || decoded.Producer.ServiceID != "goreecloud-gateway" {
		t.Fatalf("unexpected decoded status: %#v", decoded)
	}
}

func TestWriteFileRejectsEmptyPath(t *testing.T) {
	if err := WriteFile("", DevelopmentSnapshot(time.Now())); err == nil {
		t.Fatal("expected empty path rejection")
	}
}
