package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/GoreeCloud/goreecloud-gateway/internal/config"
)

type snapshotOutput struct {
	SnapshotDir string                  `json:"snapshot_dir"`
	Snapshot    config.RecoverySnapshot `json:"snapshot"`
}

func main() {
	action := flag.String("action", "", "recovery action: snapshot or restore")
	root := flag.String("root", "", "bounded Gateway recovery root")
	configPath := flag.String("config", "", "active Gateway configuration path")
	sourceRevision := flag.String("source-revision", "", "exact source revision for snapshot evidence")
	snapshotDir := flag.String("snapshot", "", "snapshot directory to restore")
	expectedCurrent := flag.String("expected-current-sha256", "", "expected active configuration SHA-256 before restore")
	flag.Parse()

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")

	switch *action {
	case "snapshot":
		directory, snapshot, err := config.CreateRecoverySnapshot(
			*root,
			*configPath,
			*sourceRevision,
			time.Now().UTC(),
		)
		if err != nil {
			fail(err)
		}
		if err := encoder.Encode(snapshotOutput{SnapshotDir: directory, Snapshot: snapshot}); err != nil {
			fail(err)
		}
	case "restore":
		receipt, err := config.RestoreRecoverySnapshot(
			*root,
			*configPath,
			*snapshotDir,
			*expectedCurrent,
			time.Now().UTC(),
		)
		if err != nil {
			fail(err)
		}
		if err := encoder.Encode(receipt); err != nil {
			fail(err)
		}
	default:
		fail(fmt.Errorf("gateway recovery: -action must be snapshot or restore"))
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
