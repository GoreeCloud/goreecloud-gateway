package publication

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
)

const MaxPolicyBytes int64 = 256 * 1024

var (
	ErrInvalidPolicy = errors.New("invalid publication policy")
	ErrPolicyTooLarge = errors.New("publication policy exceeds size limit")
)

// LoadPlanFile reads a local publication policy through a bounded, strict JSON
// boundary and returns its deterministic, mutation-free plan.  It never
// contacts a data plane and intentionally does not include rejected input in
// returned errors, so malformed credentials or infrastructure identifiers are
// not copied into control-plane logs by callers.
func LoadPlanFile(path string) (Plan, error) {
	if path == "" {
		return Plan{}, ErrInvalidPolicy
	}

	file, err := os.Open(path)
	if err != nil {
		return Plan{}, errors.New("publication policy is unavailable")
	}
	defer func() { _ = file.Close() }()

	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return Plan{}, errors.New("publication policy is unavailable")
	}

	payload, err := io.ReadAll(io.LimitReader(file, MaxPolicyBytes+1))
	if err != nil {
		return Plan{}, errors.New("publication policy is unreadable")
	}
	if int64(len(payload)) > MaxPolicyBytes {
		return Plan{}, ErrPolicyTooLarge
	}

	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()

	var config Config
	if err = decoder.Decode(&config); err != nil {
		return Plan{}, ErrInvalidPolicy
	}

	var trailing any
	if err = decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Plan{}, ErrInvalidPolicy
	}

	plan, err := BuildPlan(config)
	if err != nil {
		return Plan{}, ErrInvalidPolicy
	}

	return plan, nil
}
