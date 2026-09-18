package main

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/GoreeCloud/goreecloud-gateway/internal/tlsconfig"
	"golang.org/x/crypto/acme"
)

const (
	accountKeyCreateReceiptSchemaV1 = "goreecloud-gateway-acme-account-key-create-receipt/v1"
	maxOperatorJSONBytes             = 64 << 10
	maxEABKeyFileBytes               = 8 << 10
)

type accountKeyCreateReceipt struct {
	Schema                      string `json:"schema"`
	DirectoryURL                string `json:"directory_url"`
	CreatedAt                   string `json:"created_at"`
	KeyType                     string `json:"key_type"`
	AccountPublicKeySHA256      string `json:"account_public_key_sha256"`
	StateFile                   string `json:"state_file"`
	ProductionCutoverAuthorized bool   `json:"production_cutover_authorized"`
}

type registrationManager interface {
	PrepareRegistration(context.Context, []string, time.Time) (tlsconfig.ACMEAccountRegistrationPlan, error)
	Register(context.Context, tlsconfig.ACMEAccountRegistrationPlan, []string, tlsconfig.ACMETermsAcceptance, *acme.ExternalAccountBinding, time.Time) (tlsconfig.ACMEAccountRegistrationReceipt, error)
}

type dependencies struct {
	now        func() time.Time
	newManager func(crypto.Signer, string, *http.Client) (registrationManager, error)
}

func defaultDependencies() dependencies {
	return dependencies{
		now: time.Now,
		newManager: func(accountKey crypto.Signer, directoryURL string, client *http.Client) (registrationManager, error) {
			return tlsconfig.NewACMEAccountRegistrationManager(accountKey, directoryURL, client)
		},
	}
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, defaultDependencies()))
}

func run(args []string, stdout, stderr io.Writer, deps dependencies) int {
	flags := flag.NewFlagSet("gateway-acme-account", flag.ContinueOnError)
	flags.SetOutput(stderr)

	action := flags.String("action", "", "action: create-key, plan, or register")
	directoryURL := flags.String("directory", "", "exact ACME directory HTTPS URL")
	stateRoot := flags.String("state-root", "", "owner-only ACME account-state directory")
	wrappingKeyFile := flags.String("wrapping-key-file", "", "protected 256-bit wrapping-key file")
	contactsFile := flags.String("contacts-file", "", "protected JSON array of ACME contact URI strings")
	planFile := flags.String("plan-file", "", "protected registration-plan JSON file for register action")
	acceptanceFile := flags.String("terms-acceptance-file", "", "protected explicit terms-acceptance JSON file")
	eabKID := flags.String("eab-kid", "", "external-account-binding key identifier (not the MAC key)")
	eabKeyFile := flags.String("eab-key-file", "", "protected base64url external-account-binding MAC key file")
	confirmRegisterDirectory := flags.String("confirm-register-directory", "", "must exactly match -directory for register action")
	timeout := flags.Duration("timeout", 30*time.Second, "ACME operation timeout")

	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "gateway ACME account: positional arguments are not supported")
		return 2
	}
	if deps.now == nil || deps.newManager == nil {
		fmt.Fprintln(stderr, "gateway ACME account: operator dependencies are incomplete")
		return 1
	}
	if *timeout <= 0 || *timeout > 5*time.Minute {
		fmt.Fprintln(stderr, "gateway ACME account: -timeout must be greater than zero and no more than 5m")
		return 2
	}

	actionValue := strings.TrimSpace(*action)
	directoryValue := strings.TrimSpace(*directoryURL)
	stateRootValue := strings.TrimSpace(*stateRoot)
	wrappingKeyFileValue := strings.TrimSpace(*wrappingKeyFile)
	if actionValue == "" || directoryValue == "" || stateRootValue == "" || wrappingKeyFileValue == "" {
		fmt.Fprintln(stderr, "gateway ACME account: -action, -directory, -state-root, and -wrapping-key-file are required")
		return 2
	}

	switch actionValue {
	case "create-key":
		if strings.TrimSpace(*contactsFile) != "" || strings.TrimSpace(*planFile) != "" || strings.TrimSpace(*acceptanceFile) != "" ||
			strings.TrimSpace(*eabKID) != "" || strings.TrimSpace(*eabKeyFile) != "" || strings.TrimSpace(*confirmRegisterDirectory) != "" {
			fmt.Fprintln(stderr, "gateway ACME account: create-key does not accept registration inputs")
			return 2
		}
	case "plan":
		if strings.TrimSpace(*contactsFile) == "" {
			fmt.Fprintln(stderr, "gateway ACME account: plan requires -contacts-file")
			return 2
		}
		if strings.TrimSpace(*planFile) != "" || strings.TrimSpace(*acceptanceFile) != "" ||
			strings.TrimSpace(*eabKID) != "" || strings.TrimSpace(*eabKeyFile) != "" || strings.TrimSpace(*confirmRegisterDirectory) != "" {
			fmt.Fprintln(stderr, "gateway ACME account: plan does not accept registration execution inputs")
			return 2
		}
	case "register":
		if strings.TrimSpace(*contactsFile) == "" || strings.TrimSpace(*planFile) == "" {
			fmt.Fprintln(stderr, "gateway ACME account: register requires -contacts-file and -plan-file")
			return 2
		}
		if strings.TrimSpace(*confirmRegisterDirectory) != directoryValue {
			fmt.Fprintln(stderr, "gateway ACME account: -confirm-register-directory must exactly match -directory")
			return 2
		}
		if (strings.TrimSpace(*eabKID) == "") != (strings.TrimSpace(*eabKeyFile) == "") {
			fmt.Fprintln(stderr, "gateway ACME account: -eab-kid and -eab-key-file must be supplied together")
			return 2
		}
	default:
		fmt.Fprintln(stderr, "gateway ACME account: -action must be create-key, plan, or register")
		return 2
	}

	wrappingKey, err := tlsconfig.LoadACMEAccountWrappingKey(wrappingKeyFileValue)
	if err != nil {
		fmt.Fprintf(stderr, "gateway ACME account: load wrapping key: %v\n", err)
		return 1
	}
	defer clear(wrappingKey)

	if actionValue == "create-key" {
		accountKey, err := tlsconfig.GenerateACMEAccountKey()
		if err != nil {
			fmt.Fprintf(stderr, "gateway ACME account: generate account key: %v\n", err)
			return 1
		}
		path, envelope, err := tlsconfig.SaveEncryptedACMEAccountKey(
			stateRootValue,
			accountKey,
			wrappingKey,
			directoryValue,
			deps.now().UTC(),
		)
		if err != nil {
			fmt.Fprintf(stderr, "gateway ACME account: persist encrypted account key: %v\n", err)
			return 1
		}
		return encodeJSON(stdout, stderr, accountKeyCreateReceipt{
			Schema:                      accountKeyCreateReceiptSchemaV1,
			DirectoryURL:                envelope.DirectoryURL,
			CreatedAt:                   envelope.CreatedAt,
			KeyType:                     envelope.KeyType,
			AccountPublicKeySHA256:      envelope.PublicKeySHA256,
			StateFile:                   path,
			ProductionCutoverAuthorized: false,
		})
	}

	accountKey, _, err := tlsconfig.LoadEncryptedACMEAccountKey(stateRootValue, wrappingKey, directoryValue)
	if err != nil {
		fmt.Fprintf(stderr, "gateway ACME account: load encrypted account key: %v\n", err)
		return 1
	}
	contacts, err := loadContactsFile(strings.TrimSpace(*contactsFile))
	if err != nil {
		fmt.Fprintf(stderr, "gateway ACME account: load contacts: %v\n", err)
		return 1
	}

	manager, err := deps.newManager(accountKey, directoryValue, &http.Client{Timeout: *timeout})
	if err != nil {
		fmt.Fprintf(stderr, "gateway ACME account: initialize registration manager: %v\n", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	if actionValue == "plan" {
		plan, err := manager.PrepareRegistration(ctx, contacts, deps.now().UTC())
		if err != nil {
			fmt.Fprintf(stderr, "gateway ACME account: prepare registration plan: %v\n", err)
			return 1
		}
		return encodeJSON(stdout, stderr, plan)
	}

	var plan tlsconfig.ACMEAccountRegistrationPlan
	if err := loadStrictJSONFile(strings.TrimSpace(*planFile), "registration plan", &plan, maxOperatorJSONBytes); err != nil {
		fmt.Fprintf(stderr, "gateway ACME account: load registration plan: %v\n", err)
		return 1
	}

	var acceptance tlsconfig.ACMETermsAcceptance
	if strings.TrimSpace(*acceptanceFile) != "" {
		if err := loadStrictJSONFile(strings.TrimSpace(*acceptanceFile), "terms acceptance", &acceptance, maxOperatorJSONBytes); err != nil {
			fmt.Fprintf(stderr, "gateway ACME account: load terms acceptance: %v\n", err)
			return 1
		}
	}

	var eab *acme.ExternalAccountBinding
	if strings.TrimSpace(*eabKeyFile) != "" {
		key, err := loadEABKey(strings.TrimSpace(*eabKeyFile))
		if err != nil {
			fmt.Fprintf(stderr, "gateway ACME account: load EAB key: %v\n", err)
			return 1
		}
		defer clear(key)
		eab = &acme.ExternalAccountBinding{KID: strings.TrimSpace(*eabKID), Key: key}
	}

	receipt, err := manager.Register(ctx, plan, contacts, acceptance, eab, deps.now().UTC())
	if err != nil {
		fmt.Fprintf(stderr, "gateway ACME account: register account: %v\n", err)
		return 1
	}
	return encodeJSON(stdout, stderr, receipt)
}

func encodeJSON(stdout, stderr io.Writer, value any) int {
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		fmt.Fprintf(stderr, "gateway ACME account: encode output: %v\n", err)
		return 1
	}
	return 0
}

func loadContactsFile(path string) ([]string, error) {
	var contacts []string
	if err := loadStrictJSONFile(path, "contacts", &contacts, maxOperatorJSONBytes); err != nil {
		return nil, err
	}
	if contacts == nil {
		return nil, errors.New("contacts JSON must be an array")
	}
	return contacts, nil
}

func loadStrictJSONFile(path, label string, destination any, maxBytes int64) error {
	data, err := readProtectedOperatorFile(path, label, maxBytes)
	if err != nil {
		return err
	}
	defer clear(data)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode %s JSON: %w", label, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%s JSON contains trailing data", label)
	}
	return nil
}

func loadEABKey(path string) ([]byte, error) {
	data, err := readProtectedOperatorFile(path, "EAB key", maxEABKeyFileBytes)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	text := strings.TrimSpace(string(data))
	if text == "" {
		return nil, errors.New("EAB key file is empty")
	}
	for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding} {
		decoded, err := encoding.DecodeString(text)
		if err != nil {
			continue
		}
		if len(decoded) > 0 {
			return decoded, nil
		}
	}
	return nil, errors.New("EAB key file must contain a non-empty base64url MAC key")
}

func readProtectedOperatorFile(path, label string, maxBytes int64) ([]byte, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("%s file path is required", label)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve %s file: %w", label, err)
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return nil, fmt.Errorf("inspect %s file: %w", label, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s file must be a regular non-symlink file", label)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s file permissions are too broad", label)
	}
	if info.Size() <= 0 || info.Size() > maxBytes {
		return nil, fmt.Errorf("%s file size is invalid", label)
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return nil, fmt.Errorf("resolve %s file symlinks: %w", label, err)
	}
	if filepath.Clean(resolved) != filepath.Clean(absolute) {
		return nil, fmt.Errorf("%s path contains a symbolic link", label)
	}
	data, err := os.ReadFile(absolute)
	if err != nil {
		return nil, fmt.Errorf("read %s file: %w", label, err)
	}
	return data, nil
}
