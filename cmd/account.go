package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	gohttp "net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/majd/ipatool/v2/pkg/http"
	"github.com/majd/ipatool/v2/pkg/keychain"
	"github.com/spf13/cobra"
)

const keychainAccountKey = "account"

// accountProfile is the account slot explicitly selected with --account.
var accountProfile string

// selectedAccountKey is the account currently in use. The scoped keychain and
// cookie jar hold a pointer to it so a login that discovers the account key
// after initialization still writes to the right slot.
var selectedAccountKey string

// stateDirectoryPath is set by initWithCommand once the state directory is
// resolved; the account registry and the active account pointer live there.
var stateDirectoryPath string

type accountProfileRecord struct {
	Key       string    `json:"key"`
	Email     string    `json:"email"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type accountRegistry struct {
	Accounts map[string]accountProfileRecord `json:"accounts"`
}

// scopedKeychain isolates App Store credentials per account by rewriting the
// single account key. Every other item is shared because it describes the
// machine rather than the signed-in account.
type scopedKeychain struct {
	base       keychain.Keychain
	accountKey *string
}

func newScopedKeychain(base keychain.Keychain, accountKey *string) keychain.Keychain {
	return &scopedKeychain{
		base:       base,
		accountKey: accountKey,
	}
}

// nolint:wrapcheck
func (s *scopedKeychain) Get(key string) ([]byte, error) {
	return s.base.Get(s.translate(key))
}

// nolint:wrapcheck
func (s *scopedKeychain) Set(key string, data []byte) error {
	return s.base.Set(s.translate(key), data)
}

// nolint:wrapcheck
func (s *scopedKeychain) Remove(key string) error {
	return s.base.Remove(s.translate(key))
}

func (s *scopedKeychain) translate(key string) string {
	if key != keychainAccountKey {
		return key
	}

	accountKey := normalizeAccountKey(*s.accountKey)
	if accountKey == "" {
		return key
	}

	return keychainAccountKey + ":" + accountKey
}

// scopedCookieJar opens the cookie jar of the selected account on first use and
// follows the selection when it changes during a login.
type scopedCookieJar struct {
	directory  string
	accountKey *string
	mu         sync.Mutex
	openedKey  string
	opened     http.CookieJar
}

func newScopedCookieJar(directory string, accountKey *string) http.CookieJar {
	return &scopedCookieJar{
		directory:  directory,
		accountKey: accountKey,
	}
}

func (j *scopedCookieJar) Cookies(u *url.URL) []*gohttp.Cookie {
	return j.current().Cookies(u)
}

func (j *scopedCookieJar) SetCookies(u *url.URL, cookies []*gohttp.Cookie) {
	j.current().SetCookies(u, cookies)
}

// nolint:wrapcheck
func (j *scopedCookieJar) Save() error {
	return j.current().Save()
}

func (j *scopedCookieJar) current() http.CookieJar {
	j.mu.Lock()
	defer j.mu.Unlock()

	accountKey := normalizeAccountKey(*j.accountKey)
	if j.opened != nil && j.openedKey == accountKey {
		return j.opened
	}

	if j.opened != nil {
		// The jar is saved after every response; flushing here only prevents a
		// selection change from dropping cookies set outside a request.
		_ = j.opened.Save()
	}

	j.opened = newCookieJarForAccount(j.directory, accountKey)
	j.openedKey = accountKey

	return j.opened
}

func normalizeAccountKey(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func cookieJarFileName(accountKey string) string {
	accountKey = normalizeAccountKey(accountKey)
	if accountKey == "" {
		return CookieJarFileName
	}

	return fmt.Sprintf("%s-%s", CookieJarFileName, url.PathEscape(accountKey))
}

func accountRegistryPath() string {
	return filepath.Join(stateDirectoryPath, AccountRegistryFileName)
}

func activeAccountPath() string {
	return filepath.Join(stateDirectoryPath, ActiveAccountFileName)
}

func emptyAccountRegistry() accountRegistry {
	return accountRegistry{Accounts: map[string]accountProfileRecord{}}
}

func loadAccountRegistry() (accountRegistry, error) {
	if stateDirectoryPath == "" {
		return emptyAccountRegistry(), nil
	}

	data, err := os.ReadFile(accountRegistryPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return emptyAccountRegistry(), nil
		}

		return accountRegistry{}, fmt.Errorf("failed to read account registry: %w", err)
	}

	var registry accountRegistry
	if err := json.Unmarshal(data, &registry); err != nil {
		return accountRegistry{}, fmt.Errorf("failed to unmarshal account registry: %w", err)
	}

	if registry.Accounts == nil {
		registry.Accounts = map[string]accountProfileRecord{}
	}

	return registry, nil
}

func saveAccountRegistry(registry accountRegistry) error {
	if stateDirectoryPath == "" {
		return errors.New("account registry is unavailable: state directory is not initialized")
	}

	if registry.Accounts == nil {
		registry.Accounts = map[string]accountProfileRecord{}
	}

	if err := os.MkdirAll(stateDirectoryPath, 0700); err != nil {
		return fmt.Errorf("failed to create state directory: %w", err)
	}

	data, err := json.MarshalIndent(registry, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal account registry: %w", err)
	}

	if err := os.WriteFile(accountRegistryPath(), data, 0600); err != nil {
		return fmt.Errorf("failed to write account registry: %w", err)
	}

	return nil
}

func upsertAccountProfile(accountKey, email string) error {
	accountKey = normalizeAccountKey(accountKey)
	if accountKey == "" {
		accountKey = normalizeAccountKey(email)
	}

	if accountKey == "" {
		return nil
	}

	registry, err := loadAccountRegistry()
	if err != nil {
		return err
	}

	registry.Accounts[accountKey] = accountProfileRecord{
		Key:       accountKey,
		Email:     strings.TrimSpace(email),
		UpdatedAt: time.Now().UTC(),
	}

	return saveAccountRegistry(registry)
}

func removeAccountProfile(accountKey string) error {
	registry, err := loadAccountRegistry()
	if err != nil {
		return err
	}

	delete(registry.Accounts, normalizeAccountKey(accountKey))

	return saveAccountRegistry(registry)
}

func listAccountProfiles() ([]accountProfileRecord, error) {
	registry, err := loadAccountRegistry()
	if err != nil {
		return nil, err
	}

	records := make([]accountProfileRecord, 0, len(registry.Accounts))
	for _, record := range registry.Accounts {
		records = append(records, record)
	}

	sort.Slice(records, func(i, j int) bool {
		return records[i].Key < records[j].Key
	})

	return records, nil
}

func resolveStoredAccountKey(spec string) string {
	spec = normalizeAccountKey(spec)
	if spec == "" {
		return ""
	}

	registry, err := loadAccountRegistry()
	if err != nil {
		return spec
	}

	if record, ok := registry.Accounts[spec]; ok {
		return record.Key
	}

	var match string

	for _, record := range registry.Accounts {
		if normalizeAccountKey(record.Email) == spec && (match == "" || record.Key < match) {
			match = record.Key
		}
	}

	if match != "" {
		return match
	}

	return spec
}

func accountProfileExists(accountKey string) (bool, error) {
	registry, err := loadAccountRegistry()
	if err != nil {
		return false, err
	}

	_, ok := registry.Accounts[normalizeAccountKey(accountKey)]

	return ok, nil
}

func readActiveAccountKey() (string, error) {
	if stateDirectoryPath == "" {
		return "", nil
	}

	data, err := os.ReadFile(activeAccountPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}

		return "", fmt.Errorf("failed to read active account: %w", err)
	}

	return normalizeAccountKey(string(data)), nil
}

func writeActiveAccountKey(accountKey string) error {
	accountKey = normalizeAccountKey(accountKey)
	if accountKey == "" {
		return clearActiveAccountKey()
	}

	if stateDirectoryPath == "" {
		return errors.New("active account is unavailable: state directory is not initialized")
	}

	if err := os.MkdirAll(stateDirectoryPath, 0700); err != nil {
		return fmt.Errorf("failed to create state directory: %w", err)
	}

	if err := os.WriteFile(activeAccountPath(), []byte(accountKey), 0600); err != nil {
		return fmt.Errorf("failed to write active account: %w", err)
	}

	return nil
}

func clearActiveAccountKey() error {
	if stateDirectoryPath == "" {
		return nil
	}

	err := os.Remove(activeAccountPath())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to clear active account: %w", err)
	}

	return nil
}

func removeCookieJarFile(accountKey string) error {
	if stateDirectoryPath == "" {
		return nil
	}

	path := filepath.Join(stateDirectoryPath, cookieJarFileName(accountKey))

	err := os.Remove(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to remove cookie jar: %w", err)
	}

	return nil
}

// resolveAccountSelection returns the account key for the running command.
func resolveAccountSelection(cmd *cobra.Command) string {
	if accountProfile != "" {
		return resolveStoredAccountKey(accountProfile)
	}

	if emailFlag := cmd.Flags().Lookup("email"); emailFlag != nil {
		if email := normalizeAccountKey(emailFlag.Value.String()); email != "" {
			return resolveStoredAccountKey(email)
		}
	}

	active, err := readActiveAccountKey()
	if err != nil || active == "" {
		return ""
	}

	// An active account file left behind without a registry entry cannot be
	// used, so fall back to the legacy single-account state instead.
	registered, err := accountProfileExists(active)
	if err != nil || !registered {
		return ""
	}

	return active
}

// ensureSelectedAccountKey rejects a command that needs an account when more
// than one account is stored but none was selected. Installations that predate
// account profiles keep the legacy single-account behavior.
func ensureSelectedAccountKey() error {
	if accountProfile != "" {
		exists, err := accountProfileExists(selectedAccountKey)
		if err != nil {
			return err
		}

		if !exists {
			return fmt.Errorf("account not found: %s", accountProfile)
		}

		return nil
	}

	if normalizeAccountKey(selectedAccountKey) != "" {
		return nil
	}

	registry, err := loadAccountRegistry()
	if err != nil {
		return err
	}

	if len(registry.Accounts) == 0 {
		return nil
	}

	return errors.New("no account selected; use the \"--account\" flag or run \"ipatool auth use <account>\"")
}
