package cmd

import (
	"context"
	"errors"
	gohttp "net/http"
	"net/url"
	"os"
	"path/filepath"

	"github.com/majd/ipatool/v2/pkg/appstore"
	"github.com/majd/ipatool/v2/pkg/log"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Account profiles", func() {
	var directory string

	BeforeEach(func() {
		previousDependencies := dependencies
		DeferCleanup(func() { dependencies = previousDependencies })
		previousStateDirectory := stateDirectoryPath
		directory = GinkgoT().TempDir()
		stateDirectoryPath = directory
		DeferCleanup(func() { stateDirectoryPath = previousStateDirectory })
		previousAccountProfile, previousSelectedAccountKey := accountProfile, selectedAccountKey
		accountProfile, selectedAccountKey = "", ""
		DeferCleanup(func() {
			accountProfile, selectedAccountKey = previousAccountProfile, previousSelectedAccountKey
		})
		dependencies.Logger = log.NewLogger(log.Args{})
	})

	Describe("Keychain scoping", func() {
		It("rewrites only the account key and shares machine state", func() {
			base := newMemoryKeychain()
			accountKey := "User@Example.com"
			chain := newScopedKeychain(base, &accountKey)

			Expect(chain.Set("account", []byte("credentials"))).To(Succeed())
			Expect(chain.Set("anisette-v4", []byte("machine"))).To(Succeed())
			Expect(base.items).To(HaveKeyWithValue("account:user@example.com", []byte("credentials")))
			Expect(base.items).To(HaveKeyWithValue("anisette-v4", []byte("machine")))

			data, err := chain.Get("account")
			Expect(err).NotTo(HaveOccurred())
			Expect(data).To(Equal([]byte("credentials")))

			Expect(chain.Remove("account")).To(Succeed())
			Expect(base.items).NotTo(HaveKey("account:user@example.com"))
			Expect(base.items).To(HaveKey("anisette-v4"))
		})

		It("keeps the legacy account key when no account is selected", func() {
			base := newMemoryKeychain()
			accountKey := ""
			chain := newScopedKeychain(base, &accountKey)

			Expect(chain.Set("account", []byte("credentials"))).To(Succeed())
			Expect(base.items).To(HaveKeyWithValue("account", []byte("credentials")))
		})
	})

	Describe("Cookie jar scoping", func() {
		It("names the legacy jar without a suffix", func() {
			Expect(cookieJarFileName("")).To(Equal(CookieJarFileName))
		})

		It("escapes the account key into a separate file", func() {
			Expect(cookieJarFileName("a/b")).To(Equal("cookies-a%2Fb"))
			Expect(cookieJarFileName(" User@Example.com ")).To(Equal("cookies-user@example.com"))
		})

		It("follows the selected account", func() {
			u, err := url.Parse("https://example.com")
			Expect(err).NotTo(HaveOccurred())
			first, second := "first@example.com", "second@example.com"
			selected := first
			jar := newScopedCookieJar(directory, &selected)

			jar.SetCookies(u, []*gohttp.Cookie{{Name: "session", Value: "first"}})
			Expect(jar.Save()).To(Succeed())
			Expect(filepath.Join(directory, cookieJarFileName(first))).To(BeAnExistingFile())
			Expect(jar.Cookies(u)).To(HaveLen(1))

			selected = second
			Expect(jar.Cookies(u)).To(BeEmpty())

			jar.SetCookies(u, []*gohttp.Cookie{{Name: "session", Value: "second"}})
			Expect(jar.Save()).To(Succeed())
			Expect(filepath.Join(directory, cookieJarFileName(second))).To(BeAnExistingFile())
		})
	})

	Describe("Registry", func() {
		It("stores profiles with private permissions and resolves them by email", func() {
			Expect(upsertAccountProfile("User@Example.com", "user@example.com")).To(Succeed())

			records, err := listAccountProfiles()
			Expect(err).NotTo(HaveOccurred())
			Expect(records).To(HaveLen(1))
			Expect(records[0].Key).To(Equal("user@example.com"))
			Expect(records[0].Email).To(Equal("user@example.com"))

			info, err := os.Stat(accountRegistryPath())
			Expect(err).NotTo(HaveOccurred())
			Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o600)))

			Expect(resolveStoredAccountKey("USER@example.com")).To(Equal("user@example.com"))
			exists, err := accountProfileExists("user@example.com")
			Expect(err).NotTo(HaveOccurred())
			Expect(exists).To(BeTrue())

			Expect(removeAccountProfile("user@example.com")).To(Succeed())
			records, err = listAccountProfiles()
			Expect(err).NotTo(HaveOccurred())
			Expect(records).To(BeEmpty())
		})

		It("resolves a stored email to the key it was registered under", func() {
			registry := emptyAccountRegistry()
			registry.Accounts["+8613912345678"] = accountProfileRecord{
				Key:   "+8613912345678",
				Email: "user@example.com",
			}
			Expect(saveAccountRegistry(registry)).To(Succeed())

			Expect(resolveStoredAccountKey("USER@example.com")).To(Equal("+8613912345678"))
		})

		It("stores and clears the active account pointer", func() {
			Expect(writeActiveAccountKey("User@Example.com")).To(Succeed())
			active, err := readActiveAccountKey()
			Expect(err).NotTo(HaveOccurred())
			Expect(active).To(Equal("user@example.com"))

			Expect(clearActiveAccountKey()).To(Succeed())
			active, err = readActiveAccountKey()
			Expect(err).NotTo(HaveOccurred())
			Expect(active).To(BeEmpty())
		})
	})

	Describe("Account selection", func() {
		BeforeEach(func() {
			Expect(upsertAccountProfile("first@example.com", "first@example.com")).To(Succeed())
			Expect(upsertAccountProfile("second@example.com", "second@example.com")).To(Succeed())
		})

		It("prefers the account flag", func() {
			accountProfile = "second@example.com"
			Expect(resolveAccountSelection(loginCmd())).To(Equal("second@example.com"))
		})

		It("uses the email flag", func() {
			cmd := loginCmd()
			Expect(cmd.Flags().Parse([]string{"--email", "SECOND@example.com"})).To(Succeed())
			Expect(resolveAccountSelection(cmd)).To(Equal("second@example.com"))
		})

		It("falls back to the active account", func() {
			Expect(writeActiveAccountKey("first@example.com")).To(Succeed())
			Expect(resolveAccountSelection(searchCmd())).To(Equal("first@example.com"))
		})

		It("ignores an active account that is not registered", func() {
			Expect(os.WriteFile(activeAccountPath(), []byte("third@example.com"), 0o600)).To(Succeed())
			Expect(resolveAccountSelection(searchCmd())).To(BeEmpty())
		})

		It("requires a selection once profiles exist", func() {
			Expect(ensureSelectedAccountKey()).To(MatchError(ContainSubstring("no account selected")))

			selectedAccountKey = "first@example.com"
			Expect(ensureSelectedAccountKey()).To(Succeed())
		})

		It("keeps the legacy behavior without profiles", func() {
			Expect(removeAccountProfile("first@example.com")).To(Succeed())
			Expect(removeAccountProfile("second@example.com")).To(Succeed())
			Expect(ensureSelectedAccountKey()).To(Succeed())
		})

		It("rejects an unknown account flag", func() {
			accountProfile = "missing@example.com"
			selectedAccountKey = "missing@example.com"

			Expect(ensureSelectedAccountKey()).To(MatchError("account not found: missing@example.com"))
		})
	})

	Describe("Login command", func() {
		It("keys credentials by the entered Apple ID instead of the active account", func() {
			Expect(upsertAccountProfile("first@example.com", "first@example.com")).To(Succeed())
			Expect(writeActiveAccountKey("first@example.com")).To(Succeed())
			selectedAccountKey = "first@example.com"

			base := newMemoryKeychain()
			dependencies.Keychain = newScopedKeychain(base, &selectedAccountKey)
			store := &fakeLoginAppStore{}
			dependencies.AppStore = store

			cmd := loginCmd()
			cmd.SetContext(context.WithValue(context.Background(), interactiveKey, false))
			cmd.SetArgs([]string{"--email", "second@example.com", "--password", "secret"})

			Expect(cmd.Execute()).To(Succeed())
			Expect(selectedAccountKey).To(Equal("second@example.com"))

			active, err := readActiveAccountKey()
			Expect(err).NotTo(HaveOccurred())
			Expect(active).To(Equal("second@example.com"))

			records, err := listAccountProfiles()
			Expect(err).NotTo(HaveOccurred())
			Expect(records).To(HaveLen(2))
		})

		It("keeps an explicitly selected account slot", func() {
			Expect(upsertAccountProfile("first@example.com", "first@example.com")).To(Succeed())
			accountProfile = "first@example.com"
			selectedAccountKey = "first@example.com"
			dependencies.AppStore = &fakeLoginAppStore{}

			cmd := loginCmd()
			cmd.SetContext(context.WithValue(context.Background(), interactiveKey, false))
			cmd.SetArgs([]string{"--email", "second@example.com", "--password", "secret"})

			Expect(cmd.Execute()).To(Succeed())
			Expect(selectedAccountKey).To(Equal("first@example.com"))
		})
	})

	Describe("Revoke command", func() {
		It("removes the profile, active pointer, and cookie jar", func() {
			Expect(upsertAccountProfile("first@example.com", "first@example.com")).To(Succeed())
			Expect(writeActiveAccountKey("first@example.com")).To(Succeed())
			selectedAccountKey = "first@example.com"
			jarPath := filepath.Join(directory, cookieJarFileName(selectedAccountKey))
			Expect(os.WriteFile(jarPath, []byte("cookies"), 0o600)).To(Succeed())
			store := &fakeRevokeAppStore{}
			dependencies.AppStore = store

			Expect(revokeCmd().Execute()).To(Succeed())
			Expect(store.revokeCalls).To(Equal(1))

			exists, err := accountProfileExists("first@example.com")
			Expect(err).NotTo(HaveOccurred())
			Expect(exists).To(BeFalse())
			active, err := readActiveAccountKey()
			Expect(err).NotTo(HaveOccurred())
			Expect(active).To(BeEmpty())
			Expect(jarPath).NotTo(BeAnExistingFile())
		})

		It("leaves legacy files alone when no account is selected", func() {
			legacyPath := filepath.Join(directory, CookieJarFileName)
			Expect(os.WriteFile(legacyPath, []byte("cookies"), 0o600)).To(Succeed())
			store := &fakeRevokeAppStore{}
			dependencies.AppStore = store

			Expect(revokeCmd().Execute()).To(Succeed())
			Expect(store.revokeCalls).To(Equal(1))
			Expect(legacyPath).To(BeAnExistingFile())
		})
	})

	Describe("Use command", func() {
		BeforeEach(func() {
			Expect(upsertAccountProfile("first@example.com", "first@example.com")).To(Succeed())
		})

		It("sets the active account by email", func() {
			cmd := useCmd()
			cmd.SetArgs([]string{"first@example.com"})

			Expect(cmd.Execute()).To(Succeed())
			active, err := readActiveAccountKey()
			Expect(err).NotTo(HaveOccurred())
			Expect(active).To(Equal("first@example.com"))
		})

		It("rejects an unknown account", func() {
			cmd := useCmd()
			cmd.SetArgs([]string{"missing@example.com"})
			cmd.SilenceErrors = true
			cmd.SilenceUsage = true

			Expect(cmd.Execute()).To(MatchError("account not found: missing@example.com"))
		})
	})

	Describe("Command guards", func() {
		It("refuses account commands when profiles exist but none is selected", func() {
			Expect(upsertAccountProfile("first@example.com", "first@example.com")).To(Succeed())

			cmd := searchCmd()
			cmd.SetArgs([]string{"example"})
			cmd.SilenceErrors = true
			cmd.SilenceUsage = true

			Expect(cmd.Execute()).To(MatchError(ContainSubstring("no account selected")))
		})
	})
})

type memoryKeychain struct {
	items map[string][]byte
}

func newMemoryKeychain() *memoryKeychain {
	return &memoryKeychain{items: map[string][]byte{}}
}

func (m *memoryKeychain) Get(key string) ([]byte, error) {
	data, ok := m.items[key]
	if !ok {
		return nil, errors.New("item not found")
	}

	return data, nil
}

func (m *memoryKeychain) Set(key string, data []byte) error {
	m.items[key] = data

	return nil
}

func (m *memoryKeychain) Remove(key string) error {
	delete(m.items, key)

	return nil
}

type fakeRevokeAppStore struct {
	appstore.AppStore
	revokeCalls int
}

func (f *fakeRevokeAppStore) Revoke() error {
	f.revokeCalls++

	return nil
}
