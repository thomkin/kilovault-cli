package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/thomkin/kilovault-cli/pkg/client"
	"github.com/thomkin/kilovault-cli/pkg/credentials"
	"github.com/thomkin/kilovault-cli/pkg/securestore"
	"github.com/thomkin/kilovault-cli/pkg/session"
	"github.com/urfave/cli/v2"
)

var skipVerifyFlag = &cli.BoolFlag{
	Name:  "skip-verify",
	Usage: "Don't check the value against the server before saving",
}

var credentialsUserFlag = &cli.StringFlag{
	Name:     "user",
	Aliases:  []string{"u"},
	Usage:    "Profile (vault user id)",
	Required: true,
}

func initCommand() *cli.Command {
	return &cli.Command{
		Name:   "init",
		Usage:  "Set up the encrypted credentials store (admin token + master password) for the profiles workflow",
		Flags:  []cli.Flag{skipVerifyFlag},
		Action: runInit,
	}
}

func credentialsCommand() *cli.Command {
	return &cli.Command{
		Name:  "credentials",
		Usage: "Manage the encrypted credentials store (admin token and per-profile E2E secrets)",
		Subcommands: []*cli.Command{
			{
				Name:   "list",
				Usage:  "Show what is stored (never prints secret values)",
				Action: runCredentialsList,
			},
			{
				Name:   "set-token",
				Usage:  "Store or replace the admin token (read from a hidden prompt or stdin)",
				Flags:  []cli.Flag{skipVerifyFlag},
				Action: runCredentialsSetToken,
			},
			{
				Name:  "set-secret",
				Usage: "Store or replace a profile's E2E secret (read from a hidden prompt or stdin)",
				Flags: []cli.Flag{
					credentialsUserFlag,
					&cli.BoolFlag{
						Name:  "generate",
						Usage: "Generate a random secret instead of prompting (for a profile with no encrypted values yet)",
					},
					skipVerifyFlag,
				},
				Action: runCredentialsSetSecret,
			},
			{
				Name:   "remove-secret",
				Usage:  "Forget a profile's E2E secret",
				Flags:  []cli.Flag{credentialsUserFlag},
				Action: runCredentialsRemoveSecret,
			},
			{
				Name:   "show-secret",
				Usage:  "Print a profile's E2E secret to stdout (e.g. to provision a host that fetches its keys)",
				Flags:  []cli.Flag{credentialsUserFlag},
				Action: runCredentialsShowSecret,
			},
			{
				Name:   "passwd",
				Usage:  "Change the master password",
				Action: runCredentialsPasswd,
			},
			{
				Name:  "backup",
				Usage: "Write a copy of the store protected by a separate recovery passphrase",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "out", Aliases: []string{"o"}, Usage: "Backup file to create (must not exist)", Required: true},
				},
				Action: runCredentialsBackup,
			},
			{
				Name:  "restore",
				Usage: "Recreate the store from a backup (asks for the recovery passphrase and a new master password)",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "in", Aliases: []string{"i"}, Usage: "Backup file", Required: true},
				},
				Action: runCredentialsRestore,
			},
		},
	}
}

// credentialsPath returns the store location and hardens the process;
// every credentials command calls it before touching any secret.
func credentialsPath() (string, error) {
	if err := securestore.HardenProcess(); err != nil {
		return "", err
	}
	return credentials.DefaultPath()
}

// resolvedEndpoint is the endpoint the rest of the CLI would talk to,
// normalized the way the store keys it.
func resolvedEndpoint(c *cli.Context) string {
	return credentials.NormalizeEndpoint(client.New(getEndpoint(c)).BaseURL())
}

// openStore unlocks the store: from the `kilovault unlock` session if
// one is active, otherwise by asking for the master password.
func openStore(p *prompter) (*credentials.Store, error) {
	path, err := credentialsPath()
	if err != nil {
		return nil, err
	}
	if !credentials.Exists(path) {
		return nil, credentials.ErrNotInitialized
	}
	if store, err := storeFromSession(path); store != nil || err != nil {
		return store, err
	}
	return unlockWithPassword(p, path)
}

// storeFromSession opens the store with the cached session key. It
// returns (nil, nil) when there's no usable session, dropping one whose
// key no longer opens the store (e.g. after `credentials passwd`).
func storeFromSession(path string) (*credentials.Store, error) {
	id, err := session.ID(path)
	if err != nil {
		return nil, nil
	}
	sess, err := session.Load(id)
	if err != nil || sess == nil {
		return nil, nil // no keyring here, or not unlocked: fall back to the password
	}
	store, err := credentials.UnlockWithKey(path, sess.Key)
	securestore.Wipe(sess.Key)
	if errors.Is(err, securestore.ErrDecrypt) {
		session.Clear(id)
		return nil, nil
	}
	return store, err
}

// unlockWithPassword asks for the master password and unlocks the
// store. On a terminal, a wrong password may be retried up to three times.
func unlockWithPassword(p *prompter, path string) (*credentials.Store, error) {
	attempts := 1
	if p.tty && os.Getenv(masterPasswordEnv) == "" {
		attempts = 3
	}
	for i := 0; ; i++ {
		pw, err := p.masterPassword()
		if err != nil {
			return nil, err
		}
		store, err := credentials.Unlock(path, pw)
		securestore.Wipe(pw)
		if err == nil {
			return store, nil
		}
		if !errors.Is(err, securestore.ErrDecrypt) || i+1 >= attempts {
			return nil, err
		}
		fmt.Fprintln(os.Stderr, "Wrong master password, try again.")
	}
}

func backupReminder(store *credentials.Store) {
	if store.Payload.BackupAt == "" {
		fmt.Fprintln(os.Stderr, "! No backup yet. The per-profile secrets exist only in this store — if it's lost,")
		fmt.Fprintln(os.Stderr, "  encrypted vault values can't be recovered. Run `kilovault credentials backup -o <file>`.")
	}
}

func verifyAdminToken(endpoint, token string) error {
	if _, err := client.NewWithToken(endpoint, token).VaultAdminList(nil); err != nil {
		return fmt.Errorf("admin token check against %s failed: %v (use --skip-verify to save anyway)", endpoint, err)
	}
	return nil
}

func runInit(c *cli.Context) error {
	path, err := credentialsPath()
	if err != nil {
		return err
	}
	if credentials.Exists(path) {
		return fmt.Errorf("%s already exists — use `kilovault credentials set-token` or `credentials passwd` to change it", path)
	}

	p := newPrompter()
	endpoint, err := p.text("Endpoint", resolvedEndpoint(c))
	if err != nil {
		return err
	}
	endpoint = credentials.NormalizeEndpoint(endpoint)

	token, err := p.secret("Admin token")
	if err != nil {
		return err
	}
	defer securestore.Wipe(token)
	if !c.Bool("skip-verify") {
		if err := verifyAdminToken(endpoint, string(token)); err != nil {
			return err
		}
	}

	var password []byte
	if env := os.Getenv(masterPasswordEnv); env != "" {
		password = []byte(env)
		if err := securestore.ValidateMasterPassword(password); err != nil {
			return err
		}
	} else if password, err = p.newPassword("New master password"); err != nil {
		return err
	}
	defer securestore.Wipe(password)

	store, err := credentials.Create(path, password)
	if err != nil {
		return err
	}
	defer store.Close()
	store.SetAdminToken(endpoint, string(token))
	if err := store.Save(); err != nil {
		return err
	}

	cfg, err := client.LoadConfigFile()
	if err != nil {
		return fmt.Errorf("failed to load config: %v", err)
	}
	if credentials.NormalizeEndpoint(cfg.Endpoint) != endpoint {
		cfg.Endpoint = endpoint
		if err := client.SaveConfig(cfg); err != nil {
			return fmt.Errorf("failed to save endpoint to config: %v", err)
		}
		fmt.Printf("✓ Saved endpoint %s to config.json\n", endpoint)
	}
	fmt.Printf("✓ Created %s (admin token for %s)\n", path, endpoint)
	fmt.Println("  Next: add each profile's E2E secret with `kilovault credentials set-secret -u <user>`.")
	backupReminder(store)
	return nil
}

func runCredentialsList(c *cli.Context) error {
	store, err := openStore(newPrompter())
	if err != nil {
		return err
	}
	defer store.Close()

	endpoint := resolvedEndpoint(c)
	fmt.Printf("Endpoint: %s\n", endpoint)
	if token := store.AdminToken(endpoint); token != "" {
		fmt.Printf("  Admin token: set%s\n", describeToken(token))
	} else {
		fmt.Println("  Admin token: not set")
	}
	if profiles := store.Profiles(endpoint); len(profiles) > 0 {
		fmt.Printf("  Profile secrets: %s\n", strings.Join(profiles, ", "))
	} else {
		fmt.Println("  Profile secrets: none")
	}

	for other, v := range store.Payload.Vaults {
		if other != endpoint {
			fmt.Printf("Other endpoint: %s (%d profile secret(s), admin token %s)\n", other, len(v.Secrets), map[bool]string{true: "set", false: "not set"}[v.AdminToken != ""])
		}
	}

	fmt.Printf("Session: %s\n", describeSession(store.Path()))
	if store.Payload.BackupAt != "" {
		fmt.Printf("Last backup: %s\n", store.Payload.BackupAt)
	} else {
		fmt.Println("Last backup: never")
	}
	return nil
}

// describeToken summarizes a JWT's subject and expiry without verifying
// it (for display only).
func describeToken(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims client.JWTPayload
	if json.Unmarshal(raw, &claims) != nil {
		return ""
	}
	desc := fmt.Sprintf(" (user %q", claims.Sub)
	switch {
	case claims.Exp == 0:
		desc += ", no expiry"
	case time.Unix(claims.Exp, 0).Before(time.Now()):
		desc += ", EXPIRED " + time.Unix(claims.Exp, 0).UTC().Format(time.RFC3339)
	default:
		desc += ", expires " + time.Unix(claims.Exp, 0).UTC().Format(time.RFC3339)
	}
	return desc + ")"
}

func runCredentialsSetToken(c *cli.Context) error {
	p := newPrompter()
	store, err := openStore(p)
	if err != nil {
		return err
	}
	defer store.Close()

	endpoint := resolvedEndpoint(c)
	token, err := p.secret("Admin token for " + endpoint)
	if err != nil {
		return err
	}
	defer securestore.Wipe(token)
	if !c.Bool("skip-verify") {
		if err := verifyAdminToken(endpoint, string(token)); err != nil {
			return err
		}
	}
	store.SetAdminToken(endpoint, string(token))
	if err := store.Save(); err != nil {
		return err
	}
	fmt.Printf("✓ Saved admin token for %s\n", endpoint)
	return nil
}

// verifyProfileSecret checks secret against the first client-side
// encrypted value stored for user. checked is false when user has no
// encrypted value to check against.
func verifyProfileSecret(endpoint, adminToken, user, secret string) (checked bool, err error) {
	cl := client.NewWithToken(endpoint, adminToken)
	list, err := cl.VaultAdminList(&user)
	if err != nil {
		return false, fmt.Errorf("failed to list %s's keys: %v", user, err)
	}
	for _, k := range list.Keys {
		got, err := cl.VaultAdminGet(user, k.Key)
		if err != nil {
			return false, fmt.Errorf("failed to fetch %s/%s: %v", user, k.Key, err)
		}
		if !client.IsEncrypted(got.Value) {
			continue
		}
		plain, err := client.DecryptBytes(secret, got.Value)
		if err != nil {
			return true, fmt.Errorf("this secret doesn't decrypt %s's existing value %q — not saved", user, k.Key)
		}
		client.ZeroBytes(plain)
		return true, nil
	}
	return false, nil
}

func runCredentialsSetSecret(c *cli.Context) error {
	user := c.String("user")
	p := newPrompter()
	store, err := openStore(p)
	if err != nil {
		return err
	}
	defer store.Close()
	endpoint := resolvedEndpoint(c)

	var secret []byte
	if c.Bool("generate") {
		s, err := credentials.GenerateSecret()
		if err != nil {
			return err
		}
		secret = []byte(s)
	} else if secret, err = p.secret("E2E secret for " + user); err != nil {
		return err
	}
	defer securestore.Wipe(secret)

	if !c.Bool("skip-verify") {
		adminToken := store.AdminToken(endpoint)
		if adminToken == "" {
			return fmt.Errorf("no admin token stored for %s to verify with — run `kilovault credentials set-token`, or use --skip-verify", endpoint)
		}
		checked, err := verifyProfileSecret(endpoint, adminToken, user, string(secret))
		if err != nil {
			return err
		}
		if checked {
			fmt.Printf("✓ Verified against %s's encrypted values\n", user)
		} else {
			fmt.Fprintf(os.Stderr, "! %s has no encrypted values on %s yet — saved without verification\n", user, endpoint)
		}
	}

	replaced := store.Secret(endpoint, user) != ""
	store.SetSecret(endpoint, user, string(secret))
	if err := store.Save(); err != nil {
		return err
	}
	verb := "Saved"
	if replaced {
		verb = "Replaced"
	}
	if c.Bool("generate") {
		verb += " generated"
	}
	fmt.Printf("✓ %s E2E secret for %s\n", verb, user)
	backupReminder(store)
	return nil
}

func runCredentialsRemoveSecret(c *cli.Context) error {
	user := c.String("user")
	store, err := openStore(newPrompter())
	if err != nil {
		return err
	}
	defer store.Close()

	if !store.RemoveSecret(resolvedEndpoint(c), user) {
		return fmt.Errorf("no secret stored for %s", user)
	}
	if err := store.Save(); err != nil {
		return err
	}
	fmt.Printf("✓ Removed E2E secret for %s\n", user)
	fmt.Fprintln(os.Stderr, "  Note: an existing backup still contains it.")
	return nil
}

func runCredentialsShowSecret(c *cli.Context) error {
	user := c.String("user")
	store, err := openStore(newPrompter())
	if err != nil {
		return err
	}
	defer store.Close()

	secret := store.Secret(resolvedEndpoint(c), user)
	if secret == "" {
		return fmt.Errorf("no secret stored for %s", user)
	}
	if isTerminal(os.Stdout) {
		fmt.Fprintln(os.Stderr, "WARNING: printing a plaintext secret to the terminal. Prefer piping it, e.g. into ssh or a provisioning tool.")
	}
	fmt.Println(secret)
	return nil
}

func runCredentialsPasswd(c *cli.Context) error {
	p := newPrompter()
	store, err := openStore(p)
	if err != nil {
		return err
	}
	defer store.Close()

	pw, err := p.newPassword("New master password")
	if err != nil {
		return err
	}
	defer securestore.Wipe(pw)
	if err := store.ChangePassword(pw); err != nil {
		return err
	}
	fmt.Println("✓ Master password changed")
	if id, err := session.ID(store.Path()); err == nil {
		if cleared, _ := session.Clear(id); cleared {
			fmt.Fprintln(os.Stderr, "  The unlock session was ended; run `kilovault unlock` again if needed.")
		}
	}
	if store.Payload.BackupAt != "" {
		fmt.Fprintln(os.Stderr, "  Existing backups are unaffected: they still open with their own recovery passphrase.")
	}
	return nil
}

func runCredentialsBackup(c *cli.Context) error {
	p := newPrompter()
	store, err := openStore(p)
	if err != nil {
		return err
	}
	defer store.Close()

	fmt.Fprintln(os.Stderr, "Choose a recovery passphrase different from the master password, and keep it offline")
	fmt.Fprintln(os.Stderr, "(password manager or paper) — it's the only way to open this backup.")
	recovery, err := p.newPassword("Recovery passphrase")
	if err != nil {
		return err
	}
	defer securestore.Wipe(recovery)

	out := c.String("out")
	if err := store.WriteBackup(out, recovery); err != nil {
		return err
	}
	fmt.Printf("✓ Wrote encrypted backup to %s\n", out)
	return nil
}

func runCredentialsRestore(c *cli.Context) error {
	path, err := credentialsPath()
	if err != nil {
		return err
	}
	if credentials.Exists(path) {
		return fmt.Errorf("%s already exists — move it aside first if you really want to replace it", path)
	}

	p := newPrompter()
	recovery, err := p.secret("Recovery passphrase")
	if err != nil {
		return err
	}
	payload, err := credentials.OpenBackup(c.String("in"), recovery)
	securestore.Wipe(recovery)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "✓ Backup opened")

	pw, err := p.newPassword("New master password")
	if err != nil {
		securestore.Wipe(payload.DataKey)
		return err
	}
	defer securestore.Wipe(pw)

	store, err := credentials.CreateFromBackup(path, payload, pw)
	if err != nil {
		securestore.Wipe(payload.DataKey)
		return err
	}
	defer store.Close()
	fmt.Printf("✓ Restored %s from %s\n", path, c.String("in"))
	return nil
}
