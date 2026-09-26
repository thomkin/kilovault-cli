package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/thomkin/kilovault-cli/pkg/client"
	"github.com/thomkin/kilovault-cli/pkg/credentials"
	"github.com/thomkin/kilovault-cli/pkg/profiles"
	"github.com/thomkin/kilovault-cli/pkg/securestore"
	"github.com/urfave/cli/v2"
)

var (
	profilesDirFlag = &cli.StringFlag{
		Name:    "dir",
		Aliases: []string{"d"},
		Usage:   "Directory holding the encrypted <user>.json.enc profile files (default ~/.config/kilovault/profiles)",
		EnvVars: []string{"KILOVAULT_PROFILES_DIR"},
	}
	profilesUserFlag = &cli.StringFlag{
		Name:    "user",
		Aliases: []string{"u"},
		Usage:   "Only this profile (vault user id); default is all profiles",
	}
	profilesUserRequiredFlag = &cli.StringFlag{
		Name:     "user",
		Aliases:  []string{"u"},
		Usage:    "Profile (vault user id)",
		Required: true,
	}
	showValuesFlag = &cli.BoolFlag{
		Name:  "show-values",
		Usage: "Print values in the change list (plaintext secrets!)",
	}
	yesFlag = &cli.BoolFlag{
		Name:    "yes",
		Aliases: []string{"y"},
		Usage:   "Don't ask for confirmation",
	}
)

func profilesCommand() *cli.Command {
	return &cli.Command{
		Name:  "profiles",
		Usage: "Administer every vault user's keys as encrypted local profiles (needs `kilovault init`)",
		Subcommands: []*cli.Command{
			{
				Name:  "list",
				Usage: "Show local profiles, unpushed changes and which have an E2E secret",
				Flags: []cli.Flag{
					profilesDirFlag, profilesUserFlag,
					&cli.BoolFlag{Name: "keys", Aliases: []string{"k"}, Usage: "Also list each profile's key names (never values)"},
				},
				Action: runProfilesList,
			},
			{
				Name:  "pull",
				Usage: "Fetch profiles from the vault into the encrypted local files",
				Flags: []cli.Flag{
					profilesDirFlag, profilesUserFlag,
					&cli.BoolFlag{Name: "force", Usage: "Overwrite profiles that have unpushed local changes (discarding them)"},
				},
				Action: runProfilesPull,
			},
			{
				Name:   "diff",
				Usage:  "Show unpushed local changes (values hidden unless --show-values)",
				Flags:  []cli.Flag{profilesDirFlag, profilesUserFlag, showValuesFlag},
				Action: runProfilesDiff,
			},
			{
				Name:  "push",
				Usage: "Write unpushed local changes to the vault",
				Flags: []cli.Flag{
					profilesDirFlag, profilesUserFlag, showValuesFlag, yesFlag,
					&cli.BoolFlag{Name: "force", Usage: "Push even if the vault changed since the last pull (overwrites those changes)"},
				},
				Action: runProfilesPush,
			},
			{
				Name:   "new",
				Usage:  "Create a new, empty profile with a generated E2E secret",
				Flags:  []cli.Flag{profilesDirFlag, profilesUserRequiredFlag},
				Action: runProfilesNew,
			},
			{
				Name:  "edit",
				Usage: "Edit a profile in $EDITOR (decrypted only in RAM), then optionally push",
				Flags: []cli.Flag{
					profilesDirFlag, profilesUserRequiredFlag, showValuesFlag, yesFlag,
				},
				Action: runProfilesEdit,
			},
		},
	}
}

// profilesEnv is the unlocked state every profiles command works with.
type profilesEnv struct {
	p        *prompter
	store    *credentials.Store
	endpoint string
	dir      string
	cl       *client.Client // nil for offline commands
}

func openProfilesEnv(c *cli.Context, needServer bool) (*profilesEnv, error) {
	dir := c.String("dir")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		dir = filepath.Join(home, ".config", "kilovault", "profiles")
	}

	p := newPrompter()
	store, err := openStore(p)
	if err != nil {
		return nil, err
	}
	e := &profilesEnv{p: p, store: store, endpoint: resolvedEndpoint(c), dir: dir}
	if needServer {
		token := store.AdminToken(e.endpoint)
		if token == "" {
			store.Close()
			return nil, fmt.Errorf("no admin token stored for %s — run `kilovault credentials set-token`", e.endpoint)
		}
		e.cl = client.NewWithToken(e.endpoint, token)
	}
	return e, nil
}

func (e *profilesEnv) close() {
	e.store.Close()
}

func (e *profilesEnv) load(user string) (*profiles.Profile, error) {
	return profiles.Load(e.dir, e.store.DataKey(), e.endpoint, user)
}

func (e *profilesEnv) save(prof *profiles.Profile) error {
	return profiles.Save(e.dir, e.store.DataKey(), prof)
}

// remoteKeys lists keys via vault.admin.list grouped by user; user == ""
// means all users.
func (e *profilesEnv) remoteKeys(user string) (map[string][]string, error) {
	var filter *string
	if user != "" {
		filter = &user
	}
	list, err := e.cl.VaultAdminList(filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %v", err)
	}
	byUser := map[string][]string{}
	for _, k := range list.Keys {
		byUser[k.UserID] = append(byUser[k.UserID], k.Key)
	}
	return byUser, nil
}

// selectLocal returns the local profiles a command should work on.
func (e *profilesEnv) selectLocal(user string) ([]string, error) {
	if user != "" {
		if err := profiles.ValidateUser(user); err != nil {
			return nil, err
		}
		if !profiles.Exists(e.dir, user) {
			return nil, fmt.Errorf("no local profile %q (run `kilovault profiles pull -u %s` or `profiles new -u %s`)", user, user, user)
		}
		return []string{user}, nil
	}
	users, err := profiles.ListLocal(e.dir)
	if err != nil {
		return nil, err
	}
	if len(users) == 0 {
		return nil, fmt.Errorf("no profiles in %s (run `kilovault profiles pull` first)", e.dir)
	}
	return users, nil
}

func warnf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "! "+format+"\n", args...)
}

// ---- list ----

func runProfilesList(c *cli.Context) error {
	e, err := openProfilesEnv(c, false)
	if err != nil {
		return err
	}
	defer e.close()

	users, err := profiles.ListLocal(e.dir)
	if err != nil {
		return err
	}
	if only := c.String("user"); only != "" {
		if !slices.Contains(users, only) {
			return fmt.Errorf("no local profile %q — run `kilovault profiles pull -u %s`", only, only)
		}
		users = []string{only}
	}
	if len(users) == 0 {
		fmt.Printf("No profiles in %s\n", e.dir)
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PROFILE\tKEYS\tUNPUSHED\tE2E SECRET\tLAST SYNC")
	var loaded []*profiles.Profile
	for _, user := range users {
		prof, err := e.load(user)
		if err != nil {
			fmt.Fprintf(w, "%s\t?\t?\t?\terror: %v\n", user, err)
			continue
		}
		loaded = append(loaded, prof)
		secret := "missing"
		if e.store.Secret(e.endpoint, user) != "" {
			secret = "stored"
		}
		synced := prof.SyncedAt
		if synced == "" {
			synced = "never"
		}
		fmt.Fprintf(w, "%s\t%d\t%d\t%s\t%s\n", user, len(prof.Values), len(prof.Changes()), secret, synced)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if c.Bool("keys") {
		for _, prof := range loaded {
			keys := make([]string, 0, len(prof.Values))
			for key := range prof.Values {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			fmt.Printf("\n%s:\n", prof.User)
			for _, key := range keys {
				fmt.Printf("  %s\n", key)
			}
		}
	}
	return nil
}

// ---- pull ----

func runProfilesPull(c *cli.Context) error {
	e, err := openProfilesEnv(c, true)
	if err != nil {
		return err
	}
	defer e.close()

	only := c.String("user")
	byUser, err := e.remoteKeys(only)
	if err != nil {
		return err
	}
	if only != "" && len(byUser[only]) == 0 {
		return fmt.Errorf("no keys found on %s for user %q", e.endpoint, only)
	}

	users := make([]string, 0, len(byUser))
	for u := range byUser {
		users = append(users, u)
	}
	sort.Strings(users)

	skipped := 0
	for _, user := range users {
		ok, err := e.pullUser(user, byUser[user], c.Bool("force"))
		if err != nil {
			return err
		}
		if !ok {
			skipped++
		}
	}

	if only == "" {
		local, err := profiles.ListLocal(e.dir)
		if err != nil {
			return err
		}
		for _, user := range local {
			if _, onServer := byUser[user]; !onServer {
				warnf("%s: exists locally but has no keys on the server (left untouched)", user)
			}
		}
	}
	if skipped > 0 {
		return fmt.Errorf("%d profile(s) skipped", skipped)
	}
	return nil
}

// pullUser replaces the local profile for user with the server's keys.
// It returns false (after printing why) when the profile is skipped;
// errors are reserved for failures that should stop the whole pull.
func (e *profilesEnv) pullUser(user string, keys []string, force bool) (bool, error) {
	if err := profiles.ValidateUser(user); err != nil {
		warnf("%s: skipped — %v", user, err)
		return false, nil
	}
	if profiles.Exists(e.dir, user) && !force {
		local, err := e.load(user)
		if err != nil {
			warnf("%s: skipped — %v (use --force to overwrite)", user, err)
			return false, nil
		}
		if n := len(local.Changes()); n > 0 {
			warnf("%s: skipped — %d unpushed local change(s); push them, or use --force to discard", user, n)
			return false, nil
		}
	}

	stored := map[string]string{}
	var encryptedKey string
	for _, key := range keys {
		if err := profiles.ValidateKey(key); err != nil {
			warnf("%s: skipped — %v", user, err)
			return false, nil
		}
		got, err := e.cl.VaultAdminGet(user, key)
		if err != nil {
			return false, fmt.Errorf("failed to fetch %s/%s: %v", user, key, err)
		}
		stored[key] = got.Value
		if encryptedKey == "" && client.IsEncrypted(got.Value) {
			encryptedKey = key
		}
	}

	secret := e.store.Secret(e.endpoint, user)
	if encryptedKey != "" && secret == "" {
		var err error
		if secret, err = e.askSecret(user, stored[encryptedKey]); err != nil {
			return false, err
		}
		if secret == "" {
			warnf("%s: skipped — has encrypted values but no E2E secret is stored (run `kilovault credentials set-secret -u %s`)", user, user)
			return false, nil
		}
	}

	prof := profiles.New(e.endpoint, user)
	for key, value := range stored {
		plain, encrypted := value, client.IsEncrypted(value)
		if encrypted {
			b, err := client.DecryptBytes(secret, value)
			if err != nil {
				warnf("%s: skipped — the stored E2E secret doesn't decrypt %q", user, key)
				return false, nil
			}
			plain = string(b)
			client.ZeroBytes(b)
		}
		prof.Values[key] = plain
		prof.Base[key] = profiles.KeyState{Value: plain, Remote: profiles.RemoteHash(value), Encrypted: encrypted}
	}
	prof.SyncedAt = time.Now().UTC().Format(time.RFC3339)
	if err := e.save(prof); err != nil {
		return false, fmt.Errorf("failed to save profile %q: %v", user, err)
	}
	fmt.Printf("✓ %s: %d key(s)\n", user, len(prof.Values))
	return true, nil
}

// askSecret prompts (on a terminal only) for user's E2E secret, checks
// it against one of their encrypted values and stores it. It returns ""
// if the user skipped or the secret was wrong.
func (e *profilesEnv) askSecret(user, encryptedValue string) (string, error) {
	if !e.p.tty {
		return "", nil
	}
	fmt.Fprintf(os.Stderr, "%s has encrypted values but no E2E secret is stored.\n", user)
	b, err := e.p.optionalSecret(fmt.Sprintf("E2E secret for %s (empty = skip)", user))
	if err != nil || b == nil {
		return "", err
	}
	defer securestore.Wipe(b)
	secret := string(b)
	plain, err := client.DecryptBytes(secret, encryptedValue)
	if err != nil {
		warnf("%s: that secret doesn't decrypt the stored values", user)
		return "", nil
	}
	client.ZeroBytes(plain)
	e.store.SetSecret(e.endpoint, user, secret)
	if err := e.store.Save(); err != nil {
		return "", err
	}
	fmt.Fprintf(os.Stderr, "✓ Verified and saved the E2E secret for %s\n", user)
	return secret, nil
}

// ---- diff ----

func runProfilesDiff(c *cli.Context) error {
	e, err := openProfilesEnv(c, false)
	if err != nil {
		return err
	}
	defer e.close()
	users, err := e.selectLocal(c.String("user"))
	if err != nil {
		return err
	}

	total := 0
	for _, user := range users {
		prof, err := e.load(user)
		if err != nil {
			return err
		}
		if changes := prof.Changes(); len(changes) > 0 {
			printChanges(user, changes, c.Bool("show-values"))
			total += len(changes)
		}
	}
	if total == 0 {
		fmt.Println("No unpushed changes.")
	}
	return nil
}

func printChanges(user string, changes []profiles.Change, showValues bool) {
	fmt.Printf("%s:\n", user)
	for _, ch := range changes {
		line := "  " + ch.Kind.Symbol() + " " + ch.Key
		if showValues {
			switch ch.Kind {
			case profiles.Add:
				line += " = " + strconv.Quote(ch.New)
			case profiles.Modify:
				line += ": " + strconv.Quote(ch.Old) + " → " + strconv.Quote(ch.New)
			case profiles.Delete:
				line += " (was " + strconv.Quote(ch.Old) + ")"
			}
		}
		fmt.Println(line)
	}
}

// ---- push ----

func runProfilesPush(c *cli.Context) error {
	e, err := openProfilesEnv(c, true)
	if err != nil {
		return err
	}
	defer e.close()
	users, err := e.selectLocal(c.String("user"))
	if err != nil {
		return err
	}
	return e.push(users, c.Bool("show-values"), c.Bool("yes"), c.Bool("force"))
}

type pushPlan struct {
	prof    *profiles.Profile
	changes []profiles.Change
	secret  string
}

// push plans and checks every profile before writing anything, so a
// conflict in one doesn't leave others half-pushed.
func (e *profilesEnv) push(users []string, showValues, yes, force bool) error {
	var plans []pushPlan
	var conflicts []string
	for _, user := range users {
		prof, err := e.load(user)
		if err != nil {
			return err
		}
		changes := prof.Changes()
		if len(changes) == 0 {
			continue
		}

		secret := e.store.Secret(e.endpoint, user)
		for _, ch := range changes {
			needsSecret := ch.Kind == profiles.Add || ch.Kind == profiles.Modify && prof.Base[ch.Key].Encrypted
			if needsSecret && secret == "" {
				return fmt.Errorf("%s: no E2E secret stored to encrypt %q — run `kilovault credentials set-secret -u %s`", user, ch.Key, user)
			}
		}

		byUser, err := e.remoteKeys(user)
		if err != nil {
			return err
		}
		onServer := map[string]bool{}
		for _, k := range byUser[user] {
			onServer[k] = true
		}
		for _, ch := range changes {
			base, synced := prof.Base[ch.Key]
			switch {
			case !synced && onServer[ch.Key]:
				conflicts = append(conflicts, fmt.Sprintf("%s/%s: added locally but also created on the server", user, ch.Key))
			case synced && !onServer[ch.Key] && ch.Kind == profiles.Modify:
				conflicts = append(conflicts, fmt.Sprintf("%s/%s: changed locally but deleted on the server", user, ch.Key))
			case synced && onServer[ch.Key]:
				got, err := e.cl.VaultAdminGet(user, ch.Key)
				if err != nil {
					return fmt.Errorf("failed to fetch %s/%s: %v", user, ch.Key, err)
				}
				if profiles.RemoteHash(got.Value) != base.Remote {
					conflicts = append(conflicts, fmt.Sprintf("%s/%s: changed on the server since the last pull", user, ch.Key))
				}
			}
		}
		plans = append(plans, pushPlan{prof: prof, changes: changes, secret: secret})
	}

	if len(plans) == 0 {
		fmt.Println("Nothing to push.")
		return nil
	}
	for _, plan := range plans {
		printChanges(plan.prof.User, plan.changes, showValues)
	}
	if len(conflicts) > 0 {
		fmt.Fprintln(os.Stderr, "Conflicts:")
		for _, cf := range conflicts {
			fmt.Fprintf(os.Stderr, "  ! %s\n", cf)
		}
		if !force {
			return fmt.Errorf("%d conflict(s): use --force to overwrite the server, or `profiles pull --force` to discard your local changes", len(conflicts))
		}
	}
	if !yes && !e.p.confirm("Push these changes?") {
		return fmt.Errorf("aborted — nothing was pushed")
	}

	applied := 0
	for _, plan := range plans {
		err := e.applyPlan(plan, &applied)
		// Save whatever was applied, even on failure, so the next
		// diff/push picks up exactly where this one stopped.
		if saveErr := e.save(plan.prof); saveErr != nil && err == nil {
			err = fmt.Errorf("failed to save profile %q: %v", plan.prof.User, saveErr)
		}
		if err != nil {
			return fmt.Errorf("push stopped after %d change(s) — earlier changes are already applied: %v", applied, err)
		}
	}
	fmt.Printf("✓ Pushed %d change(s)\n", applied)
	return nil
}

func (e *profilesEnv) applyPlan(plan pushPlan, applied *int) error {
	prof := plan.prof
	for _, ch := range plan.changes {
		label := prof.User + "/" + ch.Key
		if ch.Kind == profiles.Delete {
			if _, err := e.cl.VaultAdminDelete(prof.User, ch.Key); err != nil {
				return fmt.Errorf("%s: %v", label, err)
			}
			delete(prof.Base, ch.Key)
			*applied++
			continue
		}

		// New keys are always encrypted; existing keys keep their mode.
		encrypt := true
		if base, synced := prof.Base[ch.Key]; synced {
			encrypt = base.Encrypted
		}
		stored := ch.New
		if encrypt {
			var err error
			if stored, err = client.Encrypt(plan.secret, ch.New); err != nil {
				return fmt.Errorf("%s: %v", label, err)
			}
		}
		if err := e.cl.VaultAdminSet(prof.User, ch.Key, stored); err != nil {
			return fmt.Errorf("%s: %v", label, err)
		}
		prof.Base[ch.Key] = profiles.KeyState{Value: ch.New, Remote: profiles.RemoteHash(stored), Encrypted: encrypt}
		*applied++
	}
	prof.SyncedAt = time.Now().UTC().Format(time.RFC3339)
	return nil
}

// ---- new ----

func runProfilesNew(c *cli.Context) error {
	user := c.String("user")
	if err := profiles.ValidateUser(user); err != nil {
		return err
	}
	e, err := openProfilesEnv(c, true)
	if err != nil {
		return err
	}
	defer e.close()

	if profiles.Exists(e.dir, user) {
		return fmt.Errorf("profile %q already exists locally", user)
	}
	byUser, err := e.remoteKeys(user)
	if err != nil {
		return err
	}
	if n := len(byUser[user]); n > 0 {
		return fmt.Errorf("%s already has %d key(s) on %s — use `kilovault profiles pull -u %s`", user, n, e.endpoint, user)
	}

	if e.store.Secret(e.endpoint, user) == "" {
		secret, err := credentials.GenerateSecret()
		if err != nil {
			return err
		}
		e.store.SetSecret(e.endpoint, user, secret)
		if err := e.store.Save(); err != nil {
			return err
		}
		fmt.Printf("✓ Generated and stored an E2E secret for %s\n", user)
		fmt.Fprintf(os.Stderr, "  Hosts that fetch %s's keys need it: `kilovault credentials show-secret -u %s`.\n", user, user)
	}
	if err := e.save(profiles.New(e.endpoint, user)); err != nil {
		return err
	}
	fmt.Printf("✓ Created empty profile %s — add keys with `kilovault profiles edit -u %s`\n", user, user)
	backupReminder(e.store)
	return nil
}
