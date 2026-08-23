package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/thomkin/kilovault-cli/pkg/client"
	"github.com/thomkin/kilovault-cli/pkg/service"
	"github.com/urfave/cli/v2"
)

func getEndpoint(c *cli.Context) string {
	if ep := c.String("endpoint"); ep != "" {
		return ep
	}
	return ""
}

// encryptIfSecret encrypts value client-side when secret is non-empty,
// leaving it untouched otherwise. The secret never leaves this process.
func encryptIfSecret(value, secret string) (string, error) {
	if secret == "" {
		return value, nil
	}
	encrypted, err := client.Encrypt(secret, value)
	if err != nil {
		return "", fmt.Errorf("Failed to encrypt value: %v", err)
	}
	return encrypted, nil
}

// decryptIfNeeded decrypts value when it carries the encrypted-value
// marker, requiring secret to be non-empty and correct. Plaintext values
// (no marker) are returned unchanged regardless of secret.
func decryptIfNeeded(value, secret string) (string, error) {
	if !client.IsEncrypted(value) {
		return value, nil
	}
	if secret == "" {
		return "", fmt.Errorf("value is encrypted; provide a secret via -s/--secret, KILOVAULT_SECRET, or config")
	}
	decrypted, err := client.Decrypt(secret, value)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt value: wrong secret or corrupted data")
	}
	return decrypted, nil
}

func main() {
	app := &cli.App{
		Name:    "kilovault-cli",
		Usage:   "CLI for kilovault secret management",
		Version: "0.0.1",
		// attr's --set/--remove values can contain commas (JSON arrays/
		// objects); disable urfave/cli's default comma-splitting of
		// StringSliceFlag values so a single occurrence is never split.
		DisableSliceFlagSeparator: true,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "endpoint",
				Aliases: []string{"e"},
				Usage:   "API endpoint (overrides env and config)",
			},
		},
		Commands: []*cli.Command{
			{
				Name:  "config",
				Usage: "Manage configuration",
				Subcommands: []*cli.Command{
					{
						Name:  "set",
						Usage: "Set config value",
						Action: func(c *cli.Context) error {
							if c.NArg() < 2 {
								return fmt.Errorf("key and value arguments required")
							}
							key := c.Args().Get(0)
							value := c.Args().Get(1)

							cfg, err := client.LoadConfigFile()
							if err != nil {
								return fmt.Errorf("Failed to load config: %v", err)
							}

							switch key {
							case "endpoint":
								cfg.Endpoint = value
							case "token":
								cfg.Token = value
							case "jwt_secret":
								cfg.JWTSecret = value
							case "secret":
								cfg.Secret = value
							case "sync-keys":
								parsed, err := client.ParseSyncKeys(value)
								if err != nil {
									return err
								}
								cfg.SyncKeys = parsed
							default:
								return fmt.Errorf("unknown config key: %s", key)
							}

							if err := client.SaveConfig(cfg); err != nil {
								return fmt.Errorf("Failed to save config: %v", err)
							}

							fmt.Printf("✓ Set %s\n", key)
							return nil
						},
					},
					{
						Name:  "get",
						Usage: "Get config value",
						Action: func(c *cli.Context) error {
							if c.NArg() < 1 {
								return fmt.Errorf("key argument required")
							}
							key := c.Args().Get(0)

							cfg, err := client.LoadConfigFile()
							if err != nil {
								return fmt.Errorf("Failed to load config: %v", err)
							}

							switch key {
							case "endpoint":
								fmt.Println(cfg.Endpoint)
							case "token":
								fmt.Println(cfg.Token)
							case "jwt_secret":
								fmt.Println(cfg.JWTSecret)
							case "secret":
								fmt.Println(cfg.Secret)
							case "sync-keys":
								data, _ := json.Marshal(cfg.SyncKeys)
								fmt.Println(string(data))
							default:
								return fmt.Errorf("unknown config key: %s", key)
							}
							return nil
						},
					},
					{
						Name:  "show",
						Usage: "Show all configuration",
						Action: func(c *cli.Context) error {
							cfg, err := client.LoadConfigFile()
							if err != nil {
								return fmt.Errorf("Failed to load config: %v", err)
							}

							data, _ := json.MarshalIndent(cfg, "", "  ")
							fmt.Println(string(data))
							return nil
						},
					},
					{
						Name:  "clear",
						Usage: "Clear config value",
						Action: func(c *cli.Context) error {
							if c.NArg() < 1 {
								return fmt.Errorf("key argument required")
							}
							key := c.Args().Get(0)

							cfg, err := client.LoadConfigFile()
							if err != nil {
								return fmt.Errorf("Failed to load config: %v", err)
							}

							switch key {
							case "endpoint":
								cfg.Endpoint = ""
							case "token":
								cfg.Token = ""
							case "jwt_secret":
								cfg.JWTSecret = ""
							case "secret":
								cfg.Secret = ""
							case "sync-keys":
								cfg.SyncKeys = nil
							default:
								return fmt.Errorf("unknown config key: %s", key)
							}

							if err := client.SaveConfig(cfg); err != nil {
								return fmt.Errorf("Failed to save config: %v", err)
							}

							fmt.Printf("✓ Cleared %s\n", key)
							return nil
						},
					},
				},
			},
			{
				Name:  "get",
				Usage: "Get secret value from vault",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "key",
						Aliases: []string{"k"},
						Usage:   "Key to get (required)",
					},
					&cli.StringFlag{
						Name:    "token",
						Aliases: []string{"t"},
						Usage:   "Auth token",
					},
					&cli.StringFlag{
						Name:    "secret",
						Aliases: []string{"s"},
						Usage:   "Secret for client-side AES-256 decryption",
					},
				},
				Action: func(c *cli.Context) error {
					key := c.String("key")
					if key == "" {
						return fmt.Errorf("key required: use -k/--key")
					}
					if c.NArg() > 0 {
						return fmt.Errorf("unexpected argument(s): %v (use -k/--key to specify the key)", c.Args().Slice())
					}

					cl := client.NewWithToken(getEndpoint(c), c.String("token"))

					result, err := cl.VaultGet(key)
					if err != nil {
						return fmt.Errorf("Request failed: %v", err)
					}

					if result.Value == "" {
						fmt.Println("(not set)")
						return nil
					}

					value, err := decryptIfNeeded(result.Value, client.ResolveSecret(c.String("secret")))
					if err != nil {
						return err
					}

					fmt.Println(value)
					return nil
				},
			},
			{
				Name:  "set",
				Usage: "Set secret value in vault",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "key",
						Aliases: []string{"k"},
						Usage:   "Key to set (required)",
					},
					&cli.StringFlag{
						Name:    "value",
						Aliases: []string{"v"},
						Usage:   "Value to set (required)",
					},
					&cli.StringFlag{
						Name:    "token",
						Aliases: []string{"t"},
						Usage:   "Auth token",
					},
					&cli.StringFlag{
						Name:    "secret",
						Aliases: []string{"s"},
						Usage:   "Secret for client-side AES-256 encryption",
					},
				},
				Action: func(c *cli.Context) error {
					key := c.String("key")
					if key == "" {
						return fmt.Errorf("key required: use -k/--key")
					}
					value := c.String("value")
					if value == "" {
						return fmt.Errorf("value required: use -v/--value")
					}
					if c.NArg() > 0 {
						return fmt.Errorf("unexpected argument(s): %v (use -k/--key and -v/--value to specify the key and value)", c.Args().Slice())
					}

					value, err := encryptIfSecret(value, client.ResolveSecret(c.String("secret")))
					if err != nil {
						return err
					}

					cl := client.NewWithToken(getEndpoint(c), c.String("token"))

					if err := cl.VaultSet(key, value); err != nil {
						return fmt.Errorf("Request failed: %v", err)
					}

					fmt.Printf("✓ Set %s\n", key)
					return nil
				},
			},
			{
				Name:  "attr",
				Usage: "Add, replace, or remove attributes inside a JSON-object vault value",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "key",
						Aliases: []string{"k"},
						Usage:   "Vault key holding the JSON value (required)",
					},
					&cli.StringSliceFlag{
						Name:  "set",
						Usage: "Set path=value (repeatable), e.g. --set user.active=true",
					},
					&cli.StringSliceFlag{
						Name:  "remove",
						Usage: "Remove path (repeatable), e.g. --remove user.oldField",
					},
					&cli.StringFlag{
						Name:    "token",
						Aliases: []string{"t"},
						Usage:   "Auth token",
					},
					&cli.StringFlag{
						Name:    "secret",
						Aliases: []string{"s"},
						Usage:   "Secret for client-side AES-256 encryption/decryption",
					},
				},
				Action: func(c *cli.Context) error {
					key := c.String("key")
					if key == "" {
						return fmt.Errorf("key required: use -k/--key")
					}
					sets := c.StringSlice("set")
					removes := c.StringSlice("remove")
					if len(sets) == 0 && len(removes) == 0 {
						return fmt.Errorf("at least one --set or --remove required")
					}
					if c.NArg() > 0 {
						return fmt.Errorf("unexpected argument(s): %v (use --set/--remove to specify edits)", c.Args().Slice())
					}

					secret := client.ResolveSecret(c.String("secret"))
					cl := client.NewWithToken(getEndpoint(c), c.String("token"))

					result, err := cl.VaultGet(key)
					if err != nil {
						return fmt.Errorf("Request failed: %v", err)
					}

					var doc interface{}
					if result.Value == "" {
						doc = map[string]interface{}{}
					} else {
						plain, err := decryptIfNeeded(result.Value, secret)
						if err != nil {
							return err
						}
						if err := json.Unmarshal([]byte(plain), &doc); err != nil {
							return fmt.Errorf("value at %q is not valid JSON: %v", key, err)
						}
					}

					// Removes first, then sets — a fixed, documented order since
					// urfave/cli doesn't preserve relative order between two
					// different repeatable flags.
					for _, path := range removes {
						if path == "" {
							return fmt.Errorf("empty --remove path")
						}
						doc, err = client.RemoveAttrPath(doc, client.ParseAttrPath(path))
						if err != nil {
							return fmt.Errorf("--remove %q: %v", path, err)
						}
					}
					for _, kv := range sets {
						path, value, ok := strings.Cut(kv, "=")
						if !ok || path == "" {
							return fmt.Errorf("invalid --set %q: expected path=value", kv)
						}
						doc, err = client.SetAttrPath(doc, client.ParseAttrPath(path), client.ParseAttrValue(value))
						if err != nil {
							return fmt.Errorf("--set %q: %v", kv, err)
						}
					}

					encoded, err := json.Marshal(doc)
					if err != nil {
						return fmt.Errorf("failed to encode result: %v", err)
					}

					newValue, err := encryptIfSecret(string(encoded), secret)
					if err != nil {
						return err
					}

					if err := cl.VaultSet(key, newValue); err != nil {
						return fmt.Errorf("Request failed: %v", err)
					}

					fmt.Printf("✓ Updated %s\n", key)
					return nil
				},
			},
			{
				Name:   "fetch",
				Usage:  "Fetch configured vault keys and write YAML/.env/Ansible-facts files (invoked by the systemd service, not meant to be run interactively)",
				Action: runFetch,
			},
			{
				Name:  "install-service",
				Usage: "Install and enable the systemd service that runs `fetch` at boot (must be run as root)",
				Action: func(c *cli.Context) error {
					return service.Install()
				},
			},
			{
				Name:  "status",
				Usage: "Check system status",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "token",
						Aliases: []string{"t"},
						Usage:   "Auth token",
					},
				},
				Action: func(c *cli.Context) error {
					cl := client.NewWithToken(getEndpoint(c), c.String("token"))

					result, err := cl.SystemAlive()
					if err != nil {
						return fmt.Errorf("Request failed: %v", err)
					}

					fmt.Printf("✓ System alive at %s\n", result.Timestamp)
					return nil
				},
			},
			{
				Name:  "token",
				Usage: "Token operations",
				Subcommands: []*cli.Command{
					{
						Name:  "local",
						Usage: "Generate token locally (requires JWT_SECRET)",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:     "jwt_secret",
								Aliases:  []string{"j"},
								Usage:    "JWT secret for signing",
							},
							&cli.StringFlag{
								Name:    "permissions",
								Aliases: []string{"p"},
								Usage:   "Permissions as JSON",
							},
							&cli.StringFlag{
								Name:    "expires",
								Aliases: []string{"e"},
								Usage:   "Token expiration in seconds",
							},
							&cli.BoolFlag{
								Name:    "save",
								Aliases: []string{"S"},
								Usage:   "Save token to ~/.config/kilovault/config.json",
							},
							&cli.StringFlag{
								Name:    "user",
								Aliases: []string{"u"},
								Usage:   "User ID (subject) for the token (required)",
							},
						},
						Action: func(c *cli.Context) error {
							userID := c.String("user")
							if userID == "" {
								return fmt.Errorf("user id required: use -u/--user")
							}
							if c.NArg() > 0 {
								return fmt.Errorf("unexpected argument(s): %v (use -u/--user to specify the user id)", c.Args().Slice())
							}

							jwtSecret := c.String("jwt_secret")
							if jwtSecret == "" {
								jwtSecret = client.ResolveJWTSecret("")
							}
							if jwtSecret == "" {
								return fmt.Errorf("JWT_SECRET required (set via --jwt-secret, JWT_SECRET env, or config)")
							}

							var permissions map[string]bool
							if permStr := c.String("permissions"); permStr != "" {
								if err := json.Unmarshal([]byte(permStr), &permissions); err != nil {
									return fmt.Errorf("invalid permissions JSON: %v", err)
								}
							}

							var expiresIn *int
							if expStr := c.String("expires"); expStr != "" {
								exp, err := strconv.Atoi(expStr)
								if err != nil {
									return fmt.Errorf("invalid expires value: %v", err)
								}
								expiresIn = &exp
							}

							token, err := client.GenerateToken(userID, permissions, expiresIn, jwtSecret)
							if err != nil {
								return fmt.Errorf("Failed to generate token: %v", err)
							}

							fmt.Println(token)

							if c.Bool("save") {
								cfg, err := client.LoadConfigFile()
								if err != nil {
									return fmt.Errorf("Failed to load config: %v", err)
								}
								cfg.Token = token
								if err := client.SaveConfig(cfg); err != nil {
									return fmt.Errorf("Failed to save token to config: %v", err)
								}
								fmt.Fprintf(os.Stderr, "✓ Token saved to ~/.config/kilovault/config.json\n")
							}

							return nil
						},
					},
				},
			},
			{
				Name:  "admin",
				Usage: "Admin operations",
				Subcommands: []*cli.Command{
					{
						Name:  "list",
						Usage: "List all keys (optionally for specific user)",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:    "token",
								Aliases: []string{"t"},
								Usage:   "Admin token",
							},
							&cli.StringFlag{
								Name:    "user",
								Aliases: []string{"u"},
								Usage:   "List keys for this user only (optional)",
							},
						},
						Action: func(c *cli.Context) error {
							if c.NArg() > 0 {
								return fmt.Errorf("unexpected argument(s): %v (use -u/--user to specify a user)", c.Args().Slice())
							}

							var userID *string
							if id := c.String("user"); id != "" {
								userID = &id
							}

							cl := client.NewWithToken(getEndpoint(c), c.String("token"))

							result, err := cl.VaultAdminList(userID)
							if err != nil {
								return fmt.Errorf("Request failed: %v", err)
							}

							if len(result.Keys) == 0 {
								fmt.Println("{}")
								return nil
							}

							if userID != nil {
								keys := make([]string, 0)
								for _, k := range result.Keys {
									keys = append(keys, k.Key)
								}
								output := map[string][]string{*userID: keys}
								data, _ := json.MarshalIndent(output, "", "  ")
								fmt.Println(string(data))
							} else {
								grouped := make(map[string][]string)
								for _, k := range result.Keys {
									grouped[k.UserID] = append(grouped[k.UserID], k.Key)
								}
								data, _ := json.MarshalIndent(grouped, "", "  ")
								fmt.Println(string(data))
							}
							return nil
						},
					},
					{
						Name:  "get",
						Usage: "Get key for any user",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:    "user",
								Aliases: []string{"u"},
								Usage:   "User ID (required)",
							},
							&cli.StringFlag{
								Name:    "key",
								Aliases: []string{"k"},
								Usage:   "Key to get (required)",
							},
							&cli.StringFlag{
								Name:    "token",
								Aliases: []string{"t"},
								Usage:   "Admin token",
							},
							&cli.StringFlag{
								Name:    "secret",
								Aliases: []string{"s"},
								Usage:   "Secret for client-side AES-256 decryption",
							},
						},
						Action: func(c *cli.Context) error {
							userID := c.String("user")
							if userID == "" {
								return fmt.Errorf("user id required: use -u/--user")
							}
							key := c.String("key")
							if key == "" {
								return fmt.Errorf("key required: use -k/--key")
							}
							if c.NArg() > 0 {
								return fmt.Errorf("unexpected argument(s): %v (use -u/--user and -k/--key to specify the user and key)", c.Args().Slice())
							}

							cl := client.NewWithToken(getEndpoint(c), c.String("token"))

							result, err := cl.VaultAdminGet(userID, key)
							if err != nil {
								return fmt.Errorf("Request failed: %v", err)
							}

							if result.Value == "" {
								fmt.Println("(not set)")
								return nil
							}

							value, err := decryptIfNeeded(result.Value, client.ResolveSecret(c.String("secret")))
							if err != nil {
								return err
							}

							fmt.Println(value)
							return nil
						},
					},
					{
						Name:  "set",
						Usage: "Set key for any user",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:    "user",
								Aliases: []string{"u"},
								Usage:   "User ID (required)",
							},
							&cli.StringFlag{
								Name:    "key",
								Aliases: []string{"k"},
								Usage:   "Key to set (required)",
							},
							&cli.StringFlag{
								Name:    "value",
								Aliases: []string{"v"},
								Usage:   "Value to set (required)",
							},
							&cli.StringFlag{
								Name:    "token",
								Aliases: []string{"t"},
								Usage:   "Admin token",
							},
							&cli.StringFlag{
								Name:    "secret",
								Aliases: []string{"s"},
								Usage:   "Secret for client-side AES-256 encryption",
							},
						},
						Action: func(c *cli.Context) error {
							userID := c.String("user")
							if userID == "" {
								return fmt.Errorf("user id required: use -u/--user")
							}
							key := c.String("key")
							if key == "" {
								return fmt.Errorf("key required: use -k/--key")
							}
							value := c.String("value")
							if value == "" {
								return fmt.Errorf("value required: use -v/--value")
							}
							if c.NArg() > 0 {
								return fmt.Errorf("unexpected argument(s): %v (use -u/--user, -k/--key and -v/--value to specify the user, key and value)", c.Args().Slice())
							}

							value, err := encryptIfSecret(value, client.ResolveSecret(c.String("secret")))
							if err != nil {
								return err
							}

							cl := client.NewWithToken(getEndpoint(c), c.String("token"))

							if err := cl.VaultAdminSet(userID, key, value); err != nil {
								return fmt.Errorf("Request failed: %v", err)
							}

							fmt.Printf("✓ Set %s for %s\n", key, userID)
							return nil
						},
					},
					{
						Name:  "delete",
						Usage: "Delete key for any user",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:    "user",
								Aliases: []string{"u"},
								Usage:   "User ID (required)",
							},
							&cli.StringFlag{
								Name:    "key",
								Aliases: []string{"k"},
								Usage:   "Key to delete (required)",
							},
							&cli.StringFlag{
								Name:    "token",
								Aliases: []string{"t"},
								Usage:   "Admin token",
							},
						},
						Action: func(c *cli.Context) error {
							userID := c.String("user")
							if userID == "" {
								return fmt.Errorf("user id required: use -u/--user")
							}
							key := c.String("key")
							if key == "" {
								return fmt.Errorf("key required: use -k/--key")
							}
							if c.NArg() > 0 {
								return fmt.Errorf("unexpected argument(s): %v (use -u/--user and -k/--key to specify the user and key)", c.Args().Slice())
							}

							cl := client.NewWithToken(getEndpoint(c), c.String("token"))

							result, err := cl.VaultAdminDelete(userID, key)
							if err != nil {
								return fmt.Errorf("Request failed: %v", err)
							}

							if result.Deleted {
								fmt.Printf("✓ Deleted %s for %s\n", key, userID)
							} else {
								fmt.Println("(not found)")
							}
							return nil
						},
					},
					{
						Name:  "history",
						Usage: "Get vault history (optionally for specific user)",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:    "token",
								Aliases: []string{"t"},
								Usage:   "Admin token",
							},
							&cli.StringFlag{
								Name:    "user",
								Aliases: []string{"u"},
								Usage:   "Show history for this user only (optional)",
							},
						},
						Action: func(c *cli.Context) error {
							if c.NArg() > 0 {
								return fmt.Errorf("unexpected argument(s): %v (use -u/--user to specify a user)", c.Args().Slice())
							}

							var userID *string
							if id := c.String("user"); id != "" {
								userID = &id
							}

							cl := client.NewWithToken(getEndpoint(c), c.String("token"))

							result, err := cl.HistoryGet(userID)
							if err != nil {
								return fmt.Errorf("Request failed: %v", err)
							}

							if len(result.History) == 0 {
								fmt.Println("No history")
								return nil
							}

							w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
							fmt.Fprintln(w, strings.Join([]string{"ID", "Timestamp", "UserID", "Key", "Action"}, "\t"))
							for _, entry := range result.History {
								fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
									entry.ID, entry.Timestamp, entry.UserID, entry.Key, entry.Action)
							}
							return w.Flush()
						},
					},
					{
						Name:  "cleanup",
						Usage: "Cleanup old history records",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:    "token",
								Aliases: []string{"t"},
								Usage:   "Admin token",
							},
						},
						Action: func(c *cli.Context) error {
							cl := client.NewWithToken(getEndpoint(c), c.String("token"))

							result, err := cl.HistoryCleanup()
							if err != nil {
								return fmt.Errorf("Request failed: %v", err)
							}

							fmt.Printf("✓ Cleaned up %d records\n", result.Count)
							return nil
						},
					},
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
