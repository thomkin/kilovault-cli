package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/thomkin/kilovault-cli/pkg/client"
	"github.com/urfave/cli/v2"
)

func getEndpoint(c *cli.Context) string {
	if ep := c.String("endpoint"); ep != "" {
		return ep
	}
	return ""
}

func main() {
	app := &cli.App{
		Name:    "kilovault-cli",
		Usage:   "CLI for kilovault secret management",
		Version: "0.0.1",
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
						Name:    "token",
						Aliases: []string{"t"},
						Usage:   "Auth token",
					},
				},
				Action: func(c *cli.Context) error {
					if c.NArg() < 1 {
						return fmt.Errorf("key argument required")
					}
					key := c.Args().Get(0)

					cl := client.NewWithToken(getEndpoint(c), c.String("token"))

					result, err := cl.VaultGet(key)
					if err != nil {
						return fmt.Errorf("Request failed: %v", err)
					}

					if result.Value != "" {
						fmt.Println(result.Value)
					} else {
						fmt.Println("(not set)")
					}
					return nil
				},
			},
			{
				Name:  "set",
				Usage: "Set secret value in vault",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "token",
						Aliases: []string{"t"},
						Usage:   "Auth token",
					},
				},
				Action: func(c *cli.Context) error {
					if c.NArg() < 2 {
						return fmt.Errorf("key and value arguments required")
					}
					key := c.Args().Get(0)
					value := c.Args().Get(1)

					cl := client.NewWithToken(getEndpoint(c), c.String("token"))

					if err := cl.VaultSet(key, value); err != nil {
						return fmt.Errorf("Request failed: %v", err)
					}

					fmt.Printf("✓ Set %s\n", key)
					return nil
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
						},
						Action: func(c *cli.Context) error {
							var userID *string
							if c.NArg() > 0 {
								id := c.Args().Get(0)
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
								Name:    "token",
								Aliases: []string{"t"},
								Usage:   "Admin token",
							},
						},
						Action: func(c *cli.Context) error {
							if c.NArg() < 2 {
								return fmt.Errorf("userId and key arguments required")
							}
							userID := c.Args().Get(0)
							key := c.Args().Get(1)

							cl := client.NewWithToken(getEndpoint(c), c.String("token"))

							result, err := cl.VaultAdminGet(userID, key)
							if err != nil {
								return fmt.Errorf("Request failed: %v", err)
							}

							if result.Value != "" {
								fmt.Println(result.Value)
							} else {
								fmt.Println("(not set)")
							}
							return nil
						},
					},
					{
						Name:  "set",
						Usage: "Set key for any user",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:    "token",
								Aliases: []string{"t"},
								Usage:   "Admin token",
							},
						},
						Action: func(c *cli.Context) error {
							if c.NArg() < 3 {
								return fmt.Errorf("userId, key and value arguments required")
							}
							userID := c.Args().Get(0)
							key := c.Args().Get(1)
							value := c.Args().Get(2)

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
								Name:    "token",
								Aliases: []string{"t"},
								Usage:   "Admin token",
							},
						},
						Action: func(c *cli.Context) error {
							if c.NArg() < 2 {
								return fmt.Errorf("userId and key arguments required")
							}
							userID := c.Args().Get(0)
							key := c.Args().Get(1)

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
						},
						Action: func(c *cli.Context) error {
							var userID *string
							if c.NArg() > 0 {
								id := c.Args().Get(0)
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

							headers := []string{"ID", "Timestamp", "UserID", "Key", "Action"}
							fmt.Println(strings.Join(headers, "\t"))
							for _, entry := range result.History {
								fmt.Printf("%s\t%s\t%s\t%s\t%s\n",
									entry.ID, entry.Timestamp, entry.UserID, entry.Key, entry.Action)
							}
							return nil
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
