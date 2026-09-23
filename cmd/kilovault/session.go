package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/thomkin/kilovault-cli/pkg/credentials"
	"github.com/thomkin/kilovault-cli/pkg/securestore"
	"github.com/thomkin/kilovault-cli/pkg/session"
	"github.com/urfave/cli/v2"
)

func unlockCommand() *cli.Command {
	return &cli.Command{
		Name:  "unlock",
		Usage: "Keep the credentials store unlocked for a while (kernel keyring, never on disk), so commands don't ask for the master password",
		Flags: []cli.Flag{
			&cli.DurationFlag{
				Name:  "timeout",
				Value: session.DefaultTTL,
				Usage: fmt.Sprintf("How long to stay unlocked (max %s)", session.MaxTTL),
			},
		},
		Action: runUnlock,
	}
}

func lockCommand() *cli.Command {
	return &cli.Command{
		Name:   "lock",
		Usage:  "End the unlock session immediately",
		Action: runLock,
	}
}

func runUnlock(c *cli.Context) error {
	ttl := c.Duration("timeout")
	if err := session.ValidateTTL(ttl); err != nil {
		return err
	}
	path, err := credentialsPath()
	if err != nil {
		return err
	}
	if !credentials.Exists(path) {
		return credentials.ErrNotInitialized
	}
	id, err := session.ID(path)
	if err != nil {
		return err
	}

	// Always ask for the password, even if a session is active: unlock
	// re-verifies and restarts the timer, like `sudo -v`.
	store, err := unlockWithPassword(newPrompter(), path)
	if err != nil {
		return err
	}
	defer store.Close()

	expires, err := session.Save(id, store.Key(), ttl)
	if err != nil {
		return err
	}
	fmt.Printf("✓ Unlocked until %s (%s)\n", expires.Format("15:04:05"), ttl)
	return nil
}

func runLock(c *cli.Context) error {
	path, err := credentials.DefaultPath()
	if err != nil {
		return err
	}
	id, err := session.ID(path)
	if err != nil {
		return err
	}
	cleared, err := session.Clear(id)
	if err != nil && !errors.Is(err, session.ErrUnavailable) {
		return err
	}
	if cleared {
		fmt.Println("✓ Locked")
	} else {
		fmt.Println("Not unlocked")
	}
	return nil
}

// describeSession reports the unlock state of the store at path, for
// `credentials list`.
func describeSession(path string) string {
	id, err := session.ID(path)
	if err != nil {
		return "unknown"
	}
	sess, err := session.Load(id)
	if err != nil {
		if errors.Is(err, session.ErrUnavailable) {
			return "unavailable (no kernel keyring)"
		}
		return "unknown (" + err.Error() + ")"
	}
	if sess == nil {
		return "locked"
	}
	securestore.Wipe(sess.Key)
	return fmt.Sprintf("unlocked until %s (%s left)", sess.Expires.Format("15:04:05"), time.Until(sess.Expires).Round(time.Second))
}
