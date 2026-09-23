package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/thomkin/kilovault-cli/pkg/securestore"
	"golang.org/x/term"
)

// masterPasswordEnv lets scripts supply the master password without a
// prompt. It's an env var, not a flag, so it never appears in argv or
// shell history.
const masterPasswordEnv = "KILOVAULT_MASTER_PASSWORD"

// prompter reads interactive input. On a terminal, secrets are read with
// echo off. When stdin is not a terminal (piped input, scripts, tests),
// each prompt consumes one line of stdin instead, in the order prompts
// are issued.
type prompter struct {
	tty bool
	in  *bufio.Reader
}

func newPrompter() *prompter {
	return &prompter{
		tty: term.IsTerminal(int(os.Stdin.Fd())),
		in:  bufio.NewReader(os.Stdin),
	}
}

// secret reads a value without echoing it. The result must not be empty.
func (p *prompter) secret(label string) ([]byte, error) {
	if p.tty {
		fmt.Fprintf(os.Stderr, "%s: ", label)
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, err
		}
		if len(b) == 0 {
			return nil, fmt.Errorf("%s: no input", strings.ToLower(label))
		}
		return b, nil
	}
	line, err := p.readLine()
	if err == nil && len(line) == 0 {
		err = errors.New("empty line")
	}
	if err != nil {
		return nil, fmt.Errorf("%s: no input (stdin is not a terminal, expected one line per prompt): %v", strings.ToLower(label), err)
	}
	return line, nil
}

// text reads a visible line, returning def if the answer is empty.
func (p *prompter) text(label, def string) (string, error) {
	if p.tty {
		if def != "" {
			fmt.Fprintf(os.Stderr, "%s [%s]: ", label, def)
		} else {
			fmt.Fprintf(os.Stderr, "%s: ", label)
		}
	}
	line, err := p.readLine()
	if err != nil {
		return "", fmt.Errorf("%s: no input (stdin is not a terminal, expected one line per prompt): %v", strings.ToLower(label), err)
	}
	if s := strings.TrimSpace(string(line)); s != "" {
		return s, nil
	}
	return def, nil
}

func (p *prompter) readLine() ([]byte, error) {
	line, err := p.in.ReadBytes('\n')
	if err != nil && !(errors.Is(err, io.EOF) && len(line) > 0) {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("unexpected end of input")
		}
		return nil, err
	}
	return bytes.TrimRight(line, "\r\n"), nil
}

// masterPassword returns the master password from KILOVAULT_MASTER_PASSWORD
// or a prompt.
func (p *prompter) masterPassword() ([]byte, error) {
	if env := os.Getenv(masterPasswordEnv); env != "" {
		return []byte(env), nil
	}
	pw, err := p.secret("Master password")
	if err != nil && !p.tty {
		return nil, fmt.Errorf("%v — run `kilovault unlock` first, or set %s for scripts", err, masterPasswordEnv)
	}
	return pw, err
}

// newPassword asks for a new password twice and validates it against the
// master password policy.
func (p *prompter) newPassword(label string) ([]byte, error) {
	pw, err := p.secret(label)
	if err != nil {
		return nil, err
	}
	if err := securestore.ValidateMasterPassword(pw); err != nil {
		securestore.Wipe(pw)
		return nil, err
	}
	again, err := p.secret("Repeat " + strings.ToLower(label))
	if err != nil {
		securestore.Wipe(pw)
		return nil, err
	}
	defer securestore.Wipe(again)
	if !bytes.Equal(pw, again) {
		securestore.Wipe(pw)
		return nil, errors.New("passwords don't match")
	}
	return pw, nil
}

func isTerminal(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}

// optionalSecret is like secret but returns nil (no error) for an empty
// answer. Only used on a terminal; without one it returns nil at once so
// piped input isn't consumed by optional prompts.
func (p *prompter) optionalSecret(label string) ([]byte, error) {
	if !p.tty {
		return nil, nil
	}
	fmt.Fprintf(os.Stderr, "%s: ", label)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil || len(b) == 0 {
		return nil, err
	}
	return b, nil
}

// confirm asks a yes/no question; anything but y/yes (including no input)
// is a no.
func (p *prompter) confirm(question string) bool {
	answer, _ := p.text(question+" [y/N]", "")
	answer = strings.ToLower(answer)
	return answer == "y" || answer == "yes"
}
