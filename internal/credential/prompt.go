package credential

import (
	"fmt"
	"io"
	"os"
	"os/signal"

	"github.com/pkg/errors"
	"golang.org/x/term"
)

// PromptCredentialResolver resolves credentials by prompting the user for a password.
type PromptCredentialResolver struct {
	// promptFn is used for testing; nil means use the real terminal prompt.
	promptFn func(label string) (string, error)
}

func NewPromptCredentialResolver() Resolver {
	return &PromptCredentialResolver{}
}

func (r *PromptCredentialResolver) ResolvePassword(_, promptLabel string) (string, error) {
	fn := r.promptFn
	if fn == nil {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return "", errors.Errorf("%s is not configured and no terminal available for prompting", promptLabel)
		}
		fn = readPassword
	}
	value, err := fn(promptLabel)
	if err != nil {
		return "", errors.Wrap(err, "failed to read credential")
	}
	return value, nil
}

func (r *PromptCredentialResolver) ResolveTLSPassphrase(certKeyPath, fieldName, promptLabel string) (string, error) {

	if certKeyPath == "" {
		return "", nil
	}
	keyPEM, err := os.ReadFile(certKeyPath)
	if err != nil {
		return "", fmt.Errorf("unable to read %s: %w", certKeyPath, err)
	}
	if !IsEncryptedPEM(keyPEM) {
		return "", nil
	}
	return r.ResolvePassword(fieldName, promptLabel)
}

func (r *PromptCredentialResolver) Flush() error {
	return nil
}

func readPassword(label string) (string, error) {
	_, _ = fmt.Fprintf(os.Stderr, "%s: ", label)

	fd := int(os.Stdin.Fd())
	oldState, err := term.GetState(fd)
	if err != nil {
		return "", errors.Wrap(err, "failed to get terminal state")
	}

	type result struct {
		password string
		err      error
	}
	resultCh := make(chan result, 1)

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	defer signal.Stop(signalChan)

	go func() {
		pw, err := term.ReadPassword(fd)
		resultCh <- result{string(pw), err}
	}()

	select {
	case r := <-resultCh:
		_, _ = fmt.Fprintln(os.Stderr)
		if r.err == io.EOF {
			return "", errors.New("password entry aborted")
		}
		return r.password, r.err
	case <-signalChan:
		_ = term.Restore(fd, oldState)
		_, _ = fmt.Fprintln(os.Stderr)
		return "", errors.New("password entry aborted")
	}
}
