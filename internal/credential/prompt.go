package credential

import (
	"fmt"
	"os"

	"github.com/pkg/errors"
	"golang.org/x/term"
)

// PromptCredentialResolver resolves credentials by prompting the user for a password.
type PromptCredentialResolver struct {
	// promptFn is used for testing; nil means use the real terminal prompt.
	promptFn func(label string) (string, error)
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

func NewPromptCredentialResolver() Resolver {
	return &PromptCredentialResolver{}
}

func readPassword(label string) (string, error) {
	fmt.Fprintf(os.Stderr, "%s: ", label)
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return string(password), nil
}
