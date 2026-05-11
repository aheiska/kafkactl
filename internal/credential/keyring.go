package credential

import (
	"errors"
	"fmt"
	"os"

	"github.com/deviceinsight/kafkactl/v5/internal/output"
	"github.com/zalando/go-keyring"
)

const KeyringService = "kafkactl"

type KeyringResolver struct {
	// keyringGetFn and keyringSetFn are used for testing; nil means use the real keyring.
	keyringGetFn func(service, key string) (string, error)
	keyringSetFn func(service, key, value string) error
	delegate     Resolver
}

func NewKeyringResolver() Resolver {
	return &KeyringResolver{
		delegate: NewPromptCredentialResolver(),
	}
}

func (r *KeyringResolver) ResolvePassword(fieldName, promptLabel string) (string, error) {

	getFn := r.keyringGetFn
	if getFn == nil {
		getFn = keyring.Get
	}

	value, err := getFn(KeyringService, fieldName)
	if err == nil && value != "" {
		output.Debugf("password found in keyring: %s", fieldName)
		return value, nil
	}
	if err != nil && errors.Is(err, keyring.ErrNotFound) {
		output.Debugf("no password stored in keyring for %s", fieldName)
	} else if err != nil {
		return "", fmt.Errorf("error looking up keyring service: %v", err)
	}

	value, err = r.delegate.ResolvePassword(fieldName, promptLabel)
	if err != nil {
		return "", err
	}

	if value != "" {
		setFn := r.keyringSetFn
		if setFn == nil {
			setFn = keyring.Set
		}
		if err := setFn(KeyringService, fieldName, value); err != nil {
			return "", fmt.Errorf("failed to save to keyring: %w", err)
		}
	}

	return value, nil
}

func (r *KeyringResolver) ResolveTLSPassphrase(certKeyPath, fieldName, promptLabel string) (string, error) {
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
