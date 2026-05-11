package credential

import (
	"errors"
	"fmt"
	"os"

	"github.com/deviceinsight/kafkactl/v5/internal/output"
	"github.com/zalando/go-keyring"
)

const KeyringService = "kafkactl"

type pendingWrite struct {
	key, value string
}

type KeyringResolver struct {
	// test hooks; nil means use the real keyring functions
	keyringGetFn func(service, key string) (string, error)
	keyringSetFn func(service, key, value string) error
	keyringDelFn func(service, key string) error
	delegate     Resolver
	clearMode    bool
	pending      []pendingWrite
}

func NewKeyringResolver(clearMode bool) Resolver {
	return &KeyringResolver{
		delegate:  NewPromptCredentialResolver(),
		clearMode: clearMode,
	}
}

func (r *KeyringResolver) ResolvePassword(fieldName, promptLabel string) (string, error) {
	if r.clearMode {
		delFn := r.keyringDelFn
		if delFn == nil {
			delFn = keyring.Delete
		}
		if err := delFn(KeyringService, fieldName); err != nil && !errors.Is(err, keyring.ErrNotFound) {
			output.Warnf("failed to clear keyring entry %s: %v", fieldName, err)
		} else if err == nil {
			output.Debugf("cleared keyring entry: %s", fieldName)
		}
	} else {
		getFn := r.keyringGetFn
		if getFn == nil {
			getFn = keyring.Get
		}
		value, err := getFn(KeyringService, fieldName)
		if err == nil {
			output.Debugf("password found in keyring: %s", fieldName)
			return value, nil
		}
		if !errors.Is(err, keyring.ErrNotFound) {
			return "", fmt.Errorf("failed to get keyring entry %s: %w", fieldName, err)
		}
		output.Debugf("no password stored in keyring for %s", fieldName)
	}

	value, err := r.delegate.ResolvePassword(fieldName, promptLabel)
	if err != nil {
		return "", err
	}

	if value != "" {
		r.pending = append(r.pending, pendingWrite{key: fieldName, value: value})
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

func (r *KeyringResolver) Flush() error {
	setFn := r.keyringSetFn
	if setFn == nil {
		setFn = keyring.Set
	}
	for _, pw := range r.pending {
		if err := setFn(KeyringService, pw.key, pw.value); err != nil {
			return fmt.Errorf("failed to save to keyring: %w", err)
		}
		output.Debugf("saved keyring entry: %s", pw.key)
	}
	r.pending = nil
	return nil
}
