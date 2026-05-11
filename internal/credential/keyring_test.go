package credential

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"encoding/pem"

	"github.com/zalando/go-keyring"
)

func TestKeyringResolver_KeyringHit_ReturnsWithoutPrompt(t *testing.T) {
	resolver := &KeyringResolver{
		keyringGetFn: func(service, key string) (string, error) {
			if service == KeyringService && key == "sasl.password" {
				return "from-keyring", nil
			}
			return "", keyring.ErrNotFound
		},
		delegate: &PromptCredentialResolver{
			promptFn: func(_ string) (string, error) {
				t.Fatal("prompt should not be called on keyring hit")
				return "", nil
			},
		},
	}
	result, err := resolver.ResolvePassword("sasl.password", "SASL Password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "from-keyring" {
		t.Errorf("expected %q, got %q", "from-keyring", result)
	}
}

func TestKeyringResolver_KeyringMiss_PromptsAndStages(t *testing.T) {
	resolver := &KeyringResolver{
		keyringGetFn: func(_, _ string) (string, error) {
			return "", keyring.ErrNotFound
		},
		delegate: &PromptCredentialResolver{
			promptFn: func(_ string) (string, error) {
				return "prompted-pass", nil
			},
		},
	}
	result, err := resolver.ResolvePassword("sasl.password", "SASL Password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "prompted-pass" {
		t.Errorf("expected %q, got %q", "prompted-pass", result)
	}
	if len(resolver.pending) != 1 || resolver.pending[0].key != "sasl.password" || resolver.pending[0].value != "prompted-pass" {
		t.Errorf("expected pending write for sasl.password, got %v", resolver.pending)
	}
}

func TestKeyringResolver_Flush_SavesPendingWrites(t *testing.T) {
	var savedService, savedKey, savedValue string
	resolver := &KeyringResolver{
		keyringGetFn: func(_, _ string) (string, error) { return "", keyring.ErrNotFound },
		keyringSetFn: func(service, key, value string) error {
			savedService = service
			savedKey = key
			savedValue = value
			return nil
		},
		delegate: &PromptCredentialResolver{
			promptFn: func(_ string) (string, error) { return "prompted-pass", nil },
		},
	}
	if _, err := resolver.ResolvePassword("sasl.password", "SASL Password"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if savedKey != "" {
		t.Error("keyring should not be written during ResolvePassword")
	}
	if err := resolver.Flush(); err != nil {
		t.Fatalf("unexpected commit error: %v", err)
	}
	if savedService != KeyringService || savedKey != "sasl.password" || savedValue != "prompted-pass" {
		t.Errorf("keyring save mismatch: %s/%s=%s", savedService, savedKey, savedValue)
	}
}

func TestKeyringResolver_Flush_SetError_ReturnsError(t *testing.T) {
	resolver := &KeyringResolver{
		keyringGetFn: func(_, _ string) (string, error) { return "", keyring.ErrNotFound },
		keyringSetFn: func(_, _, _ string) error { return fmt.Errorf("keyring write failed") },
		delegate: &PromptCredentialResolver{
			promptFn: func(_ string) (string, error) { return "prompted-pass", nil },
		},
	}
	if _, err := resolver.ResolvePassword("sasl.password", "SASL Password"); err != nil {
		t.Fatalf("unexpected error during resolve: %v", err)
	}
	if err := resolver.Flush(); err == nil {
		t.Fatal("expected error from Flush when setFn fails")
	}
}

func TestKeyringResolver_KeyringError_ReturnsError(t *testing.T) {
	resolver := &KeyringResolver{
		keyringGetFn: func(_, _ string) (string, error) {
			return "", fmt.Errorf("keyring daemon unavailable")
		},
		delegate: &PromptCredentialResolver{
			promptFn: func(_ string) (string, error) {
				t.Fatal("prompt should not be called on keyring error")
				return "", nil
			},
		},
	}
	_, err := resolver.ResolvePassword("sasl.password", "SASL Password")
	if err == nil {
		t.Fatal("expected error on keyring lookup failure")
	}
}

func TestKeyringResolver_ClearMode_DeletesExistingAndPrompts(t *testing.T) {
	var deletedKey string
	resolver := &KeyringResolver{
		keyringDelFn: func(_, key string) error {
			deletedKey = key
			return nil
		},
		delegate: &PromptCredentialResolver{
			promptFn: func(_ string) (string, error) { return "new-pass", nil },
		},
		clearMode: true,
	}
	result, err := resolver.ResolvePassword("sasl.password", "SASL Password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "new-pass" {
		t.Errorf("expected %q, got %q", "new-pass", result)
	}
	if deletedKey != "sasl.password" {
		t.Errorf("expected keyring entry to be deleted, got deletedKey=%q", deletedKey)
	}
	if len(resolver.pending) != 1 || resolver.pending[0].value != "new-pass" {
		t.Errorf("expected new value staged, got %v", resolver.pending)
	}
}

func TestKeyringResolver_ResolveTLSPassphrase_EmptyPath_ReturnsEmpty(t *testing.T) {
	resolver := &KeyringResolver{
		keyringGetFn: func(_, _ string) (string, error) {
			t.Fatal("keyring should not be consulted for empty certKeyPath")
			return "", nil
		},
		delegate: &PromptCredentialResolver{},
	}
	result, err := resolver.ResolveTLSPassphrase("", "tls.certKeyPassphrase", "TLS Passphrase")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "" {
		t.Errorf("expected empty result, got %q", result)
	}
}

func TestKeyringResolver_ResolveTLSPassphrase_UnencryptedKey_ReturnsEmpty(t *testing.T) {
	path := writeKeyringTempPEM(t, "RSA PRIVATE KEY", nil)
	resolver := &KeyringResolver{
		keyringGetFn: func(_, _ string) (string, error) {
			t.Fatal("keyring should not be consulted for unencrypted key")
			return "", nil
		},
		delegate: &PromptCredentialResolver{},
	}
	result, err := resolver.ResolveTLSPassphrase(path, "tls.certKeyPassphrase", "TLS Passphrase")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "" {
		t.Errorf("expected empty result for unencrypted key, got %q", result)
	}
}

func TestKeyringResolver_ResolveTLSPassphrase_EncryptedKey_UsesKeyring(t *testing.T) {
	path := writeKeyringTempPEM(t, "ENCRYPTED PRIVATE KEY", nil)
	resolver := &KeyringResolver{
		keyringGetFn: func(service, key string) (string, error) {
			if service == KeyringService && key == "tls.certKeyPassphrase" {
				return "keyring-passphrase", nil
			}
			return "", keyring.ErrNotFound
		},
		delegate: &PromptCredentialResolver{
			promptFn: func(_ string) (string, error) {
				t.Fatal("prompt should not be called on keyring hit")
				return "", nil
			},
		},
	}
	result, err := resolver.ResolveTLSPassphrase(path, "tls.certKeyPassphrase", "TLS Passphrase")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "keyring-passphrase" {
		t.Errorf("expected %q, got %q", "keyring-passphrase", result)
	}
}

// helpers

func writeKeyringTempPEM(t *testing.T, pemType string, headers map[string]string) string {
	t.Helper()
	block := &pem.Block{Type: pemType, Headers: headers, Bytes: []byte("fake-key-data")}
	data := pem.EncodeToMemory(block)
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
