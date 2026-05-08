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

func TestKeyringResolver_KeyringMiss_PromptsAndSaves(t *testing.T) {
	var savedService, savedKey, savedValue string

	resolver := &KeyringResolver{
		keyringGetFn: func(_, _ string) (string, error) {
			return "", keyring.ErrNotFound
		},
		keyringSetFn: func(service, key, value string) error {
			savedService = service
			savedKey = key
			savedValue = value
			return nil
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
	if savedService != KeyringService || savedKey != "sasl.password" || savedValue != "prompted-pass" {
		t.Errorf("keyring save mismatch: %s/%s=%s", savedService, savedKey, savedValue)
	}
}

func TestKeyringResolver_KeyringError_WarnsAndFallsBackToPrompt(t *testing.T) {
	resolver := &KeyringResolver{
		keyringGetFn: func(_, _ string) (string, error) {
			return "", fmt.Errorf("keyring daemon unavailable")
		},
		keyringSetFn: func(_, _, _ string) error { return nil },
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
}

func TestKeyringResolver_KeyringSetError_WarnsButReturnsValue(t *testing.T) {
	resolver := &KeyringResolver{
		keyringGetFn: func(_, _ string) (string, error) {
			return "", keyring.ErrNotFound
		},
		keyringSetFn: func(_, _, _ string) error {
			return fmt.Errorf("keyring write failed")
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
