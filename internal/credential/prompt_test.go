package credential

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestPromptResolver_ReturnsPromptedValue(t *testing.T) {
	resolver := &PromptCredentialResolver{
		promptFn: func(_ string) (string, error) {
			return "prompted-pass", nil
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

func TestPromptResolver_NoTerminal_ReturnsError(t *testing.T) {
	// promptFn nil + no real terminal (CI) → error
	resolver := &PromptCredentialResolver{promptFn: nil}
	if _, err := resolver.ResolvePassword("sasl.password", "SASL Password"); err == nil {
		t.Fatal("expected error when no terminal available")
	}
}

func TestPromptResolver_PromptError_Propagates(t *testing.T) {
	resolver := &PromptCredentialResolver{
		promptFn: func(_ string) (string, error) {
			return "", os.ErrClosed
		},
	}
	if _, err := resolver.ResolvePassword("sasl.password", "SASL Password"); err == nil {
		t.Fatal("expected error to propagate from promptFn")
	}
}

func TestPromptResolver_ResolveTLSPassphrase_EmptyPath_ReturnsEmpty(t *testing.T) {
	resolver := &PromptCredentialResolver{
		promptFn: func(_ string) (string, error) {
			t.Fatal("prompt should not be called for empty certKeyPath")
			return "", nil
		},
	}
	result, err := resolver.ResolveTLSPassphrase("", "tls.certKeyPassphrase", "TLS Passphrase")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "" {
		t.Errorf("expected empty result for missing path, got %q", result)
	}
}

func TestPromptResolver_ResolveTLSPassphrase_UnencryptedKey_ReturnsEmpty(t *testing.T) {
	path := writeTempPEM(t, &unencryptedPEMBlock)
	resolver := &PromptCredentialResolver{
		promptFn: func(_ string) (string, error) {
			t.Fatal("prompt should not be called for unencrypted key")
			return "", nil
		},
	}
	result, err := resolver.ResolveTLSPassphrase(path, "tls.certKeyPassphrase", "TLS Passphrase")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "" {
		t.Errorf("expected empty result for unencrypted key, got %q", result)
	}
}

func TestPromptResolver_ResolveTLSPassphrase_EncryptedKey_Prompts(t *testing.T) {
	path := writeTempPEM(t, &encryptedPKCS8PEMBlock)
	resolver := &PromptCredentialResolver{
		promptFn: func(_ string) (string, error) {
			return "the-passphrase", nil
		},
	}
	result, err := resolver.ResolveTLSPassphrase(path, "tls.certKeyPassphrase", "TLS Passphrase")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "the-passphrase" {
		t.Errorf("expected %q, got %q", "the-passphrase", result)
	}
}

// helpers

var unencryptedPEMBlock = pemBlock{pemType: "RSA PRIVATE KEY", headers: nil, encrypted: false}
var encryptedPKCS8PEMBlock = pemBlock{pemType: "ENCRYPTED PRIVATE KEY", headers: nil, encrypted: true}

type pemBlock struct {
	pemType   string
	headers   map[string]string
	encrypted bool
}

func writeTempPEM(t *testing.T, b *pemBlock) string {
	t.Helper()
	block := &pem.Block{Type: b.pemType, Headers: b.headers, Bytes: []byte("fake-key-data")}
	data := pem.EncodeToMemory(block)
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
