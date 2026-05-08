package credential

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/youmark/pkcs8"
)

func TestIsEncryptedPEM_Unencrypted(t *testing.T) {
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: []byte("fake-key-data"),
	})
	if IsEncryptedPEM(pemBytes) {
		t.Error("expected unencrypted PEM to return false")
	}
}

func TestIsEncryptedPEM_LegacyPKCS1(t *testing.T) {
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: map[string]string{"DEK-Info": "AES-256-CBC,aabbccdd"},
		Bytes:   []byte("fake-encrypted-data"),
	})
	if IsEncryptedPEM(pemBytes) {
		t.Error("expected legacy PKCS#1 PEM to return false (not supported)")
	}
}

func TestIsEncryptedPEM_EncryptedPKCS8(t *testing.T) {
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: []byte("fake-encrypted-data"),
	})
	if !IsEncryptedPEM(pemBytes) {
		t.Error("expected PKCS#8 encrypted PEM to return true")
	}
}

func TestIsEncryptedPEM_NilInput(t *testing.T) {
	if IsEncryptedPEM([]byte("not a pem file")) {
		t.Error("expected non-PEM data to return false")
	}
}

func TestIsLegacyEncryptedPEM_WithDEKInfo(t *testing.T) {
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: map[string]string{"DEK-Info": "AES-256-CBC,aabbccdd"},
		Bytes:   []byte("fake-encrypted-data"),
	})
	if !IsLegacyEncryptedPEM(pemBytes) {
		t.Error("expected legacy PKCS#1 PEM to return true")
	}
}

func TestIsLegacyEncryptedPEM_PKCS8(t *testing.T) {
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: []byte("fake-encrypted-data"),
	})
	if IsLegacyEncryptedPEM(pemBytes) {
		t.Error("expected PKCS#8 encrypted PEM to return false")
	}
}

func encryptedPKCS8PEM(t *testing.T, password string) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := pkcs8.MarshalPrivateKey(key, []byte(password), nil)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: der})
}

func TestDecryptPEMKey_PKCS8_RoundTrip(t *testing.T) {
	encPEM := encryptedPKCS8PEM(t, "testpass")

	decrypted, err := DecryptPEMKey(encPEM, "testpass")
	if err != nil {
		t.Fatalf("failed to decrypt: %v", err)
	}

	block, _ := pem.Decode(decrypted)
	if block == nil {
		t.Fatal("failed to decode decrypted PEM")
	}
	if _, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		t.Fatalf("decrypted key is not valid PKCS#8: %v", err)
	}
}

func TestDecryptPEMKey_LegacyPKCS1_ReturnsError(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyDER := x509.MarshalPKCS1PrivateKey(key)
	//nolint:staticcheck
	encBlock, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", keyDER, []byte("testpass"), x509.PEMCipherAES256)
	if err != nil {
		t.Fatal(err)
	}
	encPEM := pem.EncodeToMemory(encBlock)

	_, err = DecryptPEMKey(encPEM, "testpass")
	if err == nil {
		t.Fatal("expected error for legacy PKCS#1 key")
	}
	if !strings.Contains(err.Error(), "legacy PEM encryption") {
		t.Errorf("expected error to mention legacy PEM encryption, got: %v", err)
	}
}

func TestDecryptPEMKey_WrongPassphrase_ReturnsError(t *testing.T) {
	encPEM := encryptedPKCS8PEM(t, "correct")

	if _, err := DecryptPEMKey(encPEM, "wrong"); err == nil {
		t.Fatal("expected error with wrong passphrase")
	}
}

func TestDecryptPEMKey_NotPEM_ReturnsError(t *testing.T) {
	if _, err := DecryptPEMKey([]byte("not a pem block"), "pass"); err == nil {
		t.Fatal("expected error for non-PEM input")
	}
}
