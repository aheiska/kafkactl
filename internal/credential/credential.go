package credential

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/pkg/errors"
	"github.com/youmark/pkcs8"
)

type Resolver interface {
	ResolvePassword(fieldName, promptLabel string) (string, error)
	ResolveTLSPassphrase(certKeyPath, fieldName, promptLabel string) (string, error)
	Flush() error
}

func IsEncryptedPEM(data []byte) bool {
	block, _ := pem.Decode(data)
	if block == nil {
		return false
	}
	return block.Type == "ENCRYPTED PRIVATE KEY"
}

func IsLegacyEncryptedPEM(data []byte) bool {
	block, _ := pem.Decode(data)
	if block == nil {
		return false
	}
	_, ok := block.Headers["DEK-Info"]
	return ok
}

func DecryptPEMKey(data []byte, passphrase string) ([]byte, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type == "ENCRYPTED PRIVATE KEY" {
		decryptedKey, err := pkcs8.ParsePKCS8PrivateKey(block.Bytes, []byte(passphrase))
		if err != nil {
			return nil, errors.Wrap(err, "failed to decrypt PKCS#8 private key")
		}
		derBytes, err := x509.MarshalPKCS8PrivateKey(decryptedKey)
		if err != nil {
			return nil, errors.Wrap(err, "failed to marshal decrypted key")
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: derBytes}), nil
	}

	if _, ok := block.Headers["DEK-Info"]; ok {
		return nil, fmt.Errorf("legacy PEM encryption (PKCS#1 with DEK-Info) is not supported.\n" +
			"Convert your key to PKCS#8 format:\n" +
			"    openssl pkcs8 -topk8 -v2 aes-256-cbc -in key.pem -out key.p8.pem")
	}

	return nil, fmt.Errorf("key is not encrypted (block type: %s)", block.Type)
}
