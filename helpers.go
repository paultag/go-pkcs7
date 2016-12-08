package pkcs7

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
)

var (
	Unsupported = fmt.Errorf("Algorithm not supported")
)

func encryptRSA(rand io.Reader, cert x509.Certificate, plaintext []byte, opts EncryptorOpts) ([]byte, error) {
	rsaPublicKey := cert.PublicKey.(*rsa.PublicKey)
	return rsa.EncryptPKCS1v15(rand, rsaPublicKey, plaintext)
}

// Encrypt the input plaintext to the x509 Certificate's Private Key
func Encrypt(rand io.Reader, cert x509.Certificate, plaintext []byte, opts EncryptorOpts) ([]byte, error) {
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		return encryptRSA(rand, cert, plaintext, opts)
	default:
		return nil, Unsupported
	}
}

func verifyRSA(rand io.Reader, cert x509.Certificate, input, signature []byte, opts VerifierOpts) (bool, error) {
	rsaPublicKey := cert.PublicKey.(*rsa.PublicKey)
	err := rsa.VerifyPKCS1v15(
		rsaPublicKey,
		opts.HashFunc(),
		input,
		signature,
	)
	return err == nil, err
}

func Verify(rand io.Reader, cert x509.Certificate, input, signature []byte, opts VerifierOpts) (bool, error) {
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		return verifyRSA(rand, cert, input, signature, opts)
	default:
		return false, Unsupported
	}
}
