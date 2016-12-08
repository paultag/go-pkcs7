// {{{ Copyright (c) Paul R. Tagliamonte <paultag@gmail.com>, 2016
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE. }}}

package pkcs7

import (
	"fmt"
	"io"

	"encoding/asn1"

	"crypto/x509"
	"crypto/x509/pkix"
)

func createRecipientsInfo(
	certs []x509.Certificate,
	algo pkix.AlgorithmIdentifier,
	encryptedKey []byte,
) []RecipientInfo {
	ret := []RecipientInfo{}
	for _, cert := range certs {
		ret = append(ret, createRecipientInfo(cert, algo, encryptedKey))
	}
	return ret
}

func createRecipientInfo(
	cert x509.Certificate,
	algo pkix.AlgorithmIdentifier,
	encryptedKey []byte,
) RecipientInfo {
	issuerAndSerial := IssuerAndSerialNumber{
		Serial: cert.SerialNumber,
		Issuer: asn1.RawValue{
			FullBytes: cert.RawIssuer,
		},
	}

	return RecipientInfo{
		Version:                0,
		IssuerAndSerialNumber:  issuerAndSerial,
		KeyEncryptionAlgorithm: algo,
		EncryptedKey:           encryptedKey,
	}
}

func makeEntropy(rand io.Reader, length int) ([]byte, error) {
	target := make([]byte, length)
	n, err := io.ReadFull(rand, target)
	if err != nil {
		return nil, err
	}
	if n < length {
		return nil, fmt.Errorf("pkcs7: didn't read enough entropy from rand")
	}
	return target, nil
}

func encryptContent(
	rand io.Reader,
	recipients []x509.Certificate,
	plaintext []byte,
	encryptionAlgorithm pkix.AlgorithmIdentifier,
	opts EncryptorOpts,
) (*asn1.RawValue, error) {
	sessionKey, err := makeEntropy(rand, 128)
	if err != nil {
		return nil, err
	}

	recipientsInfo := createRecipientsInfo(
		recipients,
		encryptionAlgorithm,
		sessionKey,
	)

	ed := EnvelopedData{
		Version:    0,
		Recipients: recipientsInfo,
		EncryptedContentInfo: EncryptedContentInfo{
			Type:      oidData,
			Algorithm: encryptionAlgorithm,
			Content:   asn1.RawValue{},
		},
	}
	return marshal(ed)
}

// Encrypt the plaintext to the recipients, maybe using the RNG `rand`, using
// EncryptorOpts.
func Encrypt(
	rand io.Reader,
	recipients []x509.Certificate,
	plaintext []byte,
	opts EncryptorOpts,
) (*ContentInfo, error) {
	contentInfo := ContentInfo{Type: oidEnvelopedData}
	iv, err := makeEntropy(rand, 16)
	if err != nil {
		return nil, err
	}

	encryptedContent, err := encryptContent(
		rand,
		recipients,
		plaintext,
		pkix.AlgorithmIdentifier{
			Algorithm:  oidEncryptionAES256CBC,
			Parameters: asn1.RawValue{Bytes: iv},
		},
		opts,
	)
	if err != nil {
		return nil, err
	}
	contentInfo.Content = *encryptedContent

	return &contentInfo, nil
}

// vim: foldmethod=marker
