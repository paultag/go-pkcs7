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

	"crypto/cipher"
	"crypto/x509"
	"crypto/x509/pkix"

	"pault.ag/go/pkcs7/utils"
)

func readRand(rand io.Reader, size int) ([]byte, error) {
	data := make([]byte, size)
	n, err := io.ReadFull(rand, data)
	if err != nil {
		return nil, err
	}
	if n != size {
		return nil, fmt.Errorf("pkcs7: not enough calming entropy")
	}
	return data, nil
}

func newIssuerAndSerialNumber(cert x509.Certificate) (*IssuerAndSerialNumber, error) {
	return &IssuerAndSerialNumber{
		Issuer: asn1.RawValue{FullBytes: cert.RawIssuer},
		Serial: cert.SerialNumber,
	}, nil
}

func newRecipientInfo(rand io.Reader, cert x509.Certificate, algorithm pkix.AlgorithmIdentifier, key []byte) (*RecipientInfo, error) {
	issuerAndSerial, err := newIssuerAndSerialNumber(cert)
	if err != nil {
		return nil, err
	}

	encryptedKey, err := utils.Encrypt(rand, cert, key, nil)
	if err != nil {
		return nil, err
	}

	return &RecipientInfo{
		IssuerAndSerialNumber:  *issuerAndSerial,
		KeyEncryptionAlgorithm: algorithm,
		EncryptedKey:           encryptedKey,
	}, nil
}

func newEncryptedContentInfo(encryptedContentType asn1.ObjectIdentifier, algorithm pkix.AlgorithmIdentifier, content []byte) (*EncryptedContentInfo, error) {
	return &EncryptedContentInfo{
		Type:      encryptedContentType,
		Algorithm: algorithm,
		Content:   asn1.RawValue{Bytes: content},
	}, nil
}

func newEnvelopedData(r Recipients, eci EncryptedContentInfo) (*EnvelopedData, error) {
	return &EnvelopedData{
		Version:              0,
		Recipients:           r,
		EncryptedContentInfo: eci,
	}, nil

}

func newContentInfo(contentType asn1.ObjectIdentifier, content []byte) (*ContentInfo, error) {
	return &ContentInfo{
		Type:    contentType,
		Content: asn1.RawValue{Bytes: content},
	}, nil
}

func newRecipients(rand io.Reader, to []x509.Certificate, encryptionAlgorithm pkix.AlgorithmIdentifier, sessionKey []byte) (*Recipients, error) {
	recipients := Recipients{}
	for _, cert := range to {
		recipient, err := newRecipientInfo(rand, cert, encryptionAlgorithm, sessionKey)
		if err != nil {
			return nil, err
		}
		recipients = append(recipients, *recipient)
	}
	return &recipients, nil
}

//
func Encrypt(rand io.Reader, to []x509.Certificate, plaintext []byte) (*ContentInfo, error) {
	// sessionKey and IV are tied to AES 256; change this to read the BlockSize
	// and friends.
	sessionKey, err := readRand(rand, 32)
	if err != nil {
		return nil, err
	}
	iv, err := readRand(rand, 16)
	if err != nil {
		return nil, err
	}

	algorithm := pkix.AlgorithmIdentifier{
		Algorithm:  oidEncryptionAES256CBC,
		Parameters: asn1.RawValue{Bytes: iv},
	}

	block, err := getBlockCipherByOID(algorithm.Algorithm, sessionKey)
	if err != nil {
		return nil, err
	}

	plaintext, err = Pad(plaintext, uint(block.BlockSize()))
	if err != nil {
		return nil, err
	}

	// this assumes CBC, which is hard coded above in a few places too
	blockMode := cipher.NewCBCEncrypter(block, iv)

	encryptedBytes := make([]byte, len(plaintext))
	blockMode.CryptBlocks(encryptedBytes, plaintext)

	encryptedContentInfo, err := newEncryptedContentInfo(oidData, algorithm, encryptedBytes)
	if err != nil {
		return nil, err
	}

	recipients, err := newRecipients(rand, to, algorithm, sessionKey)
	if err != nil {
		return nil, err
	}

	envelopedData, err := newEnvelopedData(*recipients, *encryptedContentInfo)
	if err != nil {
		return nil, err
	}

	envelopedDataBytes, err := asn1.Marshal(*envelopedData)
	if err != nil {
		return nil, err
	}

	return newContentInfo(oidEnvelopedData, envelopedDataBytes)
}

// vim: foldmethod=marker
