package pkcs7

import (
	"bytes"
	"fmt"
	"io"
	"math/big"

	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
)

var (
	// TODO: Remove this.
	Unimplemented = fmt.Errorf("pkcs7: paultag is lazy")

	// If the PKCS#7 implemtation here doesn't know what to do with that Content Type,
	// we'll bail out of the function with one of these guys.
	UnsupportedContent = fmt.Errorf("pkcs7: unsupported content type")

	// If the PKCS#7 decryption bits don't know how to decrypt the message,
	// we're going to go ahead and tell the user we don't know what's up.
	UnsupportedAlgorithm = fmt.Errorf("pkcs7: unsupported algorithm")

	// If we can't find a matching x509 Certificate in the RecipientInfo list,
	// we'll drop this out of Error. Matching is done based on Issuer bytes
	// and Serial. If you know exactly what is going on (e.g. Self-Signed and
	// you didn't keep it around because lol self signed certificates aren't
	// real), you can go ahead and manually fiddle the internals.
	NoMatchingCertificate = fmt.Errorf("pkcs7: can't find your cert")

	//
	NoMatchingAttribute = fmt.Errorf("pkcs7: can't find the right attribute")

	//
	NoMatchingAlgorithm = fmt.Errorf("pkcs7: can't find the right hashing algorithm")
)

var (
	oidEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

	oidAttributeMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}

	oidEncryptionAES256CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidEncryptionDESCBC     = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 7}
	oidEncryptionDESEDE3CBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}

	oidDigestAlgorithmSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidDigestAlgorithmSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	// XXX: Add more hashes, this is nowhere near good enough.

	oidSignatureAlgorithmRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
)

// {{{ OID Algorithm Lookups

// Look up a x509.SignatureAlgorithm by the ASN1 ObjectIdentifiers sent over
// in the SignerInfo, which can be used out in a call x509.CheckSignature
func getSignatureAlgorithmByOID(signerInfo SignerInfo) (x509.SignatureAlgorithm, error) {

	digestAlgorithm := signerInfo.DigestAlgorithm.Algorithm
	signatureAlgorithm := signerInfo.DigestEncryptionAlgorithm.Algorithm

	switch {
	case signatureAlgorithm.Equal(oidSignatureAlgorithmRSA) && digestAlgorithm.Equal(oidDigestAlgorithmSHA256):
		return x509.SHA256WithRSA, nil
	case signatureAlgorithm.Equal(oidSignatureAlgorithmRSA) && digestAlgorithm.Equal(oidDigestAlgorithmSHA1):
		return x509.SHA1WithRSA, nil
	default:
		return x509.SignatureAlgorithm(0), NoMatchingAlgorithm
	}
}

// Get a crypto.Hash by ASN1 ObjectIdentifier.
func getHashByOID(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch {
	case oid.Equal(oidDigestAlgorithmSHA256):
		return crypto.SHA256, nil
	case oid.Equal(oidDigestAlgorithmSHA1):
		return crypto.SHA1, nil
	default:
		return crypto.Hash(0), NoMatchingAlgorithm
	}
}

// }}}

// {{{ Attributes

type Attribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

type Attributes []Attribute

func (a Attributes) Find(attributeType asn1.ObjectIdentifier) (*Attribute, error) {
	for _, el := range a {
		if el.Type.Equal(attributeType) {
			return &el, nil
		}
	}
	return nil, NoMatchingAttribute
}

// }}}

// {{{ SignerInfo

type SignerInfo struct {
	Version                   int
	IssuerAndSerialNumber     IssuerAndSerialNumber
	DigestAlgorithm           pkix.AlgorithmIdentifier
	AuthenticatedAttributes   Attributes `asn1:"optional,tag:0"`
	DigestEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedDigest           []byte
	UnauthenticatedAttributes Attributes `asn1:"optional,tag:1"`
}

func (s SignerInfo) Matches(cert x509.Certificate) bool {
	return s.IssuerAndSerialNumber.Matches(cert)
}

type SignersInfo []SignerInfo

func (s SignersInfo) Find(cert x509.Certificate) (*SignerInfo, error) {
	for _, entry := range s {
		if entry.Matches(cert) {
			return &entry, nil
		}
	}
	return nil, NoMatchingCertificate
}

// }}}

// {{{ ASN1 Bytestream with Certificates

type RawCertificates struct {
	Raw asn1.RawContent
}

func (gah RawCertificates) Certificates() ([]*x509.Certificate, error) {
	if len(gah.Raw) == 0 {
		// lol nbd
		return nil, nil
	}

	var asn1Cert asn1.RawValue
	if _, err := asn1.Unmarshal(gah.Raw, &asn1Cert); err != nil {
		return nil, err
	}

	return x509.ParseCertificates(asn1Cert.Bytes)
}

// }}}

// {{{ SignedData

type SignedData struct {
	Version                    int                        `asn1:"default:1"`
	DigestAlgorithmIdentifiers []pkix.AlgorithmIdentifier `asn1:"set"`
	ContentInfo                ContentInfo
	RawCertificates            RawCertificates        `asn1:"optional,tag:0"`
	CRLs                       []pkix.CertificateList `asn1:"optional,tag:1"`
	SignerInfo                 SignersInfo            `asn1:"set"`
}

// {{{ Signature Verification

// Explictly pass in the x509 Certificate we're checking against. If I was
// a clever attacker, I might just make a self-signed TLS certificate with
// the same issuer and serial, and hope no one checks too closely that it's
// not the same same. As a result, if you plan on trusting the cert that's
// coming across the line, It's on you to load and verify you've got the
// right cert in your hand.
//
// This means we won't check the CA signature, NotAfter, NotBefore, KeyUsage,
// or anything else. That's on you, buddy!
func (s SignedData) Verify(cert x509.Certificate) error {
	signerInfo, err := s.SignerInfo.Find(cert)
	if err != nil {
		return err
	}
	_, err = s.VerifyHash(*signerInfo, cert)
	if err != nil {
		return err
	}
	return s.VerifySignature(*signerInfo, cert)
}

// {{{ AttributeSet (internal to signing)

type AttributeSet struct {
	Attributes Attributes `asn1:"set"`
}

// }}}

func (s SignedData) VerifySignature(signerInfo SignerInfo, cert x509.Certificate) error {
	algorithm, err := getSignatureAlgorithmByOID(signerInfo)
	if err != nil {
		return err
	}

	if !signerInfo.Matches(cert) {
		return fmt.Errorf("provided SignerInfo doesn't match the given x509 Certificate")
	}

	attributes, err := asn1.Marshal(AttributeSet{
		Attributes: signerInfo.AuthenticatedAttributes,
	})
	if err != nil {
		return err
	}

	var signedData asn1.RawValue
	asn1.Unmarshal(attributes, &signedData)

	return cert.CheckSignature(algorithm, signedData.Bytes, signerInfo.EncryptedDigest)
}

func (s SignedData) VerifyHash(signerInfo SignerInfo, cert x509.Certificate) ([]byte, error) {
	var digest []byte

	attribute, err := signerInfo.AuthenticatedAttributes.Find(oidAttributeMessageDigest)
	if err != nil {
		return nil, err
	}

	_, err = asn1.Unmarshal(attribute.Value.Bytes, &digest)
	if err != nil {
		return nil, err
	}

	/* Right, so we've got the digest we think it is, so let's go ahead and
	 * do some number crunching */

	algorithm, err := getHashByOID(signerInfo.DigestAlgorithm.Algorithm)
	if err != nil {
		return nil, err
	}

	// TODO: "Compound" nonsense.
	var body asn1.RawValue
	if _, err := asn1.Unmarshal(s.ContentInfo.Content.Bytes, &body); err != nil {
		return nil, err
	}

	hash := algorithm.New()
	hash.Write(body.Bytes)
	sum := hash.Sum(nil)

	if !hmac.Equal(digest, sum) {
		return nil, fmt.Errorf("pkcs7: digest mismatch %x vs %x")
	}

	return sum, nil
}

func (s SignedData) Certificates() ([]*x509.Certificate, error) {
	return s.RawCertificates.Certificates()

}

// }}}

// }}}

// {{{ IssuerAndSerialNumber

type IssuerAndSerialNumber struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

func (i IssuerAndSerialNumber) Matches(cert x509.Certificate) bool {
	return cert.SerialNumber.Cmp(i.Serial) == 0 &&
		bytes.Compare(cert.RawIssuer, i.Issuer.FullBytes) == 0
}

// }}}

// {{{ RecipientInfo

type RecipientInfo struct {
	Version                int
	IssuerAndSerialNumber  IssuerAndSerialNumber
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

// Check to see if the RecipientInfo Serial and Issuer match our Certificate.
func (r RecipientInfo) Matches(cert x509.Certificate) bool {
	return r.IssuerAndSerialNumber.Matches(cert)
}

// Get the content key out of the EncryptedKey entry
func (r RecipientInfo) Decrypt(
	decrypter crypto.Decrypter,
	rand io.Reader,
	opts crypto.DecrypterOpts,
) ([]byte, error) {
	return decrypter.Decrypt(rand, r.EncryptedKey, opts)
}

type Recipients []RecipientInfo

// Given a list of RecipientInfo objects, find the matching RecipientInfo entry
// by seeing which Serial and Issuer matches our certificate. If no matching
// RecipientInfo is found, we'll return a `NoMatchingCertificate` error.
func (r Recipients) Find(cert x509.Certificate) (*RecipientInfo, error) {
	for _, el := range r {
		if el.Matches(cert) {
			return &el, nil
		}
	}
	return nil, NoMatchingCertificate
}

// }}}

// {{{ EnvelopedData

type EnvelopedData struct {
	Version              int
	Recipients           Recipients `asn1:"set"`
	EncryptedContentInfo EncryptedContentInfo
}

func (e EnvelopedData) Decrypt(cert x509.Certificate, decrypter crypto.Decrypter, rand io.Reader, opts crypto.DecrypterOpts) ([]byte, error) {
	/* Now, let's find our RecipientInfo payload */
	whoami, err := e.Recipients.Find(cert)
	if err != nil {
		return nil, err
	}

	decryptionKey, err := whoami.Decrypt(decrypter, rand, opts)
	if err != nil {
		return nil, err
	}

	return e.EncryptedContentInfo.RawDecrypt(decryptionKey)
}

// }}}

// {{{ EncryptedContentInfo

type EncryptedContentInfo struct {
	Type      asn1.ObjectIdentifier
	Algorithm pkix.AlgorithmIdentifier
	Content   asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

// For users who know what they're doing, here's the knob.
func (e EncryptedContentInfo) RawDecrypt(key []byte) ([]byte, error) {
	encryptedBytes := e.Content.Bytes

	var blockCipher cipher.Block
	var err error

	algorithm := e.Algorithm.Algorithm
	switch {
	case algorithm.Equal(oidEncryptionDESCBC):
		blockCipher, err = des.NewCipher(key)
	case algorithm.Equal(oidEncryptionDESEDE3CBC):
		blockCipher, err = des.NewTripleDESCipher(key)
	case algorithm.Equal(oidEncryptionAES256CBC):
		blockCipher, err = aes.NewCipher(key)
	default:
		return nil, UnsupportedAlgorithm
	}

	if err != nil {
		return nil, err
	}

	iv := e.Algorithm.Parameters.Bytes

	if len(iv) != blockCipher.BlockSize() {
		return nil, fmt.Errorf("pkcs7: iv doesn't match block size")
	}

	cbc := cipher.NewCBCDecrypter(blockCipher, iv)
	decryptedBytes := make([]byte, len(encryptedBytes))

	cbc.CryptBlocks(decryptedBytes, encryptedBytes)
	decryptedBytes, err = Unpad(decryptedBytes, uint(cbc.BlockSize()))
	if err != nil {
		return nil, err
	}

	return decryptedBytes, nil

}

// }}}

// {{{ ContentInfo

// Given a series of bytes, go ahead and create a ContentInfo header.
func parseContentInfo(data []byte) (*ContentInfo, []byte, error) {
	contentInfo := ContentInfo{}
	next, err := asn1.Unmarshal(data, &contentInfo)
	return &contentInfo, next, err
}

// ContentInfo encapsulation. This is the top level struct. One can then
// dispatch based on `Type`, and call the right method(s).
type ContentInfo struct {
	Type    asn1.ObjectIdentifier
	Content asn1.RawValue `asn1:"explicit,optional,tag:0`
}

func (c ContentInfo) RawContent() ([]byte, error) {
	var asn1Cert asn1.RawValue
	if _, err := asn1.Unmarshal(c.Content.Bytes, &asn1Cert); err != nil {
		return nil, err
	}
	return asn1Cert.Bytes, nil
}

func (c ContentInfo) SignedData() (*SignedData, error) {
	if !c.Type.Equal(oidSignedData) {
		return nil, fmt.Errorf(
			"pkcs7: trying to parse SignedData without the right OID",
		)
	}
	signedData := SignedData{}
	if _, err := asn1.Unmarshal(c.Content.Bytes, &signedData); err != nil {
		return nil, err
	}
	return &signedData, nil
}

// Get the EnvelopedData struct out of the body of the Content. If the content
// is not Enveloped, we'll return an error. otherwise, we'll unpack the
// encrypted goodness into a EnvelopedData struct.
func (c ContentInfo) EnvelopedData() (*EnvelopedData, error) {
	if !c.Type.Equal(oidEnvelopedData) {
		return nil, fmt.Errorf(
			"pkcs7: trying to parse EnvelopedData without the right OID",
		)
	}
	envelopedData := EnvelopedData{}
	if _, err := asn1.Unmarshal(c.Content.Bytes, &envelopedData); err != nil {
		return nil, err
	}
	return &envelopedData, nil
}

// DER encoded only pls
func New(data []byte) (*ContentInfo, error) {
	contentInfo, trailingBytes, err := parseContentInfo(data)
	if err != nil {
		return nil, err
	}
	if len(trailingBytes) != 0 {
		return nil, fmt.Errorf("pkcs7: trailing der bytes in the message")
	}

	return contentInfo, nil
}

// }}}

// vim: foldmethod=marker