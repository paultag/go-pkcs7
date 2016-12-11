package pkcs7_test

import (
	"bytes"
	"flag"
	"os"
	"testing"

	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"

	"pault.ag/go/pkcs7"
)

var aliceCert *x509.Certificate
var bobCert *x509.Certificate

var aliceRsaPrivateKey *rsa.PrivateKey
var bobRsaPrivateKey *rsa.PrivateKey
var malloryRsaPrivateKey *rsa.PrivateKey

func assert(t *testing.T, condition bool, what string) {
	if !condition {
		t.Fatal(what)
	}
}

func nokay(t *testing.T, err error, what string) {
	assert(t, err != nil, what)
}

func ok(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err.Error())
	}
}

func TestEncryption(t *testing.T) {
	contentInfo, err := pkcs7.Encrypt(
		rand.Reader,
		[]x509.Certificate{*aliceCert},
		SecretData,
	)
	ok(t, err)

	_, err = asn1.Marshal(*contentInfo)
	ok(t, err)
}

func TestEncryptionRoundTrip(t *testing.T) {
	contentInfo, err := pkcs7.Encrypt(
		rand.Reader,
		[]x509.Certificate{*aliceCert},
		SecretData,
	)
	ok(t, err)

	contentInfoBytes, err := asn1.Marshal(*contentInfo)
	ok(t, err)

	contentInfo, err = pkcs7.Parse(contentInfoBytes)
	ok(t, err)

	envelopedData, err := contentInfo.EnvelopedData()
	ok(t, err)

	secretData, err := envelopedData.Decrypt(*aliceCert, aliceRsaPrivateKey, rand.Reader, nil)
	ok(t, err)

	assert(t, bytes.Compare(secretData, SecretData) == 0, "decrypted data doesn't match test corpus")
}

func TestEncryptionStuffFails(t *testing.T) {
	contentInfo, err := pkcs7.Encrypt(
		rand.Reader,
		[]x509.Certificate{*aliceCert},
		SecretData,
	)
	ok(t, err)

	contentInfoBytes, err := asn1.Marshal(*contentInfo)
	ok(t, err)

	contentInfo, err = pkcs7.Parse(contentInfoBytes)
	ok(t, err)

	envelopedData, err := contentInfo.EnvelopedData()
	ok(t, err)

	_, err = envelopedData.Decrypt(*bobCert, bobRsaPrivateKey, rand.Reader, nil)
	nokay(t, err, "it thinks it decrypted it...")
}

func TestSign(t *testing.T) {
	dataContentInfo, err := pkcs7.Data(SecretData)
	ok(t, err)
	_, err = pkcs7.Sign(rand.Reader, *dataContentInfo, *aliceCert, aliceRsaPrivateKey, crypto.SHA256)
	ok(t, err)
}

func TestSignAndVerify(t *testing.T) {
	dataContentInfo, err := pkcs7.Data(SecretData)
	ok(t, err)
	signedContentInfo, err := pkcs7.Sign(rand.Reader, *dataContentInfo, *aliceCert, aliceRsaPrivateKey, crypto.SHA256)
	ok(t, err)

	signedContentInfoBytes, err := asn1.Marshal(*signedContentInfo)
	ok(t, err)

	contentInfo, err := pkcs7.Parse(signedContentInfoBytes)
	ok(t, err)

	underlyingContentInfo, err := contentInfo.SignedData()
	ok(t, err)

	ok(t, underlyingContentInfo.Verify(*aliceCert))
}

func TestSignAndFailsToVerifyBadHash(t *testing.T) {
	dataContentInfo, err := pkcs7.Data(SecretData)
	ok(t, err)
	signedContentInfo, err := pkcs7.Sign(rand.Reader, *dataContentInfo, *aliceCert, aliceRsaPrivateKey, crypto.SHA256)
	ok(t, err)

	signedContentInfo.Content.Bytes[100] = 'h'

	signedContentInfoBytes, err := asn1.Marshal(*signedContentInfo)
	ok(t, err)

	contentInfo, err := pkcs7.Parse(signedContentInfoBytes)
	ok(t, err)

	underlyingContentInfo, err := contentInfo.SignedData()
	ok(t, err)

	nokay(t, underlyingContentInfo.Verify(*aliceCert), "Hash validation passed")
}

func TestSignAndFailsToVerifyWithTotallyWrongCert(t *testing.T) {
	dataContentInfo, err := pkcs7.Data(SecretData)
	ok(t, err)
	signedContentInfo, err := pkcs7.Sign(rand.Reader, *dataContentInfo, *aliceCert, aliceRsaPrivateKey, crypto.SHA256)
	ok(t, err)

	signedContentInfoBytes, err := asn1.Marshal(*signedContentInfo)
	ok(t, err)

	contentInfo, err := pkcs7.Parse(signedContentInfoBytes)
	ok(t, err)

	underlyingContentInfo, err := contentInfo.SignedData()
	ok(t, err)

	nokay(t, underlyingContentInfo.Verify(*bobCert), "Bogus signature was fine passed")
}

func TestSignAndFailsToVerifySignature(t *testing.T) {
	dataContentInfo, err := pkcs7.Data(SecretData)
	ok(t, err)
	signedContentInfo, err := pkcs7.Sign(rand.Reader, *dataContentInfo, *aliceCert, malloryRsaPrivateKey, crypto.SHA256)
	ok(t, err)

	signedContentInfoBytes, err := asn1.Marshal(*signedContentInfo)
	ok(t, err)

	contentInfo, err := pkcs7.Parse(signedContentInfoBytes)
	ok(t, err)

	underlyingContentInfo, err := contentInfo.SignedData()
	ok(t, err)

	nokay(t, underlyingContentInfo.Verify(*aliceCert), "Bogus signature was fine passed")
}

func TestMain(m *testing.M) {
	block, _ := pem.Decode(AliceCert)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(err)
	}
	aliceCert = cert

	block, _ = pem.Decode(BobsCert)
	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(err)
	}
	bobCert = cert

	block, _ = pem.Decode(AliceKey)
	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	aliceRsaPrivateKey = rsaKey

	block, _ = pem.Decode(BobsKey)
	rsaKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	bobRsaPrivateKey = rsaKey

	block, _ = pem.Decode(MalloryKey)
	rsaKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	malloryRsaPrivateKey = rsaKey

	flag.Parse()
	ret := m.Run()
	os.Exit(ret)
}

var (
	AliceCert []byte = []byte(`-----BEGIN CERTIFICATE-----
MIIEXTCCAsWgAwIBAgIRAJB4MY12+llkm0LMilO286kwDQYJKoZIhvcNAQELBQAw
WTELMAkGA1UEBhMCVVMxKjAoBgNVBAoTIVN0cmV4Q29ycCBTeW5lcm5pc3RzIElu
Y29ycG9yYXRlZDEeMBwGA1UEAxMVS2V2aW5zLU1CUC5zdHJleC5jb3JwMB4XDTE2
MTIxMTE3NTcxM1oXDTE3MTIxMTE3NTcxM1owWTELMAkGA1UEBhMCVVMxKjAoBgNV
BAoTIVN0cmV4Q29ycCBTeW5lcm5pc3RzIEluY29ycG9yYXRlZDEeMBwGA1UEAxMV
S2V2aW5zLU1CUC5zdHJleC5jb3JwMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIB
igKCAYEA11HE0IdpPCSlWHTIr0nXrUGUxcq5IMeTc6VIM0wigGjW0MFO6gzNnjVo
iBITupsUAv9QjalTPpYI6tC+jX9sAbDtLrI/qU95YCinOsFaRfQNwGTXGxumsepl
6Bl/fTryMWaAZ/Bo8prJXT3H3XHpoXsmJTuZghq24zhXgxVEfz4tDmiJp75SW4Zm
SUHKtXwX8Vwtyji0EWq3zHuNpwepeY0tiaOkAjOPosOElBHrv7Y8tQw0PqXjqpND
myRBHP8G3XfF9PB+TS0b1KkndR9y95DSl9rCyyjH1ppvde9jOoZpsakq6fCe698x
gkv3LtBb5DVACVjpDzm3AwVLhHDWZARNoHUi3WhvsXj0CrCmjtVr+BePXHU5Xp3i
mAgr47shzOG/Q6eARF60xNq4/HN7gMrBriVIl1glE7w6hE3Jh6I5ctcU1AQC7V93
iCaFQ7LNHNAUKuytm9iJ6dDo9k5Z71G14sZEuxXMjWHoKf9vVKjEE/Umy8aJkD4v
fPnooMAjAgMBAAGjIDAeMA4GA1UdDwEB/wQEAwIFoDAMBgNVHRMBAf8EAjAAMA0G
CSqGSIb3DQEBCwUAA4IBgQBtEdKPoto5Fqlpl8DqShJzOoXsqRtbjCmxPbKPfLbK
4cfIHdvCt7i4UDq1uouBpVclA21cdDOWreNHOW8wnE9ccGazEs4YztFGIpLCHp3u
B82CwYfWaFBBT5Dhs/RRNUBa9tn3m/o9xTnBymcbHZ/WinPsHFh5z82aEt1hOXuw
O/Q4TqyfOEVwsBPYwZ/nYgnyuI130956xH+Z73jgUo0Ci92VJq00/PytejbcRo9H
UQ/Gc9ycfHbUfS4s/9naCE+DPoLeOVMBytsrLOFEXaJNFv9DLbRf2rPws6P7GqW8
QIsIktPu5yVIznIG4re9W1wJoPpbyfL/KsHdbOqklkEtrAMrnzR5SSeEyk8HTzYA
j0cJQITCN+vAa4ydnZ6+86w2kt3R8xpyJY9y6bVkH55ft9kQlB4od6r+Q5Mr6eii
lgmL9D1o2wVfDwWMU4PtNqLV9cYw+lelWxw02QLq+jXuF5ABUbbWhNHJMRSwFKLN
Q+dboFBMPggDWrPrgWSk8bw=
-----END CERTIFICATE-----
`)
	AliceKey []byte = []byte(`-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
`)
	MalloryKey []byte = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA3j+sMete0f1BzXRRuYAAy4i3SdKITVhe9A9g0MG4GH4H96Oy
Q8mEJYPqpSQ2QZlVv9ObVr1bIFMqBaWYEEpOtECBrfPN/nWxocCAl0hPI7hvGRV0
TIMZ3uBITldJvgwwYJi2QcXADK5zsOGneroabGGik18VBEz6wyKDS9w8tVFRsD1A
JhQuMSg+IDv4Q2vqbwoSq2pq/e7uQf4+cfSu5lV2pJIZJo8mq6YsrNpgk7L7vk/E
zRuhUh3HsugPOCKdJgGs8h3K9AlxEZlrRrRNeBH+bGtuOs5K4B93SPBUZ0wkwWkU
CC2yzHs3kEjxRmmxzXQiRAvK4F/M4aZrAnq3WwIDAQABAoIBAB/3JHshkUe+l0JH
oqF9iZ+8kDAr+bK2LSIJPDGKS0IqjlbN0ovxZfJHYO5ToQIaXbzzYHo/TeX+UCLz
yEU/isZeKMiuMkiRAPV0zIn1unw2wLPo5AtFJ+lodL3fzBlrg2HBVSVsncy1Iqqk
KgR60+YWvN1ZZZpyv/Zk9mFo0cp6HRdFVPx5AHlHb/RM/Lo/QFN+NXKqFpXs9BOx
O83xC0gUHt/weslRuzAQBQlj6+B4hOgCRyEVx3wMLZ8GoQQAdK6cPndgGqrg+9Sf
PAd+RKfjKHUVe8zh94Cl0MRIm9J+HrFVO00yBQpjbxAGPttQ5/2Ee91pZouRWGZ7
XZY/4tECgYEA8wNq/0AMKC5xxn0MiGoP72BOJb1pWJ2XlDvKvw9gssImPWAmtju0
bsBr8/9xR52a56SApANIwugdSPt5L8pzgzmNIzyHuuooYAOpeED+RvQTgsOCfG3N
iGfvA+p55c2sZfhxxosAaH+EfrpAvne2zzmQpKlT/qc2eaAHg7oiyTcCgYEA6iAu
ULXaC30zsNdb8xoNa+jqEfNk7ag3W76u6+FVNu/kgsH3Lknza1YXl1Cp+RDqk7vA
s/PlNnfOzZuPrftp4brkZ0g6lxmx9CsF0luGcGB5qqNfAexZxrCJDxh2wUvXqRKf
ggCy592ZazsHFpL0oOVaPwh1v5hiMmYTCHszBP0CgYEAlhrZX3sPR06Q5prdP/HL
j/+7paIezSbityRLssJr5173Qdf/cXbll7dxtxBkx2i5gzXgY+7HZeT8GdWDYJq7
ySWmYUqFSFZUxCHe7zGuHuOqnY3oLrWgTA5u28tcqi7lu0K//HRltyZ1D9Y6IaxO
lieniZ4yDMz6YBwSKDK0Q/cCgYEA3kwj7bpdB9+e/t/cjFxGNhl2dgjV4dmAhnns
+EaBdKIeJBErMyZAG8AosiGC4duv/wmcFMEU97yV/R8hMx6uEAg16eLozqM1FhLr
eiow4e6YVu67vMW/ECp6WHzv9OSgJgZqsTMcq476ppfrSQHLiCF8qLDNrFdxlUzZ
8YmYjbkCgYBf/GsCR/KjwUCouFq5hsRSzEPtSZ9Po4Eyjv7LtX+TF2danKak44bU
RiYfqbigxDM/TsoNEqkWj8lrgE+8tjp/q39iQL41vcNbt7nqCYc8ReQ1tKrC3j3L
JhONIdLcifl7DeJMLPm9eSQeeTL7Tmqt/0m2kcJW6TrxcLls+RqtiQ==
-----END RSA PRIVATE KEY-----
`)

	BobsCert []byte = []byte(`-----BEGIN CERTIFICATE-----
MIIEXDCCAsSgAwIBAgIQDjDy+g+JLRJJyOvQlUpnFDANBgkqhkiG9w0BAQsFADBZ
MQswCQYDVQQGEwJVUzEqMCgGA1UEChMhU3RyZXhDb3JwIFN5bmVybmlzdHMgSW5j
b3Jwb3JhdGVkMR4wHAYDVQQDExVLZXZpbnMtTUJQLnN0cmV4LmNvcnAwHhcNMTYx
MjExMTkwMDA2WhcNMTcxMjExMTkwMDA2WjBZMQswCQYDVQQGEwJVUzEqMCgGA1UE
ChMhU3RyZXhDb3JwIFN5bmVybmlzdHMgSW5jb3Jwb3JhdGVkMR4wHAYDVQQDExVL
ZXZpbnMtTUJQLnN0cmV4LmNvcnAwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGK
AoIBgQC/H+si5BFSI944t3XZP2zGdfCpcm+uXkiC0W4tJjXk+/Mm0eb6TmuEcinO
SPzqfqSEE9UxeQeRUEUA6/9Z1TRm75zhxCJpv0I1Lki1dk4YvjdO8Dmajbsn8LTr
m7MlGdwNoEvlXpJiHxA2+N4ps/KpiYAPF6ZapEXBoHp+M3VzGZKCoEOavp6luI3r
cmlHTqqZM1+dUt5Ozf3hVadg/8txhs+ivBuzM2j6E05DZgqzHW/UL155zp03Jx7b
lYay1g0fDYmXwDG/9D5Kd8+gCAp103SOizfTBCPZJV9knDIsalEU8VUovX9YDUfo
Oen2ORoBbrHXfNCwNXT/XFD1g6/DPUfX6ydw1JwOrNi6Vzo1o0DugdMd1er8EDYR
S+MmYb5vGFu/QKoauFNkqZG92CKVGAK9Wl8ArF/UISbmv5oR7SjT+V2sclCYHrab
2bTnRwlTs3q9+zhDMEthZFVDED70rTdr2hWh3qlBuGGbZVievLGUJJOHsmLim3ki
DiZGbLUCAwEAAaMgMB4wDgYDVR0PAQH/BAQDAgWgMAwGA1UdEwEB/wQCMAAwDQYJ
KoZIhvcNAQELBQADggGBAIHwlFtYX9y8xQspTg7B34FMXgqOgjsiEKJiL1noWIfk
Pv1sZvoWZhmVTvzvVYDKsZYTVro+OOORms5Z6kk9MV5N4hWuTG/Zij1Q+UcQTqmz
J/LigQtVfeOlcYrRlRh/v0cTaHyXjeRM+c1MeNdfnWgTZnEcZwGqvHJrE9nPlTsb
/ss3saLh+8S/yS0qtLgKPCrUQHzJNt1Sp8irceH4388dlIy7ebtooyJk0DFBhWeY
H4WdRh7vs39wrNZW5Um/yeH8M+djmPDynhcbhKQU0jU6DgQtmtOGrJfmN7HJFHwi
3Lf4qaIC7WCHE0lLELdT+dXWTO8vOG8pS1VpDAx0lX8Yaq8uYjalJm/FHH2VYpH8
FQl/dQe68Z0vp8L7at9v8suvjaNaPB5eW+PDUfoEmQ3MGwbRo2BHa8wGC0/zhlNl
FOse5ft23HwKvSJSfK5LSGo51KoHnaR0/1Vr5uLqvJAVAGdNHYlo4+YVbUkVbZ/j
0/cdnqxVgDhmT6dMZlqzWQ==
-----END CERTIFICATE-----
`)

	BobsKey []byte = []byte(`-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
`)

	SecretData []byte = []byte(`Congress shall make no law respecting an establishment of
religion, or prohibiting the free exercise thereof; or abridging the freedom of
speech, or of the press; or the right of the people peaceably to assemble, and
to petition the Government for a redress of grievances.`)
)
