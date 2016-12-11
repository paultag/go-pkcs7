package pkcs7_test

import (
	"flag"
	"os"
	"testing"

	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"

	"pault.ag/go/pkcs7"
)

var cert *x509.Certificate
var rsaPrivateKey *rsa.PrivateKey

func assert(t *testing.T, condition bool, what string) {
	if !condition {
		t.Fatal(what)
	}
}

func ok(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err.Error())
	}
}

func TestEncryption(t *testing.T) {
	data := []byte(`Congress shall make no law respecting an establishment of
religion, or prohibiting the free exercise thereof; or abridging the freedom of
speech, or of the press; or the right of the people peaceably to assemble, and
to petition the Government for a redress of grievances.`)
	assert(t, cert != nil, "cert isn't set, what")

	contentInfo, err := pkcs7.Encrypt(
		rand.Reader,
		[]x509.Certificate{*cert},
		data,
	)
	ok(t, err)

	_, err = asn1.Marshal(*contentInfo)
	ok(t, err)
}

func TestMain(m *testing.M) {
	block, _ := pem.Decode([]byte(TestCert))
	testCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(err)
	}

	block, _ = pem.Decode([]byte(TestKey))
	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	cert = testCert
	rsaPrivateKey = rsaKey

	flag.Parse()
	ret := m.Run()
	os.Exit(ret)
}

const (
	TestCert string = `-----BEGIN CERTIFICATE-----
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
`
	TestKey string = `-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
`
)
