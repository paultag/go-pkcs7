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
	"crypto"
	"io"
)

type Verifier interface {
	// Public returns the public key corresponding to the opaque,
	// private key.
	Public() crypto.PublicKey

	// Verify checks the valididity of the signature over the given
	// digest value.
	Verify(rand io.Reader, digest []byte, signature []byte, opts VerifierOpts) (valid bool, err error)
}

type VerifierOpts interface {
	HashFunc() crypto.Hash
}

type Encryptor interface {
	// Public returns the public key corresponding to the opaque,
	// private key.
	Public() crypto.PublicKey

	// Encrypt encrypts msg. The opts argument should be appropriate for
	// the primitive used. See the documentation in each implementation for
	// details.
	Encrypt(rand io.Reader, cleartext []byte, opts EncryptorOpts) (ciphertext []byte, err error)
}

type EncryptorOpts interface{}

// vim: foldmethod=marker
