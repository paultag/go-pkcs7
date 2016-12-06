pkcs7
=====

Pure-Go implemntation of the PKCS#7 specification.

WARNING
-------

This implementation is like totally super not implemented all the way through.
When this blows up, puts a hole through your screen and deletes all your data,
please don't blame me.

So far, it only decrypts encrypted messages, and verifies the signatures of
signed messages.


High level features
-------------------

 - [x] Decryption
 - [x] Signature Validation
 - [ ] Encryption
 - [ ] Signing
