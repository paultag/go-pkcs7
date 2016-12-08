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
	"bytes"
	"fmt"
)

func Unpad(data []byte, blockSize uint) ([]byte, error) {
	if blockSize < 1 {
		return nil, fmt.Errorf("Block size looks wrong")
	}

	if uint(len(data))%blockSize != 0 {
		return nil, fmt.Errorf("Data isn't aligned to blockSize")
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("Data is empty")
	}

	paddingLength := int(data[len(data)-1])
	for _, el := range data[len(data)-paddingLength:] {
		if el != byte(paddingLength) {
			return nil, fmt.Errorf("Padding had malformed entries")
		}
	}

	return data[:len(data)-paddingLength], nil
}

func Pad(data []byte, blockSize uint) ([]byte, error) {
	neededBytes := blockSize - (uint(len(data)) % blockSize)
	return append(data, bytes.Repeat([]byte{byte(neededBytes)}, int(neededBytes))...), nil

}

// vim: foldmethod=marker
