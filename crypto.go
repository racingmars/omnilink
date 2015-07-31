// Copyright 2015 Matthew R. Wilson <mwilson@mattwilson.org>. All
// rights reserved. Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package omnilink

import (
	"crypto/aes"
	"errors"
	"math"
)

// Given a 128-bit AES key and 40-bit session ID, derive the session AES key
// by XORing the last 40 bits of the AES key with the 40 bits of the session
// ID.
func deriveSessionKey(key [16]byte, sessionId [5]byte) [16]byte {
	for i := 0; i < 5; i++ {
		key[11+i] ^= sessionId[i]
	}
	return key
}

func encryptPacketData(sessionKey, data []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, err
	}

	// Pad data to fill 16-byte blocks
	dataLen := len(data) - 4 // first 4 bytes aren't part of the encrypted data
	neededLen := int(math.Ceil(float64(dataLen)/16.0)) * 16
	padBytes := neededLen - dataLen

	output := make([]byte, len(data)+padBytes)

	// Copy the header bytes
	copy(output, data[0:4])

	// Handle each data block -- i is the beginning byte of the block in data[],
	// and we'll increment by 16 each time to move to the next block. Start at 4
	// because that's where the data that needs to be encrypted starts.
	for i := 4; i < len(output); i += 16 {
		block := make([]byte, 16) // get a newly zeroed block slice
		copy(block, data[i:])
		block[0] ^= data[0] // block[0] XOR MSB(sequence number)
		block[1] ^= data[1] // block[1] XOR LSB(sequence number)
		cipher.Encrypt(output[i:i+16], block)
	}

	return output, nil
}

func decryptPacketBlock(sessionKey, sequenceNum, block []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, err
	}

	if len(sequenceNum) < 2 {
		return nil, errors.New("Sequence number must be 2 bytes")
	}

	if len(block) < 16 {
		return nil, errors.New("Block length must be 16 bytes")
	}

	result := make([]byte, 16)
	cipher.Decrypt(result, block)
	result[0] ^= sequenceNum[0] // result[0] XOR MSB(sequence number)
	result[1] ^= sequenceNum[1] // result[1] XOR LSB(sequence number)

	return result, nil
}
