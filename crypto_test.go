// Copyright 2015 Matthew R. Wilson <mwilson@mattwilson.org>. All
// rights reserved. Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package omnilink

import "encoding/hex"
import "testing"

func TestSessionKey(t *testing.T) {
	key, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	sessionID, _ := hex.DecodeString("2021222324")
	expected := "000102030405060708090a2b2d2f2d2b"

	var keyArray [16]byte
	var sessionArray [5]byte

	copy(keyArray[:], key)
	copy(sessionArray[:], sessionID)

	sessionKey := deriveSessionKey(keyArray, sessionArray)

	if hex.EncodeToString(sessionKey[:]) != expected {
		t.Error("Unexpected session key.")
	}
}

func TestEncrypt(t *testing.T) {
	sessionKey, _ := hex.DecodeString("000102030405060708090a2b2d2f2d2b")
	testData, _ := hex.DecodeString("01230000000102030405060708090A0B0C0D0E0F10")
	_, err := encryptPacketData(sessionKey, testData)
	if err != nil {
		t.Error(err)
		return
	}
}
