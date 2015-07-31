// Copyright 2015 Matthew R. Wilson <mwilson@mattwilson.org>. All
// rights reserved. Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package crc16

import "testing"
import "encoding/hex"

func TestCrc16(t *testing.T) {
	testString := "E100CAFE"
	expectedSum := "1CE1"

	inBytes, _ := hex.DecodeString(testString)
	expectedBytes, _ := hex.DecodeString(expectedSum)

	crc := New()
	n, err := crc.Write(inBytes)
	result := crc.Sum(make([]byte, 0))
	t.Logf("Returned value=%s, expected=%s", hex.EncodeToString(result),
		expectedSum)

	if n != len(inBytes) {
		t.Error("Write returned wrong length")
	}

	if err != nil {
		t.Error("Write returned an error")
	}

	if result[0] != expectedBytes[0] || result[1] != expectedBytes[1] {
		t.Error("Bad CRC-16 value")
	}

	if crc.Size() != 2 {
		t.Error("Bad size; CRC-16 should always be 2 bytes.")
	}

	crc.Reset()

	result = crc.Sum(make([]byte, 0))
	if result[0] != 0 || result[1] != 0 {
		t.Error("Bad value after reset")
	}
}
