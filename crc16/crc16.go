// Copyright 2015 Matthew R. Wilson <mwilson@mattwilson.org>. All
// rights reserved. Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package crc16 implements a 16-bit cyclic redundancy check for HAI
// automation systems.
package crc16

import "hash"

// The size of a CRC-16 checksum in bytes.
const Size = 2

// The HAI (Home Automation Inc.) polynomial for the Omni Link II protocol.
const HAI = 0xA001

type crc16 struct {
	sum  uint16
	poly uint16
}

// New creates a new hash.Hash for computing the CRC-16 checksum for
// HAI automation systems.
func New() hash.Hash {
	return &crc16{sum: 0, poly: HAI}
}

func (c *crc16) Sum(b []byte) []byte {
	return append(b, byte(c.sum>>8), byte(c.sum))
}

func (c *crc16) Reset() {
	c.sum = 0
}

func (c *crc16) Size() int {
	return Size
}

func (c *crc16) BlockSize() int {
	return 1
}

func (c *crc16) Sum16() uint16 {
	return c.sum
}

func (c *crc16) Write(p []byte) (n int, err error) {
	for _, b := range p {
		c.update(b)
	}
	return len(p), nil
}

func (c *crc16) update(b byte) {
	c.sum ^= uint16(b)
	for i := 0; i < 8; i++ {
		flag := (c.sum & 1) == 1
		c.sum = c.sum >> 1
		if flag {
			c.sum ^= c.poly
		}
	}
}
