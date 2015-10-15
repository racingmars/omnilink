// Copyright 2015 Matthew R. Wilson <mwilson@mattwilson.org>. All
// rights reserved. Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package omnilink

import (
	"bytes"
	"encoding/binary"
)

type pktMsgType uint8

// Application Packet message types
const (
	pktNoMessage       pktMsgType = 0  // No message
	pktReqNewSession   pktMsgType = 1  // Client request new session
	pktAckNewSession   pktMsgType = 2  // Controller acknowledge new session
	pktReqSecure       pktMsgType = 3  // Client request secure connections
	pktAckSecure       pktMsgType = 4  // Controller acknowledge secure connection
	pktClientTerminate pktMsgType = 5  // Client session terminated
	pktServerTerminate pktMsgType = 6  // Controller session terminated
	pktCannotCreate    pktMsgType = 7  // Controller cannot start new session
	pktApplication     pktMsgType = 32 // Omni-Link II application data message
)

type packet struct {
	seqnum  uint16     // sequence number, 1-65535 (rollover back to 1)
	msgtype pktMsgType // message type
	data    []byte     // variable length, optional message data
}

func (p *packet) preparePacket(sessionKey []byte) ([]byte, error) {
	buf := new(bytes.Buffer) // output buffer

	// Build the unencrypted byte sequence
	binary.Write(buf, binary.BigEndian, p.seqnum)
	binary.Write(buf, binary.BigEndian, p.msgtype)
	buf.WriteByte(0) // reserved byte position
	if sessionKey != nil {
		buf.Write(p.data)
	}

	// Don't need to encrypt certain message types, so we're done
	if p.msgtype == pktNoMessage || p.msgtype == pktReqNewSession ||
		p.msgtype == pktAckNewSession {
		return buf.Bytes(), nil
	}

	// Remaining types need encryption
	return encryptPacketData(sessionKey, buf.Bytes())
}
