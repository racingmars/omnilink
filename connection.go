// Copyright 2015 Matthew R. Wilson <mwilson@mattwilson.org>. All
// rights reserved. Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package omnilink

import (
	"net"
	"sync"
	"time"
)

type Omni struct {
	c          *net.TCPConn // Connection to Omni controller
	address    *net.TCPAddr // Address of Omni controller
	key        []byte       // AES key
	sessionKey []byte       // AES session key
	seqNum     uint16       // packet sequence number
	seqMutex   sync.Mutex   // protect sequence number
}

func Connect(host, port string, key []byte) (*Omni, error) {
	var omni Omni
	omni.key = key

	address, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	omni.address = address

	// Connect to the Omni controller
	c, err := net.DialTCP("tcp", nil, omni.address)
	if err != nil {
		if c != nil {
			c.Close()
		}
		return nil, err
	}

	omni.c = c
	omni.c.SetKeepAlivePeriod(time.Duration(30) * time.Second)
	omni.c.SetKeepAlive(true)

	return &omni, nil
}

func (omni *Omni) getSeqNum() uint16 {
	omni.seqMutex.Lock()
	omni.seqNum++
	if omni.seqNum > 65535 || omni.seqNum < 1 {
		omni.seqNum = 1 // wrap around to 1, not 0
	}
	n := omni.seqNum
	omni.seqMutex.Unlock()
	return n
}

func (omni *Omni) negotiate() error {
	// Send the "Request New Session" message
	pkt := &packet{seqnum: omni.getSeqNum(), msgtype: pktReqNewSession}
	msg, _ := pkt.preparePacket(nil)
	_, err := omni.c.Write(msg)

	if err != nil {
		return err
	}

	buf := make([]byte, 512)

	nn := 0
	// read at least 4 bytes:
	for nn < 4 {
		n, err := omni.c.Read(buf[nn:])
		//TODO: should we have a timeout here?
		if err != nil {
			return err
		}
		nn += n
	}
	return nil
}
