// Copyright 2015 Matthew R. Wilson <mwilson@mattwilson.org>. All
// rights reserved. Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package omnilink

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// The Omni structure represents an instance of a connection to an Omni
// controller.
type Omni struct {
	c          *net.TCPConn // Connection to Omni controller
	address    *net.TCPAddr // Address of Omni controller
	key        []byte       // AES key
	sessionID  []byte       // Session ID
	sessionKey []byte       // AES session key
	seqNum     uint16       // packet sequence number
	seqMutex   sync.Mutex   // protect sequence number
	buf        []byte       // incoming data buffer
}

// Connect this Omni instance to the controller specified in the parameters.
func Connect(host, port string, key []byte) (*Omni, error) {
	var omni Omni
	omni.key = key
	omni.buf = make([]byte, 512)

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

	err = omni.negotiateNewSession()
	if err != nil {
		omni.c.Close()
		return nil, err
	}

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

func (omni *Omni) negotiateNewSession() error {
	// Send the "Request New Session" message
	pkt := &packet{seqnum: omni.getSeqNum(), msgtype: pktReqNewSession}
	msg, _ := pkt.preparePacket(nil)
	_, err := omni.c.Write(msg)

	if err != nil {
		omni.c.Close()
		return err
	}

	nn := 0
	// read at least 4 bytes:
	for nn < 4 {
		n, err := omni.c.Read(omni.buf[nn:])
		//TODO: should we have a timeout here?
		if err != nil {
			omni.c.Close()
			return err
		}
		nn += n
	}

	if omni.buf[0] != msg[0] || omni.buf[1] != msg[1] {
		omni.c.Close()
		return errors.New("New Session response seq num doesn't match request.")
	}

	if pktMsgType(omni.buf[2]) != pktAckNewSession {
		omni.c.Close()
		return fmt.Errorf("New Session response was wrong type: %x.", omni.buf[2])
	}

	// Should have a good response, let's read the next 7 bytes for the data
	for nn < 11 {
		n, err := omni.c.Read(omni.buf[nn:])
		if err != nil {
			omni.c.Close()
			return err
		}
		nn += n
	}

	var keyArray [16]byte
	var sessionArray [5]byte

	copy(keyArray[:], omni.key)
	copy(sessionArray[:], omni.buf[6:11])
	omni.sessionID = sessionArray[:]

	sessionKey := deriveSessionKey(keyArray, sessionArray)
	if len(sessionKey) != 16 {
		omni.c.Close()
		return errors.New("Bad session key length.")
	}
	omni.sessionKey = sessionKey[:]

	// Now send the Request Secure Session command
	pkt = &packet{seqnum: omni.getSeqNum(), msgtype: pktReqSecure,
		data: omni.sessionID}
	msg, _ = pkt.preparePacket(omni.sessionKey)
	_, err = omni.c.Write(msg)

	if err != nil {
		omni.c.Close()
		return err
	}

	nn = 0
	for nn < 4 {
		n, err := omni.c.Read(omni.buf[nn:])
		//TODO: should we have a timeout here?
		if err != nil {
			omni.c.Close()
			return err
		}
		nn += n
	}

	if omni.buf[0] != msg[0] || omni.buf[1] != msg[1] {
		omni.c.Close()
		return errors.New("New Secure response seq num doesn't match request.")
	}

	if pktMsgType(omni.buf[2]) != pktAckSecure {
		omni.c.Close()
		return fmt.Errorf("Secure Session response was wrong type: %x.", omni.buf[2])
	}

	// Good response, let's read 16 bytes of encrypted data
	for nn < 20 {
		n, err := omni.c.Read(omni.buf[nn:])
		if err != nil {
			omni.c.Close()
			return err
		}
		nn += n
	}

	unenc, err := decryptPacketBlock(omni.sessionKey, omni.buf[0:2], omni.buf[4:20])
	if err != nil {
		omni.c.Close()
		return err
	}

	if bytes.Compare(unenc[0:5], omni.sessionID) != 0 {
		omni.c.Close()
		return errors.New("Session ID in secure session response does not match.")
	}

	// I think we should have a good secure connection established now.

	return nil
}

func (omni *Omni) readEncryptedPacket() *packet {

	return nil
}

func (omni *Omni) Close() {
	omni.c.Close()
}
