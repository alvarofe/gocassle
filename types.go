package gocassle

import (
	"encoding/binary"
)

const (
	TLS_HANDSHAKE   = 22
	TLS_ALERT       = 21
	TLS_CIPHERSPEC  = 20
	TLS_APPLICATION = 23
	TLS_HEARBEAT    = 24
)

const (
	HELLO_REQUEST       = 0
	CLIENT_HELLO        = 1
	SERVER_HELLO        = 2
	NEW_SESSION_TICKET  = 4
	CERTIFICATE         = 11
	SERVER_KEY_EXCHANGE = 12
	CERTIFICATE_REQUEST = 13
	SERVER_HELLO_DONE   = 14
	CERTIFICATE_VERIFY  = 15
	CLIENT_KEY_EXCHANGE = 16
	FINISHED            = 20
)

const (
	SSL30 = 0
	TLS10 = 1
	TLS11 = 2
	TLS12 = 3
)

//TODO improve error handling
type errorString struct {
	s string
}

func (e *errorString) Error() string {
	return e.s
}

type TlsRecord struct {
	contentType uint8
	tlsVersion  uint8
	length      uint16
	data        []byte
}

type TlsHanshakeRecord struct {
	msgType         uint8
	handshakeLength uint32
	messageData     []byte
}

func (hrec *TlsHanshakeRecord) DecodeRecord(data []byte) error {
}

func (rec *TlsRecord) DecodeRecord(data []byte) error {
	rec.contentType = uint8(data[0])
	major := uint8(data[1])
	minor := uint8(data[2])
	if major != 3 {
		return &errorString{"bad record"}
	} else {
		if minor == 0 {
			rec.tlsVersion = SSL30
		} else if minor == 1 {
			rec.tlsVersion = TLS10
		} else if minor == 2 {
			rec.tlsVersion = TLS11
		} else if minor == 3 {
			rec.tlsVersion = TLS12
		}
	}
	rec.length = binary.LittleEndian.Uint16(data[3:5])
	rec.data = data[6:]
	return nil
}
