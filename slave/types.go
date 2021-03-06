package slave

import (
	"crypto/x509"
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

type HandshakeRecord struct {
	msgType         uint8
	handshakeLength uint32
	messageData     []byte
}

func (hrec *HandshakeRecord) DecodeHandshakeRecord(data []byte) error {
	if len(data) > 5 {
		hrec.msgType = uint8(data[0])
		length := binary.BigEndian.Uint32(data[1:5]) >> 8
		if int(length) > len(data) {
			return &errorString{"Record to short"}
		}
		hrec.handshakeLength = length
		hrec.messageData = data[4 : 4+length]
		return nil
	}
	return &errorString{"Record too short"}
}

func (rec *TlsRecord) DecodeTlsRecord(data []byte) error {
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
	rec.length = binary.BigEndian.Uint16(data[3:5])
	if int(rec.length) > len(data) {
		return &errorString{"little data to process"}
	}
	rec.data = data[5 : 5+rec.length]
	return nil
}

type CertMessage struct {
	payload   []byte
	certChain []*x509.Certificate
}

func (c *CertMessage) ParseCertMessage() error {
	payload := c.payload
	payload = payload[3:]
	for len(payload) > 0 {
		certLength := binary.BigEndian.Uint32(payload[0:4]) >> 8
		cert, err := x509.ParseCertificate(payload[3 : 3+certLength])
		if err != nil {
			return err
		}
		c.certChain = append(c.certChain, cert)
		payload = payload[3+certLength:]
	}
	return nil
}
