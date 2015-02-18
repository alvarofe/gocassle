package gocassle

import (
	"encoding/hex"
	"fmt"
	"sort"
)

func ProcessSessionData(tlsData chan map[uint32][]byte) {
	for {
		session := new(TlsSession)
		session.ProcessTlsData(<-tlsData)
	}
}

type TlsSession struct {
	records []TlsRecord
}

func (session *TlsSession) ProcessTlsData(data map[uint32][]byte) {
	var keys []int
	var payload []byte
	for k := range data {
		keys = append(keys, int(k))
	}
	sort.Ints(keys)
	for _, k := range keys {
		payload = append(payload, data[uint32(k)]...)
	}
	session.SplitTlsRecords(payload)
}

func (session *TlsSession) SplitTlsRecords(data []byte) {
	var auxRecord TlsRecord
	for len(data) > 0 {
		if err := auxRecord.DecodeTlsRecord(data); err != nil {
			break
		}
		session.records = append(session.records, auxRecord)
		data = data[5+auxRecord.length:]
	}
	session.extractCertificateFromSession()
	/*for i := range session.records {*/
	//fmt.Println(hex.Dump(session.records[i].data))
	/*}*/
}

func (session *TlsSession) extractCertificateFromSession() {
	//Here we have to look those message with mesageType 11. Those messages
	//mean Certificate but also we have to look after a serverHelloMessage
	//since sometimes after this message comes a certificate and we do not
	//want to lose anyone
	for i := range session.records {
		record := session.records[i]
		if record.contentType == TLS_HANDSHAKE {
			// We can follow is likely that will find a certificate
			fmt.Println("ENTRO")
			var hrec HanshakeRecord
			if err := hrec.DecodeHandshakeRecord(record.data); err == nil {

				fmt.Println("ENTRO2")
				if hrec.msgType == CERTIFICATE {
					fmt.Println(hex.Dump(hrec.messageData))
				} else if hrec.msgType == SERVER_HELLO {
					fmt.Println(hex.Dump(hrec.messageData))
				}
			}

		}
	}
}
