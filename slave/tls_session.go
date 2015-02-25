package slave

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
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
	var tmpRecord TlsRecord
	for len(data) > 0 {
		if err := tmpRecord.DecodeTlsRecord(data); err != nil {
			break
		}
		session.records = append(session.records, tmpRecord)
		data = data[5+tmpRecord.length:]
	}
	if payload, found := session.extractCertificateFromSession(); found {
		handleCertificateMessage(payload)
	}

}

type PinObject struct {
	DNSNames    []string `json:"dnsnames"`
	SubjectHash []byte   `json:"subject"`
	IssuerHash  []byte   `json:"issuer"`
}

func sendCertificateToServer(c *CertMessage) {
	var pin PinObject = PinObject{}
	siteCert := c.certChain[0]
	issuerCert := c.certChain[1]
	hasher := sha256.New()
	hasher.Write(siteCert.RawSubjectPublicKeyInfo)
	pin.DNSNames = siteCert.DNSNames
	pin.SubjectHash = hasher.Sum(nil)
	hasher.Reset()
	hasher.Write(issuerCert.RawSubjectPublicKeyInfo)
	pin.IssuerHash = hasher.Sum(nil)
	url := "http://localhost:8080/pins"
	buf, err := json.Marshal(pin)
	if err != nil {
		return
	}
	body := bytes.NewBuffer(buf)
	//fmt.Println(body)
	r, _ := http.Post(url, "application/json", body)
	response, _ := ioutil.ReadAll(r.Body)
	fmt.Println(string(response))

}

func handleCertificateMessage(payload []byte) {
	var cert *CertMessage = new(CertMessage)
	cert.payload = payload
	if err := cert.ParseCertMessage(); err == nil {
		// launch a goroutine to process the data and send it to the master
		go sendCertificateToServer(cert)
	}
}

func (session *TlsSession) extractCertificateFromSession() ([]byte, bool) {
	//Here we have to look those message with mesageType 11. Those messages
	//mean Certificate but also we have to look after a serverHelloMessage
	//since sometimes after this message comes a certificate and we do not
	//want to lose anyone
	for i := range session.records {
		record := session.records[i]
		if record.contentType == TLS_HANDSHAKE {
			// We can follow is likely that will find a certificate
			var hrec HandshakeRecord
			if err := hrec.DecodeHandshakeRecord(record.data); err == nil {
				if hrec.msgType == CERTIFICATE {
					return hrec.messageData, true
				} else if hrec.msgType == SERVER_HELLO {
					data := record.data[4+hrec.handshakeLength:]
					if len(data) > 0 {
						var certRecord HandshakeRecord
						if err := certRecord.DecodeHandshakeRecord(data); err == nil {
							return certRecord.messageData, true
						}
					}
				}
			}

		}
	}
	return nil, false

}
