package model

import (
	"github.com/ant0ine/go-json-rest/rest"
	"net/http"
	"sync"
)

type PinDB struct {
	Id          string `json:"dnsname"`
	SubjectHash []byte `json:"hash_subject_spki"`
	IssuerHash  []byte `json:"hash_issuer_spki"`
}

//This object will be which the client send us once is detected a certificate
type PinObject struct {
	DNSNames    []string `json:"dnsnames"`
	SubjectHash []byte   `json:"subject"`
	IssuerHash  []byte   `json:"issuer"`
}

type DB struct {
	sync.RWMutex
	Store []*PinDB
}

var db DB = DB{}

func GetAllPins(w rest.ResponseWriter, r *rest.Request) {
	db.RLock()
	pins := make([]PinDB, len(db.Store))
	i := 0
	for _, pin := range db.Store {
		pins[i] = *pin
		i++
	}
	db.RUnlock()
	w.WriteJson(&pins)

}

func PostPin(w rest.ResponseWriter, r *rest.Request) {
	u := PinObject{}
	err := r.DecodeJsonPayload(&u)
	if err != nil {
		rest.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	db.Lock()
	for i := range u.DNSNames {
		db.Store = append(db.Store, &PinDB{u.DNSNames[i], u.SubjectHash, u.IssuerHash})
	}
	db.Unlock()
	w.WriteJson(&u)
}
