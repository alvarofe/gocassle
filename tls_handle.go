package gocassle

import (
	"encoding/hex"
	"fmt"
	"sort"
)

func ProcessSessionData(tlsData chan map[uint32][]byte) {
	for {
		sessionData := new(TlsSessionData)
		sessionData.OrderData(<-tlsData)
	}
}

type TlsSessionData struct {
	data []byte
}

func (sessionData *TlsSessionData) OrderData(data map[uint32][]byte) {
	var keys []int
	for k := range data {
		keys = append(keys, int(k))
	}
	sort.Ints(keys)
	for _, k := range keys {
		sessionData.data = append(sessionData.data, data[uint32(k)]...)
	}
	fmt.Println(hex.Dump(sessionData.data))
}
