package gocassle

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/miekg/pcap"
)

var channelData chan map[uint32][]byte = make(chan map[uint32][]byte)

func StartSniffing(device *string, port *string) {

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	handler, err := pcap.OpenLive(*device, int32(1600), true, 500)
	if handler == nil {
		fmt.Fprintf(os.Stderr, "Device %s is not available", *device, err)
		return
	}
	defer handler.Close()

	go func() {
		for sig := range c {
			log.Printf("\n\ncaptured %v, stopping sniffer and exiting..\n", sig)
			stats, _ := handler.Getstats()
			fmt.Printf(
				"Packet Received %d, Packets Dropped %d\n",
				stats.PacketsReceived, stats.PacketsDropped)
			os.Exit(1)
		}
	}()

	//This goroutine will process the tls session data
	//Is a bucle that wait to receive data
	go ProcessSessionData(channelData)

	expr := "tcp src port " + string(*port)

	if ferr := handler.SetFilter(expr); ferr != nil {
		fmt.Fprintf(os.Stderr, "Bad filter")
		return
	}

	for pkt, r := handler.NextEx(); r >= 0; pkt, r = handler.NextEx() {
		if r == 0 {
			// timeout, continue
			continue
		}
		handlePacket(pkt)
	}
	fmt.Fprintln(os.Stderr, "tcpdump:", handler.Geterror())

}

func handlePacket(pkt *pcap.Packet) {
	pkt.Decode()
	if len(pkt.Headers) == 2 {
		if ipHdr, ok := pkt.Headers[0].(*pcap.Iphdr); ok {
			if tcpHdr, ok := pkt.Headers[1].(*pcap.Tcphdr); ok {
				key := ipHdr.SrcAddr() + ":" + ipHdr.DestAddr() + ":" + strconv.Itoa(int(tcpHdr.SrcPort)) + ":" + strconv.Itoa(int(tcpHdr.DestPort))
				flagTcp := tcpHdr.Flags
				payload := pkt.Payload
				seq := tcpHdr.Seq
				reasemble(flagTcp, payload, key, seq)
			}
		}
	}

}

func isInitialRecord(data []byte) bool {
	if len(data) > 0 {
		contentType := uint8(data[0])
		msgType := uint8(data[5])
		major := uint8(data[1])
		minor := uint8(data[2])
		tlsVersion := 0
		if major != 3 {
			return false
		} else {
			if minor == 0 {
				tlsVersion = SSL30
			} else if minor == 1 {
				tlsVersion = TLS10
			} else if minor == 2 {
				tlsVersion = TLS11
			} else if minor == 3 {
				tlsVersion = TLS12
			}
		}

		if contentType == TLS_HANDSHAKE && msgType == SERVER_HELLO {
			return true
		} else if contentType == TLS_ALERT && tlsVersion >= TLS10 {
			return true
		}
	}
	return false

}

type dataTrack struct {
	psh_ack   int8
	recollect bool
	data      map[uint32][]byte
}

var tlsData map[string]*dataTrack = make(map[string]*dataTrack)

func reasemble(flags uint16, payload []byte, key string, seq uint32) {

	recollect := false

	if dataTrackRet, ok := tlsData[key]; !ok {
		recollect = false
	} else {
		recollect = dataTrackRet.recollect
	}

	if flags == pcap.TCP_ACK {
		if recollect {
			tlsData[key].data[seq] = payload
		} else if isInitialRecord(payload) {
			tlsData[key] = &dataTrack{0, true, map[uint32][]byte{seq: payload}}
		}

	}

	if flags == pcap.TCP_ACK|pcap.TCP_PSH {
		if recollect {
			if tlsData[key].psh_ack != 1 {
				tlsData[key].psh_ack += 1
				tlsData[key].data[seq] = payload
			} else {
				tlsData[key].data[seq] = payload
				channelData <- tlsData[key].data
				delete(tlsData, key)
			}
		}
	}
}
