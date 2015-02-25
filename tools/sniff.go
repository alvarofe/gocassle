package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/alvarofe/gocassle/slave"
)

var (
	device = flag.String("i", "en1", "Interface")
	port   = flag.String("p", "443", "Port")
	help   = flag.Bool("h", false, "Help")
)

func init() {

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [-i interface] [-p port]\n", os.Args[0])
		os.Exit(1)
	}

	flag.Parse()
}

func main() {

	if *help {
		flag.Usage()
		os.Exit(0)
	}
	slave.StartSniffing(device, port)
}
