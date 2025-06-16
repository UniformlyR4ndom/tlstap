package main

import (
	"flag"
	"log"

	"tlstap/test"
)

func main() {
	optListen := flag.String("l", "", "listen endpoint (e.g. 127.0.0.1:8000)")
	optConnect := flag.String("c", "", "connect endpoint (e.g. 127.0.0.1:9000)")
	optBufSize := flag.Int("bs", 4096, "buffer size")
	optMaxHoldMs := flag.Int("maxhold", 1000, "maximum hold time (in ms)")
	flag.Parse()

	if *optListen == "" {
		log.Fatal("Listen address must be provided")
	}

	if *optConnect == "" {
		log.Fatal("Connect address must be provided")
	}

	if *optBufSize <= 0 {
		log.Fatal("Buffer size must be positive")
	}

	if *optMaxHoldMs <= 0 {
		log.Fatal("Maximum hold time must be positive")
	}

	bp := test.NewBufferProxy(*optListen, *optConnect, *optBufSize, *optMaxHoldMs)
	bp.Start()
}
