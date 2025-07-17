package main

import (
	"encoding/hex"
	"log"
	"tlstap/cli"
	"tlstap/intercept"
)

func main() {
	data := []byte("hello proxy")
	info := intercept.DataFrame{
		Size:   uint32(len(data)),
		ConnId: 17,
	}

	s := hex.EncodeToString(info.ToBytes())
	log.Printf("%s%s", s, hex.EncodeToString(data))

	cli.StartWithCli(nil)
}
