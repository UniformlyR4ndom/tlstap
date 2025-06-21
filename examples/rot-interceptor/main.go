package main

import (
	"encoding/json"
	"fmt"
	"log"
	"unicode"

	"tlstap/cli"
	interceptors "tlstap/interceptors"
	"tlstap/logging"
	tlstap "tlstap/proxy"
)

type RotConfig struct {
	Rot       int `json:"rot"`
	MinSeqLen int `json:"min-len"`
}

type RotInterceptor struct {
	// implements unused boilerplate (Init, Finalize, ConnectionEstablished, ConnectionTerminated)
	interceptors.NullInterceptor

	rot          int
	minSeqLength int
	logger       *logging.Logger
}

func (i *RotInterceptor) Intercept(info *tlstap.ConnInfo, data []byte) ([]byte, error) {
	runes := []rune(string(data))
	for {
		s, e := nextPrintableSeq(runes, i.minSeqLength)
		if s < 0 {
			break
		}

		for j := 0; j <= e; j++ {
			data[j] = byte(rotLetter(runes[j], i.rot))
		}

		runes = runes[e+1:]
	}

	i.logger.Info("%s <-> %s: (len: %d) %s", info.SrcEndpoint, info.DstEndpoint, len(data), string(data))
	return data, nil
}

func nextPrintableSeq(runes []rune, minLen int) (start, length int) {
	for s := 0; s < len(runes); s++ {
		if !unicode.IsPrint(runes[s]) {
			continue
		}

		end := len(runes) - 1
		for j := s + 1; j < len(runes); j++ {
			if !unicode.IsPrint(runes[j]) {
				end = j - 1
				break
			}
		}

		if end-s+1 >= minLen {
			return s, end
		}

		s = end + 1
	}

	return -1, 0
}

func rotLetter(r rune, rot int) rune {
	switch {
	case r >= 'A' && r <= 'Z':
		return rune(int('A') + (int(r-'A')+rot)%26)
	case r >= 'a' && r <= 'z':
		return rune(int('a') + (int(r-'a')+rot)%26)
	default:
		return r
	}
}

func configCallback(config tlstap.ProxyConfig, iConfig tlstap.InterceptorConfig, logger *logging.Logger) (tlstap.Interceptor, error) {
	if iConfig.Name != "rot" {
		return nil, fmt.Errorf("unexpected interceptor name: %s", iConfig.Name)
	}

	var rConf RotConfig
	checkFatal(json.Unmarshal(iConfig.ArgsJson, &rConf))

	i := RotInterceptor{
		rot:          rConf.Rot,
		minSeqLength: rConf.MinSeqLen,
		logger:       logger,
	}

	return &i, nil
}

func main() {
	cli.StartWithCli(configCallback)
}

func checkFatal(err error) {
	if err != nil {
		log.Fatalf("Fatal error: %v", err)
	}
}
