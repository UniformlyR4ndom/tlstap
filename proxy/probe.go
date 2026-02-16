package tlstap

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"log"
)

const maxFailures = 5

type probeResult struct {
	// negative vaues represent a failure counter
	// value > 0 represents success
	state int

	proto string
}

type Prober struct {
	cache        map[[32]byte]probeResult
	cacheEnabled bool
}

func NewProber(cacheEnabled bool) Prober {
	return Prober{
		cache:        make(map[[32]byte]probeResult),
		cacheEnabled: cacheEnabled,
	}
}

func (p *Prober) Probe(connect string, baseConfig *tls.Config, protos []string) (proto string, cached bool, err error) {
	h := hashProtos(protos)
	entry, ok := p.cache[h]

	if !ok {
		proto, err := doProbe(connect, baseConfig, protos)
		if err == nil {
			p.storeCache(h, probeResult{state: 1, proto: proto})
		} else {
			p.storeCache(h, probeResult{state: -1})
		}

		return proto, false, err
	}

	if entry.state > 0 {
		return entry.proto, true, nil
	}

	if fails := -entry.state; fails >= maxFailures {
		return "", false, fmt.Errorf("too many failed probes (%d), giving up for protocols %v", fails, protos)
	}

	proto, err = doProbe(connect, baseConfig, protos)
	if err == nil {
		p.storeCache(h, probeResult{state: 1, proto: proto})
	} else {
		r := p.cache[h]
		p.storeCache(h, probeResult{state: r.state - 1})
	}

	return proto, false, err
}

func (p *Prober) storeCache(k [32]byte, v probeResult) {
	if p.cacheEnabled {
		p.cache[k] = v
	}
}

func doProbe(connect string, baseConfig *tls.Config, protos []string) (string, error) {
	config := baseConfig.Clone()
	config.NextProtos = protos
	config.GetClientCertificate = nil
	var selected string
	config.VerifyConnection = func(cs tls.ConnectionState) error {
		selected = cs.NegotiatedProtocol
		log.Printf("cs - suite: %s", tls.CipherSuiteName(cs.CipherSuite))
		log.Printf("cs - version: %s", tls.VersionName(cs.Version))
		return fmt.Errorf("aborting probe connection")
	}

	conn, err := tls.Dial("tcp", connect, config)
	if err == nil {
		conn.Handshake()
		conn.Close()
	}

	if selected != "" {
		err = nil
	}

	return selected, err
}

func hashProtos(protos []string) [32]byte {
	lenBuf := make([]byte, 8)
	hasher := sha256.New()
	for _, p := range protos {
		binary.LittleEndian.PutUint64(lenBuf, uint64(len(p)))
		hasher.Write(lenBuf)
		hasher.Write([]byte(p))
	}

	return [32]byte(hasher.Sum(nil))
}
