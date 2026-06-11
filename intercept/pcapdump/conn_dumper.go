package pcapdump

import (
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

const (
	maxPayloadIPv4 = 65535 - 20 - 20 // IPv4 header (20) + TCP header (20)
	maxPayloadIPv6 = 65535 - 40 - 20 // IPv6 header (40) + TCP header (20)
)

type ConnDumper struct {
	IPDown   net.IP
	IPUp     net.IP
	PortDown uint16
	PortUp   uint16

	seqDown uint32
	seqUp   uint32
	ipv4    bool

	seqMu   sync.Mutex
	writerMu *sync.Mutex
}

func NewConnDumper(ipDown, ipUp net.IP, portDown, portUp uint16, writerMu *sync.Mutex) (*ConnDumper, error) {
	d := &ConnDumper{
		PortDown: portDown,
		PortUp:   portUp,
		writerMu: writerMu,
	}

	if ipDown.To4() != nil && ipUp.To4() != nil {
		d.ipv4 = true
		d.IPDown = ipDown.To4()
		d.IPUp = ipUp.To4()
	} else {
		d.IPDown = ipDown.To16()
		d.IPUp = ipUp.To16()
	}

	return d, nil
}

func (e *ConnDumper) maxPayload() int {
	if e.ipv4 {
		return maxPayloadIPv4
	}
	return maxPayloadIPv6
}

func (e *ConnDumper) WritePacketUp(w *pcapgo.Writer, payload []byte) error {
	return e.writeChunked(w, e.IPDown, e.IPUp, e.PortDown, e.PortUp, true, payload)
}

func (e *ConnDumper) WritePacketDown(w *pcapgo.Writer, payload []byte) error {
	return e.writeChunked(w, e.IPUp, e.IPDown, e.PortUp, e.PortDown, false, payload)
}

func (e *ConnDumper) writeChunked(w *pcapgo.Writer, srcIP, dstIP net.IP, srcPort, dstPort uint16, up bool, payload []byte) error {
	max := e.maxPayload()
	for len(payload) > 0 {
		n := len(payload)
		if n > max {
			n = max
		}
		chunk := payload[:n]
		payload = payload[n:]

		var seq, ack uint32
		e.seqMu.Lock()
		if up {
			seq, ack = e.seqUp, e.seqDown
			e.seqUp += uint32(n)
		} else {
			seq, ack = e.seqDown, e.seqUp
			e.seqDown += uint32(n)
		}
		e.seqMu.Unlock()

		if err := e.writePacket(w, srcIP, dstIP, srcPort, dstPort, seq, ack, chunk); err != nil {
			return err
		}
	}
	return nil
}

func (e *ConnDumper) writePacket(w *pcapgo.Writer, srcIP, dstIP net.IP, srcPort, dstPort uint16, seq, ack uint32, payload []byte) error {
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     seq,
		Ack:     ack,
		ACK:     true,
		Window:  65535,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	var err error
	if e.ipv4 {
		ip := &layers.IPv4{
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolTCP,
			SrcIP:    srcIP,
			DstIP:    dstIP,
		}
		tcp.SetNetworkLayerForChecksum(ip)
		err = gopacket.SerializeLayers(buf, opts, ip, tcp, gopacket.Payload(payload))
	} else {
		ip := &layers.IPv6{
			Version:    6,
			HopLimit:   64,
			NextHeader: layers.IPProtocolTCP,
			SrcIP:      srcIP,
			DstIP:      dstIP,
		}
		tcp.SetNetworkLayerForChecksum(ip)
		err = gopacket.SerializeLayers(buf, opts, ip, tcp, gopacket.Payload(payload))
	}

	if err != nil {
		return err
	}

	data := buf.Bytes()
	e.writerMu.Lock()
	defer e.writerMu.Unlock()
	return w.WritePacket(gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(data),
		Length:        len(data),
	}, data)
}
