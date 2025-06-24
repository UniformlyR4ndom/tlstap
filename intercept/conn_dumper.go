package intercept

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type IPType byte

const (
	IPv4 = 4
	IPv6 = 6
)

const (
	EtherTypeIPv4 = 0x0800
	EtherTypeIPv6 = 0x86dd
)

const (
	TcpCRw = 0x80
	TcpECE = 0x40
	TcpURG = 0x20
	TcpACK = 0x10
	TcpPSH = 0x08
	TcpRST = 0x04
	TcpSYN = 0x02
	TcpFIN = 0x01
)

type ConnDumper struct {
	IPDown net.IP
	IPUp   net.IP

	macDown [6]byte
	macUp   [6]byte

	ipDown    []byte
	ipUp      []byte
	ipVersion byte

	PortDown uint16
	PortUp   uint16

	seqDown uint32
	seqUp   uint32

	lock sync.Mutex
}

// Create a new ConnDumper with the given source and destination MACs, IPs and TCP ports
func NewConnDumper(macDown, macUp [6]byte, ipDown, ipUp net.IP, portDown, portUp uint16) (*ConnDumper, error) {
	e := ConnDumper{
		IPDown:   ipDown,
		IPUp:     ipUp,
		macDown:  macDown,
		macUp:    macUp,
		PortDown: portDown,
		PortUp:   portUp,
	}

	ipAv4 := ipDown.To4()
	ipBv4 := ipUp.To4()
	switch {
	case ipAv4 == nil && ipBv4 == nil:
		// both are IPv6 addresses
		ipAv6 := ipDown.To16()
		if ipAv6 == nil {
			return nil, fmt.Errorf("invalid IP address: %v", ipDown)
		}

		ipBv6 := ipUp.To16()
		if ipBv6 == nil {
			return nil, fmt.Errorf("invalid IP address: %v", ipUp)
		}

		e.ipDown = ipAv6
		e.ipUp = ipBv6
		e.ipVersion = IPv6
	case ipAv4 != nil && ipBv4 != nil:
		// both are Ipv4 addresses
		e.ipDown = ipAv4
		e.ipUp = ipBv4
		e.ipVersion = IPv4
	case ipAv4 != nil && ipBv4 == nil:
		ipBv6 := ipUp.To16()
		if ipBv6 == nil {
			return nil, fmt.Errorf("invalid IP address: %v", ipUp)
		}

		e.ipDown = mapIPv4([4]byte(ipAv4))
		e.ipUp = ipBv6
		e.ipVersion = IPv6
	case ipAv4 == nil && ipBv4 != nil:
		ipAv6 := ipDown.To16()
		if ipAv6 == nil {
			return nil, fmt.Errorf("invalid IP address: %v", ipDown)
		}

		e.ipDown = ipAv6
		e.ipUp = mapIPv4([4]byte(ipBv4))
		e.ipVersion = IPv6
	}

	return &e, nil
}

// Write a single packet headed upstream to the given writer
func (e *ConnDumper) WritePacketUp(w *pcapgo.Writer, tcpPayload []byte) error {
	e.lock.Lock()
	seq := e.seqUp
	ack := e.seqDown
	e.seqUp += uint32(len(tcpPayload))
	e.lock.Unlock()

	return e.writePacket(w, e.macDown, e.macUp, e.ipDown, e.ipUp, e.PortDown, e.PortUp, seq, ack, tcpPayload)
}

// Write a single packet headed downstream to the given writer
func (e *ConnDumper) WritePacketDown(w *pcapgo.Writer, tcpPayload []byte) error {
	e.lock.Lock()
	seq := e.seqDown
	ack := e.seqUp
	e.seqDown += uint32(len(tcpPayload))
	e.lock.Unlock()

	return e.writePacket(w, e.macUp, e.macDown, e.ipUp, e.ipDown, e.PortUp, e.PortDown, seq, ack, tcpPayload)
}

// Write a single network packet to the given writer
func (e *ConnDumper) writePacket(w *pcapgo.Writer, srcMac, dstMac [6]byte, srcIp, dstIp []byte, srcPort, dstPort uint16, seq, ack uint32, tcpPayload []byte) error {
	p := gopacket.NewPacket(e.buildPacket(srcMac, dstMac, srcIp, dstIp, srcPort, dstPort, seq, ack, tcpPayload), layers.LayerTypeEthernet, gopacket.Default)
	info := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(p.Data()),
		Length:        len(p.Data()),
	}

	return w.WritePacket(info, p.Data())
}

// Build a single network packet including ethernet header, IP header, TCP header and TCP payload
func (e *ConnDumper) buildPacket(srcMac, dstMac [6]byte, srcIp, dstIp []byte, srcPort, dstPort uint16, seq, ack uint32, tcpPayload []byte) []byte {
	tcpHeader := buildTcpHeader(srcPort, dstPort, seq, ack, TcpACK)
	ipPayloadLength := len(tcpHeader) + len(tcpPayload)
	var ipHeader []byte
	var ethHeader []byte
	switch e.ipVersion {
	case IPv4:
		ipHeader = buildIPv4Header([4]byte(srcIp), [4]byte(dstIp), uint16(ipPayloadLength))
		ethHeader = buildEthHeader(srcMac, dstMac, EtherTypeIPv4)
	case IPv6:
		ipHeader = buildIPv6Header([16]byte(srcIp), [16]byte(dstIp), uint16(ipPayloadLength))
		ethHeader = buildEthHeader(srcMac, dstMac, EtherTypeIPv6)
	default:
		panic(fmt.Sprintf("invalid IP version: %d", e.ipVersion))
	}

	return assemblePacket(ethHeader, ipHeader, tcpHeader, tcpPayload)
}

// Assemble ethernet, IP and TCP header together with payload to a single byte slice
func assemblePacket(ethHeader, ipHeader, tcpHeader, data []byte) []byte {
	packet := make([]byte, 0, len(ethHeader)+len(ipHeader)+len(tcpHeader)+len(data))
	packet = append(packet, ethHeader...)
	packet = append(packet, ipHeader...)
	packet = append(packet, tcpHeader...)
	packet = append(packet, data...)
	return packet
}

// Build ehternet header form given source and destination MAC addresses as well as ether type
func buildEthHeader(srcMac, dstMac [6]byte, etherType uint16) []byte {
	ethHeader := make([]byte, 0, 14)
	ethHeader = append(ethHeader, dstMac[:]...)
	ethHeader = append(ethHeader, srcMac[:]...)
	ethHeader, _ = binary.Append(ethHeader, binary.BigEndian, etherType)
	return ethHeader
}

// Build anIPv4 header from given source and destination IP addresses as well as payload length
func buildIPv4Header(srcIp, dstIp [4]byte, payloadLength uint16) []byte {
	ipHeader := []byte{
		0x45,       // version (4 bit) and IHL (4 bit)
		0x00,       // ToS
		0x00, 0x00, // total length (will be filled in later)
		0x24, 0x1d, // identification
		0x40, 0x00, // flags (3 bit), fragment offset (13 bit)
		0x40,       // TTL (64)
		0x06,       // protocol (0x06 for TCP)
		0x00, 0x00, // header checksum (left all zero)
	}

	ipHeader = append(ipHeader, srcIp[:]...) // source IP
	ipHeader = append(ipHeader, dstIp[:]...) // destination IP
	totalLength := 20 + payloadLength
	binary.Encode(ipHeader[2:], binary.BigEndian, totalLength)
	return ipHeader
}

// Build anIPv6 header from given source and destination IP addresses as well as payload length
func buildIPv6Header(srcIp, dstIp [16]byte, payloadLength uint16) []byte {
	ipHeader := []byte{
		0x60,       // version (4 bit), traffic class part 1 (4 bit)
		0x00,       // traffic class part 2 (4 bit), flow label part 1 (4 bit)
		0x00, 0x00, // flow label part 2 (16 bit)
		0x00, 0x00, // payload length (will be filled in later)
		0x06, // next header (0x06 for TCP)
		0x40, // hop limit (64)
	}

	ipHeader = append(ipHeader, srcIp[:]...)
	ipHeader = append(ipHeader, dstIp[:]...)
	binary.Encode(ipHeader[4:], binary.BigEndian, payloadLength)
	return ipHeader
}

// Build a TCP header with given ports, sequence and acknowledgement numbers and flags
func buildTcpHeader(srcPort, dstPort uint16, seq, ack uint32, flags byte) []byte {
	header := []byte{
		0x00, 0x00, // source port
		0x00, 0x00, // destination port
		0x00, 0x00, 0x00, 0x00, // sequence number
		0x00, 0x00, 0x00, 0x00, // acknowledgment number
		0x50,       // data offset (+ 4 reserved bits)
		flags,      // flags (8 bit)
		0x02, 0x00, // windows size (512)
		0x00, 0x00, // checksum (left all zero)
		0x00, 0x00, // urgent pointer
	}

	binary.Encode(header, binary.BigEndian, srcPort)     // source port
	binary.Encode(header[2:], binary.BigEndian, dstPort) // destination port
	binary.Encode(header[4:], binary.BigEndian, seq)     // sequence number
	binary.Encode(header[8:], binary.BigEndian, ack)     // acknowledgment number
	return header
}

// Map an IPv4 address to its corresponding IPv6 address
func mapIPv4(ipv4 [4]byte) []byte {
	ipv6 := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0}
	copy(ipv6[12:], ipv4[:])
	return ipv6[:]
}
