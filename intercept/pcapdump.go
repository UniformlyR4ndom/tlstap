package intercept

import (
	"errors"
	"net"
	"os"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	tlstap "tlstap/proxy"
)

type PcapConfig struct {
	FilePath string `json:"file"`
	Truncate bool   `json:"truncate"`
}

// PcapDumpInterceptor writes all data passing through it to a pcap file
type PcapDumpInterceptor struct {
	filePath string
	truncate bool

	pcapFile *os.File
	writer   *pcapgo.Writer

	dumpers map[uint32]*ConnDumper
}

func NewPcapDumpInterceptor(path string, trucnate bool) PcapDumpInterceptor {
	return PcapDumpInterceptor{
		filePath: path,
		truncate: trucnate,
		dumpers:  make(map[uint32]*ConnDumper),
	}
}

func (i *PcapDumpInterceptor) Init(addr net.TCPAddr) error {
	writeHeader := i.truncate
	if _, err := os.Stat((i.filePath)); errors.Is(err, os.ErrNotExist) {
		writeHeader = true
	}

	opt := os.O_APPEND
	if i.truncate {
		opt = os.O_TRUNC
	}

	f, err := os.OpenFile(i.filePath, opt|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}

	i.pcapFile = f
	i.writer = pcapgo.NewWriter(f)
	if writeHeader {
		return i.writer.WriteFileHeader(65535, layers.LinkTypeEthernet)
	}

	return nil
}

func (i *PcapDumpInterceptor) Finalize(addr net.TCPAddr) {
	i.pcapFile.Close()
}

func (i *PcapDumpInterceptor) ConnectionEstablished(info *tlstap.ConnInfo) error {
	if _, ok := i.dumpers[info.ConnID]; ok {
		return nil
	}

	mac := [6]byte{0x00, 0xaa, 0xaa, 0xaa, 0xaa, 0x00}
	dumper, err := NewConnDumper(mac, mac, info.SrcIP, info.DstIP, info.SrcPort, info.DstPort)
	if err != nil {
		return err
	}

	i.dumpers[info.ConnID] = dumper
	return nil
}

func (i *PcapDumpInterceptor) ConnectionTerminated(info *tlstap.ConnInfo) error {
	delete(i.dumpers, info.ConnID)
	return nil
}

func (i *PcapDumpInterceptor) Intercept(info *tlstap.ConnInfo, data []byte) ([]byte, error) {
	dumper, ok := i.dumpers[info.ConnID]
	if !ok {
		// TODO: return an error here?
		return data, nil
	}

	switch {
	case net.IP.Equal(dumper.IPDown, info.SrcIP) && dumper.PortDown == info.SrcPort &&
		net.IP.Equal(dumper.IPUp, info.DstIP) && dumper.PortUp == info.DstPort:
		dumper.WritePacketUp(i.writer, data)
	case net.IP.Equal(dumper.IPDown, info.DstIP) && dumper.PortDown == info.DstPort &&
		net.IP.Equal(dumper.IPUp, info.SrcIP) && dumper.PortUp == info.SrcPort:
		dumper.WritePacketDown(i.writer, data)
	}

	return data, nil
}
