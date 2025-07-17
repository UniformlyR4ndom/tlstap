package intercept

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"tlstap/assert"
	"tlstap/logging"
	tlstap "tlstap/proxy"
)

type FrameType byte

const (
	FrameTypeData = iota
	FrameTypeInfo
)

type Frame interface {
	Type() FrameType
	DataSize() int

	ToBytes() []byte
}

// serialized form:
// type 			- byte
// data size 		- uint32
// connection ID 	- uint32
type DataFrame struct {
	Size   uint32
	ConnId uint32
}

func (f *DataFrame) Type() FrameType {
	return FrameTypeData
}

func (f *DataFrame) DataSize() int {
	return int(f.Size)
}

func (f *DataFrame) ToBytes() []byte {
	buf := [9]byte{}
	buf[0] = byte(f.Type())
	_, err := binary.Encode(buf[1:], binary.LittleEndian, f.Size)
	assert.Assertf(err == nil, "Unexpected error: %v. This is a bug.", err)
	_, err = binary.Encode(buf[5:], binary.LittleEndian, f.ConnId)
	assert.Assertf(err == nil, "Unexpected error: %v. This is a bug.", err)
	return buf[:]
}

func ReadDataFrame(r io.Reader) (DataFrame, error) {
	f := DataFrame{}
	if err := binary.Read(r, binary.LittleEndian, &f.Size); err != nil {
		return DataFrame{}, err
	}

	if err := binary.Read(r, binary.LittleEndian, &f.ConnId); err != nil {
		return DataFrame{}, err
	}

	return f, nil
}

// serialized form:
// type 				- byte
// event ID				- byte
// connection ID		- uint32
// downstream remote 	- string
// upstream remote		- string
// strings are prefixed by length (uint32) and UTF8-encoded
type InfoFrame struct {
	EventId    byte
	ConnId     uint32
	RemoteDown string
	RemoteUp   string
}

const (
	BridgeEventInit            = 0x01
	BridgeEventTerminate       = 0x02
	BridgeEventConnEstablished = 0x10
	BridgeEventConnTerminated  = 0x11
	BridgeEventInfo            = 0x20
)

func (f *InfoFrame) Type() FrameType {
	return FrameTypeInfo
}

func (f *InfoFrame) DataSize() int {
	return 0
}

func (f *InfoFrame) ToBytes() []byte {
	var buf bytes.Buffer
	buf.Grow(2 + 3*4 + len(f.RemoteDown) + len(f.RemoteUp))

	err := buf.WriteByte(byte(f.Type()))
	assert.Assertf(err == nil, "Unexpected error: %v. This is a bug.", err)

	err = buf.WriteByte(f.EventId)
	assert.Assertf(err == nil, "Unexpected error: %v. This is a bug.", err)

	err = binary.Write(&buf, binary.LittleEndian, f.ConnId)
	assert.Assertf(err == nil, "Unexpected error: %v. This is a bug.", err)

	n := uint32(len(f.RemoteDown))
	assert.Assertf(int(n) == len(f.RemoteDown), "Length truncated. This is a bug.")

	err = binary.Write(&buf, binary.LittleEndian, n)
	assert.Assertf(err == nil, "Unexpected error: %v. This is a bug.", err)

	_, err = buf.Write([]byte(f.RemoteDown))
	assert.Assertf(err == nil, "Unexpected error: %v. This is a bug.", err)

	n = uint32(len(f.RemoteUp))
	assert.Assertf(int(n) == len(f.RemoteUp), "Length truncated. This is a bug.")

	err = binary.Write(&buf, binary.LittleEndian, n)
	assert.Assertf(err == nil, "Unexpected error: %v. This is a bug.", err)

	_, err = buf.Write([]byte(f.RemoteUp))
	assert.Assertf(err == nil, "Unexpected error: %v. This is a bug.", err)

	return buf.Bytes()
}

type BridgeInterceptor struct {
	NullInterceptor

	connectEndpoint string
	connMap         sync.Map

	readBuf []byte
	logger  *logging.Logger
}

type BridgeConfig struct {
	Connect string `json:"connect"`
}

const (
	maxFrameSize = 1 << 20
	readBufSize  = 1 << 12
)

func NewBridgeInterceptor(connect string, logger *logging.Logger) BridgeInterceptor {
	return BridgeInterceptor{
		connectEndpoint: connect,
		readBuf:         make([]byte, readBufSize),
		logger:          logger,
	}
}

func (i *BridgeInterceptor) ConnectionEstablished(info *tlstap.ConnInfo) error {
	conn, err := net.Dial("tcp", i.connectEndpoint)
	if err != nil {
		return err
	}

	i.connMap.Store(int(info.ConnID), conn)
	infoFrame := InfoFrame{
		EventId:    BridgeEventConnEstablished,
		ConnId:     uint32(info.ConnID),
		RemoteDown: info.SrcEndpoint,
		RemoteUp:   info.DstEndpoint,
	}

	_, err = conn.Write(infoFrame.ToBytes())
	return err
}

func (i *BridgeInterceptor) ConnectionTerminated(info *tlstap.ConnInfo) error {
	infoFrame := InfoFrame{
		EventId:    BridgeEventConnTerminated,
		ConnId:     uint32(info.ConnID),
		RemoteDown: info.SrcEndpoint,
		RemoteUp:   info.DstEndpoint,
	}

	c, ok := i.connMap.Load(int(info.ConnID))
	if !ok {
		return fmt.Errorf("no connection %d", info.ConnID)
	}

	i.connMap.Delete(int(info.ConnID))
	conn, ok := c.(net.Conn)
	assert.Assertf(ok, "Unexpected type: %T", c)
	conn.Write(infoFrame.ToBytes())
	conn.Close()
	return nil
}

func (i *BridgeInterceptor) Intercept(info *tlstap.ConnInfo, data []byte) ([]byte, error) {
	n := uint32(len(data))
	assert.Assertf(int(n) == len(data), "Length truncated")

	c, ok := i.connMap.Load(int(info.ConnID))
	if !ok {
		return data, fmt.Errorf("no connection %d", info.ConnID)
	}

	conn, ok := c.(net.Conn)
	assert.Assertf(ok, "Unexpected type: %T", c)

	outFrame := DataFrame{
		Size:   n,
		ConnId: uint32(info.ConnID),
	}

	if _, err := conn.Write(outFrame.ToBytes()); err != nil {
		return data, err
	}

	if _, err := conn.Write(data); err != nil {
		return data, err
	}

	inFrame, err := ReadDataFrame(conn)
	if err != nil {
		return data, err
	}

	if inFrame.Size > maxFrameSize {
		i.logger.Error("Recieved frame is too large (%d btyes). Maximum of %d bytes are acceptable.", inFrame.Size, maxFrameSize)
	}

	if int(inFrame.Size) > len(i.readBuf) {
		i.readBuf = make([]byte, inFrame.Size)
	}

	if _, err = io.ReadFull(conn, i.readBuf[:inFrame.Size]); err != nil {
		return data, err
	}

	return i.readBuf[:inFrame.Size], nil
}
