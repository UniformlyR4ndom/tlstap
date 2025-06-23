package intercept

import (
	"encoding/hex"
	"net"

	"tlstap/logging"
	tlstap "tlstap/proxy"
)

// HexDumpInterceptor writes all data passing through it to the logger in hexdump format
type HexDumpInterceptor struct {
	Logger *logging.Logger
}

func (i *HexDumpInterceptor) Init(addr net.TCPAddr) error {
	return nil
}

func (i *HexDumpInterceptor) Finalize(addr net.TCPAddr) {}

func (i *HexDumpInterceptor) ConnectionEstablished(info *tlstap.ConnInfo) error {
	if i.Logger != nil {
		i.Logger.Info("Connection established: %v (%v->%v)", info.ConnID, info.SrcEndpoint, info.DstEndpoint)
	}

	return nil
}

func (i *HexDumpInterceptor) ConnectionTerminated(info *tlstap.ConnInfo) error {
	if i.Logger != nil {
		i.Logger.Info("Connection terminated: %v (%v->%v)", info.ConnID, info.SrcEndpoint, info.DstEndpoint)
	}

	return nil
}

// Write data in hexdump format to logger.
// If the Logger is nil, skip logging entirely.
func (i *HexDumpInterceptor) Intercept(info *tlstap.ConnInfo, data []byte) ([]byte, error) {
	if i.Logger != nil {
		i.Logger.Info("%v -> %v (%v):\n%v\n", info.SrcEndpoint, info.DstEndpoint, info.ConnID, hex.Dump(data))
	}

	return data, nil
}
