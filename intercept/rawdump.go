package intercept

import (
	"net"

	"tlstap/logging"
	tlstap "tlstap/proxy"
)

type RawdumpInterceptor struct {
	Logger *logging.Logger
}

func (i *RawdumpInterceptor) Init(addr net.TCPAddr) error {
	return nil
}

func (i *RawdumpInterceptor) Finalize(addr net.TCPAddr) {}

func (i *RawdumpInterceptor) ConnectionEstablished(info *tlstap.ConnInfo) error {
	if i.Logger != nil {
		i.Logger.Info("Connection established: %v (%v->%v)", info.ConnID, info.SrcEndpoint, info.DstEndpoint)
	}

	return nil
}

func (i *RawdumpInterceptor) ConnectionTerminated(info *tlstap.ConnInfo) error {
	if i.Logger != nil {
		i.Logger.Info("Connection terminated: %v (%v->%v)", info.ConnID, info.SrcEndpoint, info.DstEndpoint)
	}

	return nil
}

func (i *RawdumpInterceptor) Intercept(info *tlstap.ConnInfo, data []byte) ([]byte, error) {
	if i.Logger != nil {
		i.Logger.Info("%v -> %v (%v):\n%v\n", info.SrcEndpoint, info.DstEndpoint, info.ConnID, string(data))
	}

	return data, nil
}
