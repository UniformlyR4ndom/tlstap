package tlstap

type Mode byte

const (
	ModePlain     = 1
	ModeTls       = 2
	ModeDetectTls = 3
	ModeMux       = 4
)

func (m Mode) String() string {
	switch m {
	case ModePlain:
		return "plain"
	case ModeTls:
		return "tls"
	case ModeDetectTls:
		return "dectecttls"
	case ModeMux:
		return "mux"
	}

	return "unknown"
}
