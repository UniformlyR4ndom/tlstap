package tlstap

import (
	"encoding/binary"
)

func readUint8(data []byte, offset int) uint8 {
	return uint8(data[offset])
}

func tryReadUint8(data []byte, offset int) (uint8, bool) {
	if offset+1 <= len(data) {
		return uint8(data[offset]), true
	}

	return 0, false
}

func tryReadUint16(data []byte, offset int) (uint16, bool) {
	if offset+2 <= len(data) {
		return binary.BigEndian.Uint16(data[offset : offset+2]), true
	}

	return 0, false
}

func readUint16(data []byte, offset int) uint16 {
	return binary.BigEndian.Uint16(data[offset : offset+2])
}

func stringOrDefault(val, defaultVal string) string {
	if val == "" {
		return defaultVal
	}

	return val
}
