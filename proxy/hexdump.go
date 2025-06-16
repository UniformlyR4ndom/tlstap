package tlstap

import (
	"bytes"
	"encoding/hex"
	"fmt"
)

func FormatHex(data []byte) string {
	return hex.EncodeToString(data)
}

func FormatHexDump(data []byte) string {
	return hex.Dump(data)
}

func FormatHexDump2(data []byte) string {
	var buffer bytes.Buffer
	buffer.Grow(3 * len(data))
	for i := 0; i < len(data); i += 16 {
		if i > 0 {
			buffer.WriteString("\n")
		}
		buffer.WriteString(fmt.Sprintf("%08x: ", i)) // address (offset)

		// hex values
		for j := 0; j < 16; j++ {
			if i+j < len(data) {
				buffer.WriteString(fmt.Sprintf("%02x ", data[i+j]))
			} else {
				buffer.WriteString(fmt.Sprint("   "))
			}
		}

		// ASCII representation
		buffer.WriteString(fmt.Sprint(" "))
		for j := 0; j < 16; j++ {
			if i+j < len(data) {
				b := data[i+j]
				if b >= 32 && b <= 126 { // printable characters
					buffer.WriteString(fmt.Sprintf("%c", b))
				} else {
					buffer.WriteString(fmt.Sprintf(".")) // non-printable characters
				}
			}
		}
	}

	return buffer.String()
}
