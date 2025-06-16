package assert

import (
	"log"
)

func Assertf(condition bool, format string, args ...any) {
	if !condition {
		log.Fatalf(format, args...)
	}
}
