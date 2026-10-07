package test

import "bytes"

// hasTrigger reports whether data contains trigger; an empty trigger never matches.
func hasTrigger(data, trigger []byte) bool {
	return len(trigger) > 0 && bytes.Contains(data, trigger)
}
