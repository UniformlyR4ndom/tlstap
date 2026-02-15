package intercept

import (
	"fmt"
	"net"
	"regexp"
	tlstap "tlstap/proxy"
)

type MatchReplaceConfig struct {
	// Replacements to perfrom (in the given order).
	// Each map should contain exactly one element.
	// Example:
	// [
	// 		{"one": "1"},
	//		{"delete[0-9]*": ""}
	// ]
	// The string "deleteonetwo" will be processed as follows:
	// "deleteonetwo" -> "delete1two" -> "two"
	Replacements []map[string]string `json:"replacements"`
}

// MatchReplaceInterceptor performs string replacesments on all data passing through it
type MatchReplaceInterceptor struct {
	replacements map[*regexp.Regexp][]byte
	order        []*regexp.Regexp
}

func NewMatchReplaceInterceptor(config *MatchReplaceConfig) (MatchReplaceInterceptor, error) {
	var order []*regexp.Regexp
	replacements := make(map[*regexp.Regexp][]byte)

	var interceptor MatchReplaceInterceptor
	for i, m := range config.Replacements {
		if len(m) != 1 {
			return interceptor, fmt.Errorf("replacement specification %d is invalid: expected map with exactly 1 element, got %d", i, len(m))
		}

		// the map is guranteed to have a single element
		for k, v := range m {
			r, err := regexp.Compile(k)
			if err != nil {
				return interceptor, fmt.Errorf("failed to compile regex for replacement specification %d: %v", i, err)
			}

			order = append(order, r)
			replacements[r] = []byte(v)
		}
	}

	interceptor = MatchReplaceInterceptor{
		replacements: replacements,
		order:        order,
	}

	return interceptor, nil
}

func (i *MatchReplaceInterceptor) Init(addr net.TCPAddr) error {
	return nil
}

func (i *MatchReplaceInterceptor) Finalize(addr net.TCPAddr) {}

func (i *MatchReplaceInterceptor) ConnectionEstablished(info *tlstap.ConnInfo) error {
	return nil
}

func (i *MatchReplaceInterceptor) ConnectionTerminated(info *tlstap.ConnInfo) error {
	return nil
}

func (i *MatchReplaceInterceptor) Intercept(info *tlstap.ConnInfo, data []byte) ([]byte, error) {
	for _, r := range i.order {
		replacement := i.replacements[r]
		data = r.ReplaceAll(data, replacement)
	}

	return data, nil
}
