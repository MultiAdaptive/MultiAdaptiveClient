package tool

import (
	"strings"
	"time"
)

func TimeStampNowSecond() int64 {
	var timestamp int64
	timestamp = time.Now().UTC().UnixNano() / int64(time.Second)
	return timestamp
}

func TrimPrefixes(s string, prefixes ...string) string {
	for _, prefix := range prefixes {
		if strings.HasPrefix(s, prefix) {
			return strings.TrimPrefix(s, prefix)
		}
	}
	return s
}
