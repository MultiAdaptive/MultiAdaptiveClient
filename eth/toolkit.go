package eth

import "strings"

func trimPrefixes(s string, prefixes ...string) string {
	for _, prefix := range prefixes {
		if strings.HasPrefix(s, prefix) {
			return strings.TrimPrefix(s, prefix)
		}
	}
	return s
}
