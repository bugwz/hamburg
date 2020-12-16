package parser

import (
	"strings"
)

// MongoDBParser parse packets with mongodb protocol rules
func MongoDBParser(p string) {
	if len(p) > 0 && p[:1] == "*" {
		var cmds []string
		lines := strings.Split(p, "\r\n")
		for i := 2; i < len(lines); i += 2 {
			cmds = append(cmds, lines[i])
		}
	}
}
