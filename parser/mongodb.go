package parser

import (
	"strings"
)

// MongoDBParser mongodb parser
type MongoDBParser struct{}

// Run parse packets
func (m *MongoDBParser) Run(v *Packet) {
	var cmds []string

	p := v.Payload
	if len(p) > 0 && p[:1] == "*" {
		lines := strings.Split(p, "\r\n")
		for i := 2; i < len(lines); i += 2 {
			cmds = append(cmds, lines[i])
		}
	}

	v.Content = strings.Join(cmds, " ")
}
