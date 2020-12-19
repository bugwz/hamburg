package parser

import (
	"strings"
)

// MemcachedParser memcached parser
type MemcachedParser struct{}

// NoReplyCommands no reply commands
var NoReplyCommands = []string{
	"get", "gets", "stats", "stat", "watch", "lru",
	"set", "add", "incr", "decr", "delete", "replace",
	"append", "prepend", "cas", "touch", "flushall",
}

// Run parse packets
func (m *MemcachedParser) Run(v *Packet) {
	p := v.Payload

	for index, cmd := range NoReplyCommands {
		if strings.LastIndex(p, cmd) == 0 {
			if index >= 6 && len(p) > 7 && strings.Contains(p[7:], "noreply") {
				v.Ignore = true
				return
			}
		}
	}

	v.Content = strings.ReplaceAll(v.Payload, "\r\n", " ")
}
