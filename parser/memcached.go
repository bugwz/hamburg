package parser

import (
	"strings"
)

// MemcachedParser memcached parser
type MemcachedParser struct{}

// Run parse packets
func (m *MemcachedParser) Run(v *Packet) {
	v.Content = strings.ReplaceAll(v.Payload, "\r\n", " ")
}
