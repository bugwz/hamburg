package parser

import (
	"strings"

	"github.com/bugwz/hamburg/utils"
)

// MemcachedParser parse packets with memcached protocol rules
func MemcachedParser(d *utils.PacketDetail) {
	d.Content = strings.ReplaceAll(d.Payload, "\r\n", " ")
}
