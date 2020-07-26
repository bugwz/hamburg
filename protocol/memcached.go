package protocol

import (
	"strings"

	"github.com/bugwz/hamburg/utils"
)

// ParsePayloadWithMC parse packets with memcached protocol rules
func ParsePayloadWithMC(d *utils.PacketDetail) {
	d.Content = strings.ReplaceAll(d.Payload, "\r\n", " ")
}
