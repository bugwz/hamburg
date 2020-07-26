package src

import (
	"github.com/bugwz/hamburg/protocol"
	"github.com/bugwz/hamburg/utils"
)

// protocol type id
const (
	PTRAW       = 1
	PTDNS       = 2
	PTHTTP      = 3
	PTRedis     = 4
	PTMemcached = 5
	PTMySQL     = 6
)

// ProtocolType protocol type
var ProtocolType = map[int]string{
	PTRAW:       "raw",
	PTDNS:       "dns",
	PTHTTP:      "http",
	PTRedis:     "redis",
	PTMemcached: "memcached",
	PTMySQL:     "mysql",
}

// ParsePayload parse payload
func (t *Hamburg) ParsePayload(d *utils.PacketDetail) {
	if d.Payload != "" {
		switch t.Conf.Protocol {
		case PTRAW:
			protocol.ParsePayloadWithRAW(d)
		case PTDNS:
			protocol.ParsePayloadWithDNS(d)
		case PTHTTP:
			protocol.ParsePayloadWithHTTP(d)
		case PTRedis:
			protocol.ParsePayloadWithRedis(d)
		case PTMemcached:
			protocol.ParsePayloadWithMC(d)
		case PTMySQL:
			protocol.ParsePayloadWithMySQL(d)
		default:
			d.Content = ""
		}
	}
}
