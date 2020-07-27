package protocol

import (
	"strings"

	"github.com/bugwz/hamburg/utils"
)

// redis payload first char
const (
	RedisSimpleString = '+'
	RedisBulkString   = '$'
	RedisInterger     = ':'
	RedisArray        = '*'
	RedisError        = '-'
)

// ParsePayloadWithRedis parse packets with redis protocol rules
func ParsePayloadWithRedis(d *utils.PacketDetail) {
	var coms []string
	payload := d.Payload

	if len(payload) > 0 {
		switch payload[0] {
		case RedisArray:
			lines := strings.Split(payload, "\r\n")
			for i := 2; i < len(lines); i += 2 {
				// parse the request commands in the pipline
				if len(lines[i]) < 1 || len(lines[i-1]) < 1 {
					continue
				}
				if lines[i][0] == RedisBulkString && i-1 > 0 && lines[i-1][0] == RedisArray {
					i = i - 1
					continue
				}
				coms = append(coms, lines[i])
			}
		default:
			coms = append(coms, strings.ReplaceAll(payload, "\r\n", " "))
		}
	}

	d.Content = strings.Join(coms, " ")
}
