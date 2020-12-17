package parser

import (
	"fmt"
	"strings"

	"github.com/bugwz/hamburg/utils"
)

// Redis payload first char
const (
	RedisError        = '-'
	RedisSimpleString = '+'
	RedisInterger     = ':'
	RedisBulkString   = '$'
	RedisArray        = '*'
)

// RedisParser parse packets with redis protocol rules
func RedisParser(d *utils.Packet) {
	var cmds []string
	p := d.Payload

	if len(p) > 0 {
		switch p[0] {
		case RedisError, RedisSimpleString, RedisInterger:
			lines := strings.Split(p, "\r\n")
			fmt.Println(lines)
			if len(lines) == 2 {
				cmds = append(cmds, lines[0][1:])
			}
		case RedisBulkString:
			lines := strings.Split(p, "\r\n")
			if len(lines) == 3 {
				cmds = append(cmds, lines[1])
			}
		case RedisArray:
			lines := strings.Split(p, "\r\n")
			for i := 2; i < len(lines); i += 2 {
				// Parse the request commands in the pipline
				if len(lines[i]) < 1 || len(lines[i-1]) < 1 {
					continue
				}
				if lines[i][0] == RedisBulkString && i-1 > 0 && lines[i-1][0] == RedisArray {
					i = i - 1
					continue
				}
				cmds = append(cmds, lines[i])
			}
		default:
			cmds = append(cmds, strings.ReplaceAll(p, "\r\n", " "))
		}
	}

	d.Content = strings.Join(cmds, " ")
}
