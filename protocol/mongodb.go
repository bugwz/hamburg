package protocol

import (
	"fmt"
	"strings"
)

// ParsePayloadWithMongoDB parse packets with mongodb protocol rules
func ParsePayloadWithMongoDB(payload string) {
	if len(payload) > 0 && payload[:1] == "*" {
		var coms []string
		lines := strings.Split(payload, "\r\n")
		for i := 2; i < len(lines); i += 2 {
			coms = append(coms, lines[i])
		}
		fmt.Println("指令为： ", strings.Join(coms, " "))
	}
}
