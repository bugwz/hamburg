package parser

import (
	"fmt"
)

// RAWParser raw parser
type RAWParser struct{}

// Run parse packets
func (r *RAWParser) Run(v *Packet) {
	v.Content = fmt.Sprintf("Seq:%s - Ack:%s - %s - PayLen:%d",
		v.Sequence, v.ACK, v.FlagStr, v.PayloadLen)
}
