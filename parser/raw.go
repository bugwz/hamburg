package parser

import (
	"fmt"

	"github.com/bugwz/hamburg/utils"
)

// RAWParser raw
func RAWParser(d *utils.Packet) {
	d.Content = fmt.Sprintf("Seq:%s - Ack:%s - %s - PayLen:%d",
		d.Sequence, d.ACK, d.FlagStr, d.PayloadLen)
}
