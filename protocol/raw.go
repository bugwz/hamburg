package protocol

import (
	"fmt"

	"github.com/bugwz/hamburg/utils"
)

// ParsePayloadWithRAW raw
func ParsePayloadWithRAW(d *utils.PacketDetail) {
	d.Content = fmt.Sprintf("Seq:%-10s Ack:%-10s Flags:%-12s PayloadLen:%d",
		d.Sequence, d.ACK, d.FlagStr, d.PayloadLen)
}
