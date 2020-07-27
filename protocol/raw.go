package protocol

import (
	"fmt"

	"github.com/bugwz/hamburg/utils"
)

// ParsePayloadWithRAW raw
func ParsePayloadWithRAW(d *utils.PacketDetail) {
	d.Content = fmt.Sprintf("Seq:%s - Ack:%s - %s - PayLen:%d",
		d.Sequence, d.ACK, d.FlagStr, d.PayloadLen)
}
