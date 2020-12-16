package parser

import (
	"fmt"
	"strings"

	"github.com/bugwz/hamburg/utils"
)

// HTTPParser parse packets with http protocol rules
func HTTPParser(d *utils.PacketDetail) {
	var rtype, host, path string
	p := d.Payload

	pls := strings.Split(p, "\r\n")
	for _, it := range pls {
		if strings.Contains(it, "Host: ") {
			if info := strings.Split(it, " "); len(info) == 2 {
				d.Direction = "REQ"
				host = info[1]
				break
			}
		}
		if strings.Contains(it, "Server: ") {
			if info := strings.Split(it, " "); len(info) == 2 {
				d.Direction = "RSP"
				host = info[1]
				break
			}
		}
	}

	if len(pls) > 2 {
		if d.Direction == "REQ" {
			if info := strings.Split(pls[0], " "); len(info) >= 3 {
				rtype = fmt.Sprintf("[%s %s]", info[2], info[0])
				path = info[1]
			}
		}
		if d.Direction == "RSP" {
			if info := strings.Split(pls[0], " "); len(info) >= 2 {
				rtype = fmt.Sprintf("[%s %s]", info[0], info[1])
			}
		}
	}
	d.Content = fmt.Sprintf("%s %s%s", rtype, host, path)
}
