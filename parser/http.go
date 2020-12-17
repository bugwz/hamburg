package parser

import (
	"fmt"
	"strings"
)

// HTTPParser http parser
type HTTPParser struct{}

// Run parse packets
func (h *HTTPParser) Run(v *Packet) {
	var rtype, host, path string

	pls := strings.Split(v.Payload, "\r\n")
	for _, it := range pls {
		if strings.Contains(it, "Host: ") {
			if info := strings.Split(it, " "); len(info) == 2 {
				v.Request = true
				host = info[1]
				break
			}
		}
		if strings.Contains(it, "Server: ") {
			if info := strings.Split(it, " "); len(info) == 2 {
				v.Request = false
				host = info[1]
				break
			}
		}
	}

	if len(pls) > 2 {
		if v.Request {
			if info := strings.Split(pls[0], " "); len(info) >= 3 {
				rtype = fmt.Sprintf("[%s %s]", info[2], info[0])
				path = info[1]
			}
		} else {
			if info := strings.Split(pls[0], " "); len(info) >= 2 {
				rtype = fmt.Sprintf("[%s %s]", info[0], info[1])
			}
		}
	}

	v.Content = fmt.Sprintf("%s %s%s", rtype, host, path)
}
