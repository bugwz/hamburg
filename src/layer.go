package src

import (
	"fmt"
	"strings"

	p "github.com/bugwz/hamburg/parser"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// UnpackLayers parse all layers
func (h *Hamburg) UnpackLayers(packet *gopacket.Packet) *p.Packet {
	v := &p.Packet{Type: h.GetLayers(*packet)}
	v.Timestap = (*packet).Metadata().CaptureInfo.Timestamp

	// Ethernet layer
	if ethernet := h.ParseEthernetLayer(*packet); ethernet != nil {
		v.SrcMAC = ethernet.SrcMAC.String()
		v.DstMAC = ethernet.DstMAC.String()
	}

	// IP layer
	if ip := h.ParseIPLayer(*packet); ip != nil {
		v.SrcIP = fmt.Sprintf("%s", ip.SrcIP)
		v.DstIP = fmt.Sprintf("%s", ip.DstIP)
	}

	// UDP layer
	if udp := h.ParseUDPLayer(*packet); udp != nil {
		v.SrcPort = fmt.Sprintf("%d", udp.SrcPort)
		v.DstPort = fmt.Sprintf("%d", udp.DstPort)
		v.CheckSum = fmt.Sprintf("%d", udp.Checksum)
		v.PayloadLen = int(udp.Length)
		v.Payload = string(udp.BaseLayer.LayerPayload())
	}

	// TCP layer
	if tcp := h.ParseTCPLayer(*packet); tcp != nil {
		v.SrcPort = fmt.Sprintf("%d", tcp.SrcPort)
		v.DstPort = fmt.Sprintf("%d", tcp.DstPort)
		v.CheckSum = fmt.Sprintf("%d", tcp.Checksum)
		v.Sequence = fmt.Sprintf("%d", tcp.Seq)

		// Parse flags
		var fstr []string
		fint := 0
		if tcp.FIN {
			fint |= FIN
			fstr = append(fstr, "FIN")
		}
		if tcp.SYN {
			fint |= SYN
			fstr = append(fstr, "SYN")
		}
		if tcp.RST {
			fint |= RST
			fstr = append(fstr, "RST")
		}
		if tcp.PSH {
			fint |= PSH
			fstr = append(fstr, "PSH")
		}
		if tcp.ACK {
			fint |= ACK
			fstr = append(fstr, "ACK")
		}
		if tcp.URG {
			fint |= URG
			fstr = append(fstr, "URG")
		}
		if tcp.ECE {
			fint |= ECE
			fstr = append(fstr, "ECE")
		}
		if tcp.CWR {
			fint |= CWR
			fstr = append(fstr, "CWR")
		}
		v.Flag = fint
		v.FlagStr = strings.Join(fstr, ",")
		v.ACK = fmt.Sprintf("%d", tcp.Ack)
	}

	// Parse payload
	if app := (*packet).ApplicationLayer(); app != nil {
		if string(app.Payload()) != "" {
			v.Payload = string(app.Payload())
			v.PayloadLen = (*packet).Metadata().CaptureLength
		}
	}

	return v
}

// GetLayers layers
func (h *Hamburg) GetLayers(packet gopacket.Packet) string {
	var packets []string
	for _, layer := range packet.Layers() {
		v := strings.ReplaceAll(fmt.Sprintln(layer.LayerType()), "\n", "")
		if v != "Ethernet" && v != "Payload" {
			packets = append(packets, v)
		}
	}

	return strings.Join(packets, "/")
}

// ParseEthernetLayer ethernet layer
func (h *Hamburg) ParseEthernetLayer(packet gopacket.Packet) *layers.Ethernet {
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		return ethernetPacket
	}

	return nil
}

// ParseIPLayer ip layer
func (h *Hamburg) ParseIPLayer(packet gopacket.Packet) *layers.IPv4 {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		return ip
	}

	return nil
}

// ParseTCPLayer tcp layer
func (h *Hamburg) ParseTCPLayer(packet gopacket.Packet) *layers.TCP {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		return tcp
	}

	return nil
}

// ParseUDPLayer udp layer
func (h *Hamburg) ParseUDPLayer(packet gopacket.Packet) *layers.UDP {
	tcpLayer := packet.Layer(layers.LayerTypeUDP)
	if tcpLayer != nil {
		udp, _ := tcpLayer.(*layers.UDP)
		return udp
	}

	return nil
}
