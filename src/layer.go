package src

import (
	"fmt"
	"strings"

	"github.com/bugwz/hamburg/utils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// LayersParser parse all layers
func (h *Hamburg) LayersParser(packet *gopacket.Packet) *utils.PacketDetail {
	s := h.Sniffer
	c := h.Conf

	s.CapturedCount++
	d := &utils.PacketDetail{Type: h.GetLayers(*packet)}
	d.Timestap = (*packet).Metadata().CaptureInfo.Timestamp

	// Ethernet layer
	if ethernet := h.ParseEthernetLayer(*packet); ethernet != nil {
		d.SrcMAC = ethernet.SrcMAC.String()
		d.DstMAC = ethernet.DstMAC.String()
	}

	// IP layer
	if ip := h.ParseIPLayer(*packet); ip != nil {
		d.SrcIP = fmt.Sprintf("%s", ip.SrcIP)
		d.DstIP = fmt.Sprintf("%s", ip.DstIP)

		// Set direction
		d.Direction = "None"
		if s.LocalIPs[d.SrcIP] != "" {
			d.Direction = "RSP"
		}
		if s.LocalIPs[d.DstIP] != "" {
			d.Direction = "REQ"
		}
	}

	// UDP layer
	if udp := h.ParseUDPLayer(*packet); udp != nil {
		d.SrcPort = fmt.Sprintf("%d", udp.SrcPort)
		d.DstPort = fmt.Sprintf("%d", udp.DstPort)
		d.CheckSum = fmt.Sprintf("%d", udp.Checksum)
		d.PayloadLen = int(udp.Length)
		d.Payload = string(udp.BaseLayer.LayerPayload())
	}

	// TCP layer
	if tcp := h.ParseTCPLayer(*packet); tcp != nil {
		d.SrcPort = fmt.Sprintf("%d", tcp.SrcPort)
		d.DstPort = fmt.Sprintf("%d", tcp.DstPort)
		d.CheckSum = fmt.Sprintf("%d", tcp.Checksum)
		d.Sequence = fmt.Sprintf("%d", tcp.Seq)

		// Parse flag
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
		d.Flag = fint
		d.FlagStr = strings.Join(fstr, ",")
		d.ACK = fmt.Sprintf("%d", tcp.Ack)
	}

	// Set direction
	if d.SrcPort != "" && d.DstPort != "" {
		for _, port := range c.ports {
			if d.SrcPort == port {
				d.Direction = "RSP"
				break
			}
			if d.DstPort == port {
				d.Direction = "REQ"
				break
			}
		}

		if d.SrcIP != "" && d.DstIP != "" {
			reqid := fmt.Sprintf("%s:%s => %s:%s", d.DstIP, d.DstPort, d.SrcIP, d.SrcPort)
			if _, exits := s.RequestDict.Get(reqid); exits {
				d.Direction = "RSP"
			}
		}
	}

	// Parse payload
	if app := (*packet).ApplicationLayer(); app != nil {
		if string(app.Payload()) != "" {
			d.Payload = string(app.Payload())
			d.PayloadLen = (*packet).Metadata().CaptureLength
		}
	}
	h.PayloadParser(d)

	// Update stats
	if d.Direction == "REQ" {
		h.Stats.IncrRequestCount()
	} else if d.Direction == "RSP" {
		h.Stats.IncrResponseCount()
	}

	return d
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
