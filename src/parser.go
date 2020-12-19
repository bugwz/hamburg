package src

import (
	"fmt"
	"strings"

	p "github.com/bugwz/hamburg/parser"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	lua "github.com/yuin/gopher-lua"
)

// Parser parser
type Parser struct {
	x   p.Parser
	lua *Lua
}

// Lua lua struct
type Lua struct {
	state *lua.LState
	args  *lua.LTable
}

// NewParser new parser
func NewParser(c *Conf) (*Parser, error) {
	x := p.NewParser(c.Protocol)
	if x == nil {
		return nil, fmt.Errorf("Not found parser with protocol %s", c.Protocol)
	}

	var l *Lua = nil
	if c.Script != "" {
		lstate := lua.NewState()
		if lstate.DoFile(c.Script) != nil {
			lstate.Close()
		}
		l = &Lua{
			state: lstate,
			args:  lstate.CreateTable(0, 0),
		}
	}

	return &Parser{
		x:   x,
		lua: l,
	}, nil
}

// Run run parser by protocol
func (s *Parser) Run(v *p.Packet) {
	s.x.Run(v)
}

// RunScript run custom script
func (s *Parser) RunScript(pkt *p.Packet) error {
	l := s.lua
	if l == nil {
		return fmt.Errorf("lua script is not available")
	}

	l.args.RawSetString("type", lua.LString(fmt.Sprintf("[%s]", pkt.Type)))
	l.args.RawSetString("direction", lua.LString(pkt.Direction))
	l.args.RawSetString("smac", lua.LString(pkt.SrcMAC))
	l.args.RawSetString("sip", lua.LString(pkt.SrcIP))
	l.args.RawSetString("sport", lua.LString(pkt.SrcPort))
	l.args.RawSetString("dmac", lua.LString(pkt.DstMAC))
	l.args.RawSetString("dip", lua.LString(pkt.DstIP))
	l.args.RawSetString("dport", lua.LString(pkt.DstPort))
	l.args.RawSetString("seq", lua.LString(pkt.Sequence))
	l.args.RawSetString("ack", lua.LString(pkt.ACK))
	l.args.RawSetString("flag", lua.LString(pkt.FlagStr))
	l.args.RawSetString("payload", lua.LString(pkt.Payload))
	l.args.RawSetString("payloadlen", lua.LString(fmt.Sprintf("%d", pkt.PayloadLen)))
	if err := l.state.CallByParam(lua.P{
		Fn:      l.state.GetGlobal("process"),
		NRet:    1,
		Protect: true,
	}, l.args); err != nil {
		fmt.Printf("run lua script failed: %v", err)
		return fmt.Errorf("run lua script failed: %v", err)
	}

	return nil
}

// UnpackLayers parse all layers
func (s *Parser) UnpackLayers(gop *gopacket.Packet) *p.Packet {
	pkt := &p.Packet{Type: s.GetLayers(*gop)}
	pkt.Timestap = (*gop).Metadata().CaptureInfo.Timestamp

	// Ethernet layer
	if ethernet := s.ParseEthernetLayer(*gop); ethernet != nil {
		pkt.SrcMAC = ethernet.SrcMAC.String()
		pkt.DstMAC = ethernet.DstMAC.String()
	}

	// IP layer
	if ip := s.ParseIPLayer(*gop); ip != nil {
		pkt.SrcIP = fmt.Sprintf("%s", ip.SrcIP)
		pkt.DstIP = fmt.Sprintf("%s", ip.DstIP)
	}

	// UDP layer
	if udp := s.ParseUDPLayer(*gop); udp != nil {
		pkt.SrcPort = fmt.Sprintf("%d", udp.SrcPort)
		pkt.DstPort = fmt.Sprintf("%d", udp.DstPort)
		pkt.CheckSum = fmt.Sprintf("%d", udp.Checksum)
		pkt.PayloadLen = int(udp.Length)
		pkt.Payload = string(udp.BaseLayer.LayerPayload())
	}

	// TCP layer
	if tcp := s.ParseTCPLayer(*gop); tcp != nil {
		pkt.SrcPort = fmt.Sprintf("%d", tcp.SrcPort)
		pkt.DstPort = fmt.Sprintf("%d", tcp.DstPort)
		pkt.CheckSum = fmt.Sprintf("%d", tcp.Checksum)
		pkt.Sequence = fmt.Sprintf("%d", tcp.Seq)

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
		pkt.Flag = fint
		pkt.FlagStr = strings.Join(fstr, ",")
		pkt.ACK = fmt.Sprintf("%d", tcp.Ack)
	}
	pkt.SrcID = fmt.Sprintf("%s:%s", pkt.SrcIP, pkt.SrcPort)
	pkt.DstID = fmt.Sprintf("%s:%s", pkt.DstIP, pkt.DstPort)

	// Find payload
	if app := (*gop).ApplicationLayer(); app != nil {
		if string(app.Payload()) != "" {
			pkt.Payload = string(app.Payload())
			pkt.PayloadLen = (*gop).Metadata().CaptureLength
		}
	}

	return pkt
}

// GetLayers layers
func (s *Parser) GetLayers(pkt gopacket.Packet) string {
	var pkts []string
	for _, layer := range pkt.Layers() {
		v := strings.ReplaceAll(fmt.Sprintln(layer.LayerType()), "\n", "")
		if v != "Ethernet" && v != "Payload" {
			pkts = append(pkts, v)
		}
	}

	return strings.Join(pkts, "/")
}

// ParseEthernetLayer ethernet layer
func (s *Parser) ParseEthernetLayer(pkt gopacket.Packet) *layers.Ethernet {
	ethernetLayer := pkt.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		return ethernetPacket
	}

	return nil
}

// ParseIPLayer ip layer
func (s *Parser) ParseIPLayer(pkt gopacket.Packet) *layers.IPv4 {
	ipLayer := pkt.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		return ip
	}

	return nil
}

// ParseTCPLayer tcp layer
func (s *Parser) ParseTCPLayer(pkt gopacket.Packet) *layers.TCP {
	tcpLayer := pkt.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		return tcp
	}

	return nil
}

// ParseUDPLayer udp layer
func (s *Parser) ParseUDPLayer(pkt gopacket.Packet) *layers.UDP {
	tcpLayer := pkt.Layer(layers.LayerTypeUDP)
	if tcpLayer != nil {
		udp, _ := tcpLayer.(*layers.UDP)
		return udp
	}

	return nil
}
