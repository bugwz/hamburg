package src

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	p "github.com/bugwz/hamburg/parser"
	"github.com/google/gopacket"
)

// Flags for exit
const (
	SignalExit  = 1
	TimeoutExit = 2
)

// Hamburg main
type Hamburg struct {
	Sniffer *Sniffer
	Parser  *Parser
	State   *State
	Done    chan int
}

// NewHamburg new hamburg
func NewHamburg(c *Conf) (*Hamburg, error) {
	if c == nil {
		return nil, fmt.Errorf("Conf is nil")
	}

	sniffer, e := NewSniffer(c)
	if e != nil {
		return nil, e
	}

	parser, e := NewParser(c)
	if e != nil {
		return nil, e
	}

	state, e := NewState(c)
	if e != nil {
		return nil, e
	}

	return &Hamburg{
		Sniffer: sniffer,
		Parser:  parser,
		State:   state,
		Done:    make(chan int),
	}, nil
}

// Run run
func (h *Hamburg) Run() {
	// 1) Output NIC information
	h.Sniffer.NICDetail()

	// 2) Set start time
	h.Sniffer.SetStartTime()

	// 3) Run scheduler
	h.Scheduler()

	// 4) Start capture packets
	ps := gopacket.NewPacketSource(h.Sniffer.pktreader, h.Sniffer.pktreader.LinkType())
	for {
		select {
		case exit := <-h.Done:
			switch exit {
			case SignalExit:
				fmt.Println("\r\nWill exit for signal...")
			case TimeoutExit:
				fmt.Println("\r\nWill exit for run timeout...")
			}
			h.State.ShowStats()
			os.Exit(0)
		case p := <-ps.Packets():
			h.SavePackets(&p)
			h.ParsePackets(&p)
		}
	}
}

// Scheduler schedule process
func (h *Hamburg) Scheduler() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for {
			select {
			case <-ch:
				h.Done <- SignalExit
				return
			case <-time.After(time.Duration(1) * time.Second):
				start := h.Sniffer.GetStartTime()
				limit := h.Sniffer.GetDuration()
				if limit != 0 && time.Now().Sub(start) >= limit {
					h.Done <- TimeoutExit
					return
				}
			}
		}
	}()
}

// ParsePackets parser packets
func (h *Hamburg) ParsePackets(gop *gopacket.Packet) {
	// 1) Parsing layers of packets
	pkt := h.Parser.UnpackLayers(gop)

	// 2) Determine the direction of the data
	h.SetDirection(pkt)

	// 3) Update process status
	h.State.IncrReqRsp(pkt.Request)

	// 4) Try run custom script
	if h.Parser.RunScript(pkt) == nil {
		return
	}

	// 5) Run the preset parsing script
	h.Parser.Run(pkt)

	// 6) Processing request and reply packet pairs
	if pkt.Ignore {
		return
	}

	reqid := fmt.Sprintf("%s -> %s", pkt.SrcID, pkt.DstID)
	rspid := fmt.Sprintf("%s -> %s", pkt.DstID, pkt.SrcID)
	if pkt.Payload == "" {
		if pkt.Request && pkt.Flag&SYN != 0 {
			h.State.dict.Remove(reqid)
		}
		if !pkt.Request && (pkt.Flag&RST != 0 || pkt.Flag&FIN != 0) {
			h.State.dict.Remove(rspid)
		}
		return
	}

	if pkt.Request {
		old, exits := h.State.dict.Get(reqid)
		if !exits {
			h.State.dict.Put(reqid, pkt)
		} else {
			old.(*p.Packet).Content += " " + pkt.Content
		}
	} else {
		if ret, ok := h.State.dict.Get(rspid); ok {
			td := pkt.Timestap.Sub(ret.(*p.Packet).Timestap)
			h.State.AddDuration(td)
			if h.State.FitSlow(td) {
				h.State.curmsg = fmt.Sprintf("%v | %s | %v | %v",
					(ret.(*p.Packet).Timestap).Format("2006-01-02 15:04:05"), rspid, td,
					ret.(*p.Packet).Content)
				if h.State.showreply {
					h.State.curmsg += fmt.Sprintf(" | %v", pkt.Content)
				}
				fmt.Println(h.State.curmsg)
			}
			h.State.dict.Remove(rspid)
		}
		// TODO: The statistical time-consuming of multiple reply packets may be small
	}
}

// SavePackets save packets to local file
func (h *Hamburg) SavePackets(p *gopacket.Packet) {
	s := h.Sniffer
	if s != nil && s.pktwriter != nil {
		s.pktwriter.WritePacket((*p).Metadata().CaptureInfo, (*p).Data())
	}
}

// SetDirection set request direction
func (h *Hamburg) SetDirection(v *p.Packet) {
	// Using IP to determine the request direction of packets
	if h.Sniffer.localip[v.SrcIP] != "" {
		v.Request = false
	}
	if h.Sniffer.localip[v.DstIP] != "" {
		v.Request = true
	}

	// Using Port to determine the request direction of packets
	if v.SrcPort != "" && v.DstPort != "" {
		for _, port := range h.Sniffer.ports {
			if v.SrcPort == port {
				v.Request = false
				break
			}
			if v.DstPort == port {
				v.Request = true
				break
			}
		}
		return
	}

	// Use recorded historical packets to determine direction
	if v.SrcIP != "" && v.DstIP != "" {
		reqid := fmt.Sprintf("%s:%s => %s:%s", v.DstIP, v.DstPort, v.SrcIP, v.SrcPort)
		if _, exits := h.State.dict.Get(reqid); exits {
			v.Request = false
		}
	}
}
