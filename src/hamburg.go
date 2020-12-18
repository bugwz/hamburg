package src

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
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

// Hamburg main struct
type Hamburg struct {
	Conf    *Conf
	Stats   *Stats
	Sniffer *Sniffer
	Parser  p.Parser
	done    chan int
}

// NewHamburg new
func NewHamburg() *Hamburg {
	return &Hamburg{
		Conf:    NewConf(),
		Sniffer: NewSniffer(),
		Stats:   NewStats(),
		Parser:  p.NewParser(p.DefaultParser),
		done:    make(chan int),
	}
}

// Run run
func (h *Hamburg) Run() {
	s := h.Sniffer
	s.StartAt = time.Now()

	// 1) Check confs
	if err := h.Conf.CheckConfs(); err != nil {
		fmt.Println(err)
		return
	}

	// 2) Pcap handle with local file or network interface
	if err := h.CreatePcapHandle(); err != nil {
		fmt.Println(err)
		return
	}
	defer s.PcapHandle.Close()

	// 3) Create pcap filter
	if err := h.CreateFilter(); err != nil {
		fmt.Println(err)
		return
	}

	// 4) Create pcap write handle to save packets to local file
	if err := h.CreatePcapWriter(); err != nil {
		fmt.Println(err)
		return
	}
	defer s.OutFileHandle.Close()

	// 5) Schedule process
	h.Scheduler()

	// 6) Start capture packets
	packetSource := gopacket.NewPacketSource(s.PcapHandle, s.PcapHandle.LinkType())
	for {
		select {
		case exit := <-h.done:
			switch exit {
			case SignalExit:
				fmt.Println("\r\nWill exit for signal...")
			case TimeoutExit:
				fmt.Println("\r\nWill exit for run timeout...")
			}
			h.Stats.ShowStats()
			return
		case p := <-packetSource.Packets():
			// Save packets to local file
			h.SavePackets(&p)

			// Parse decoded packets
			v := h.UnpackLayers(&p)

			// Check direction
			h.SetRequest(v)

			// Parse
			h.ParsePackets(v)
		}
	}
}

// SetRequest set request
func (h *Hamburg) SetRequest(v *p.Packet) {
	s := h.Sniffer

	// Set direction
	if s.LocalIPs[v.SrcIP] != "" {
		v.Request = false
	}
	if s.LocalIPs[v.DstIP] != "" {
		v.Request = true
	}

	// Set direction
	if v.SrcPort != "" && v.DstPort != "" {
		for _, port := range h.Conf.GetPorts() {
			if v.SrcPort == port {
				v.Request = false
				break
			}
			if v.DstPort == port {
				v.Request = true
				break
			}
		}

		if v.SrcIP != "" && v.DstIP != "" {
			reqid := fmt.Sprintf("%s:%s => %s:%s", v.DstIP, v.DstPort, v.SrcIP, v.SrcPort)
			if _, exits := s.RequestDict.Get(reqid); exits {
				v.Request = false
			}
		}
	}

	if v.Request {
		h.Stats.IncrRequest(1)
	} else {
		h.Stats.IncrResponse(1)
	}
}

// Scheduler schedule process
func (h *Hamburg) Scheduler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for {
			select {
			case <-c:
				h.done <- SignalExit
				return
			case <-time.After(time.Duration(1) * time.Second):
				limit := h.Conf.GetDuration()
				if limit != 0 && time.Now().Sub(h.Sniffer.StartAt) >= limit {
					h.done <- TimeoutExit
					return
				}
			}
		}
	}()
}

// ParsePackets process decoding packets
func (h *Hamburg) ParsePackets(v *p.Packet) {
	s := h.Sniffer
	c := h.Conf

	// Try parse packets with with lua script
	if h.Conf.script.Run(v) == nil {
		return
	}

	// Parse payload
	h.Parser.Run(v)

	srcid := fmt.Sprintf("%s:%s", v.SrcIP, v.SrcPort)
	dstid := fmt.Sprintf("%s:%s", v.DstIP, v.DstPort)
	reqid := fmt.Sprintf("%s -> %s", srcid, dstid)
	rspid := fmt.Sprintf("%s -> %s", dstid, srcid)
	if v.Payload == "" {
		if v.Request && v.Flag&SYN != 0 {
			s.RequestDict.Remove(reqid)
		}
		if !v.Request && (v.Flag&RST != 0 || v.Flag&FIN != 0) {
			s.RequestDict.Remove(rspid)
		}
		return
	}

	if v.Request {
		// Filter noreply commands
		if h.IsNoReply(v.Payload) {
			return
		}
		old, exits := s.RequestDict.Get(reqid)
		if !exits {
			s.RequestDict.Put(reqid, v)
		} else {
			old.(*p.Packet).Content += " " + v.Content
		}
	} else {
		if reqd, exits := s.RequestDict.Get(rspid); exits {
			dura := v.Timestap.Sub(reqd.(*p.Packet).Timestap)
			h.Stats.AddDuration(dura)
			if dura >= c.GetSlowDura() {
				h.Stats.IncrSlowlog(1)
				msg := fmt.Sprintf("%v | %s | %v | %v",
					(reqd.(*p.Packet).Timestap).Format("2006-01-02 15:04:05"), rspid, dura,
					reqd.(*p.Packet).Content)
				if c.GetShowrsp() {
					msg += fmt.Sprintf(" | %v", v.Content)
				}
				fmt.Println(msg)
			}
			s.RequestDict.Remove(rspid)
		}
		// TODO: The statistical time-consuming of multiple reply packets may be small
	}
}

// IsNoReply noreply commands
func (h *Hamburg) IsNoReply(pl string) bool {
	plen := len(pl)
	switch h.Conf.protocol {
	case p.Redis:
		return plen > 12 && strings.LastIndex(pl, "REPLCONF ACK") == 0
	case p.Memcached:
		for index, cmd := range noReplyCommands {
			if strings.LastIndex(pl, cmd) == 0 {
				if index >= 6 && plen > 7 && strings.Contains(pl[7:], "noreply") {
					return true
				}
				return false
			}
		}
		return false
	default:
		return false
	}
}

// SavePackets save packets to local file
func (h *Hamburg) SavePackets(p *gopacket.Packet) {
	s := h.Sniffer
	if s != nil && s.OutFileHWriter != nil {
		s.OutFileHWriter.WritePacket((*p).Metadata().CaptureInfo, (*p).Data())
	}
}
