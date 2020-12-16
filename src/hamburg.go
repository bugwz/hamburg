package src

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	p "github.com/bugwz/hamburg/protocol"
	"github.com/bugwz/hamburg/utils"
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
	done    chan int
}

// NewHamburg new
func NewHamburg() *Hamburg {
	return &Hamburg{
		Conf:    NewConf(),
		Sniffer: NewSniffer(),
		Stats:   NewStats(),
		done:    make(chan int),
	}
}

// Run run
func (h *Hamburg) Run() {
	s := h.Sniffer
	s.StartTime = time.Now()

	// Check confs
	if err := h.Conf.CheckConfs(); err != nil {
		fmt.Println(err)
		return
	}

	// Pcap handle with local file or network interface
	if err := h.CreatePcapHandle(); err != nil {
		fmt.Println(err)
		return
	}
	defer s.PcapHandle.Close()

	// Create pcap filter
	if err := h.CreateFilter(); err != nil {
		fmt.Println(err)
		return
	}

	// Create pcap write handle to save packets to local file
	if err := h.CreatePcapWriter(); err != nil {
		fmt.Println(err)
		return
	}
	defer s.OutFileHandle.Close()

	// Schedule process
	h.Scheduler()

	// Start capture packets
	packetSource := gopacket.NewPacketSource(s.PcapHandle, s.PcapHandle.LinkType())
	for {
		select {
		case <-h.done:
			h.Stats.ShowStats()
			return
		case p := <-packetSource.Packets():
			// Save packets to local file
			h.SavePackets(&p)

			// Parse decoded packets
			h.ParsePackets(&p, h.ParsePacketLayers(&p))
		}
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
			case <-time.After(h.Conf.duration):
				h.done <- TimeoutExit
				return
			}
		}
	}()
}

// ParsePackets process decoding packets
func (h *Hamburg) ParsePackets(packet *gopacket.Packet, detail *utils.PacketDetail) {
	s := h.Sniffer
	c := h.Conf

	// Try parse packets with with lua script
	if h.Conf.script.Run(detail) == nil {
		return
	}

	reqid := fmt.Sprintf("%15s:%-5s => %15s:%-5s", detail.SrcIP, detail.SrcPort, detail.DstIP, detail.DstPort)
	rspid := fmt.Sprintf("%15s:%-5s => %15s:%-5s", detail.DstIP, detail.DstPort, detail.SrcIP, detail.SrcPort)
	if detail.Payload == "" {
		if detail.Direction == "REQ" && detail.Flag&SYN != 0 {
			s.RequestDict.Remove(reqid)
		}
		if detail.Direction == "RSP" && (detail.Flag&RST != 0 || detail.Flag&FIN != 0) {
			s.RequestDict.Remove(rspid)
		}
		return
	}

	if detail.Direction == "REQ" {
		// Filter noreply commands
		if h.IsNoReply(detail.Payload) {
			return
		}
		old, exits := s.RequestDict.Get(reqid)
		if !exits {
			s.RequestDict.Put(reqid, detail)
		} else {
			old.(*utils.PacketDetail).Content += " " + detail.Content
		}
	} else {
		if reqd, exits := s.RequestDict.Get(rspid); exits {
			dura := detail.Timestap.Sub(reqd.(*utils.PacketDetail).Timestap)
			h.Stats.IncrTimeIntervalCount(dura)
			if dura >= c.slowdura {
				h.Stats.IncrSlowlogCount()
				msg := fmt.Sprintf("%v || %s || %v || %v",
					(reqd.(*utils.PacketDetail).Timestap).Format("2006-01-02 15:04:05"), rspid, dura,
					reqd.(*utils.PacketDetail).Content)
				if c.showrsp {
					msg += fmt.Sprintf(" || %v", detail.Content)
				}
				fmt.Println(msg)
			}
			s.RequestDict.Remove(rspid)
		}
		// TODO: The statistical time-consuming of multiple reply packets may be small
	}
}

// IsNoReply noreply commands
func (h *Hamburg) IsNoReply(payload string) bool {
	plen := len(payload)
	switch h.Conf.protocol {
	case p.Redis:
		return plen > 12 && strings.LastIndex(payload, "REPLCONF ACK") == 0
	case p.Memcached:
		for index, cmd := range noReplyCommands {
			if strings.LastIndex(payload, cmd) == 0 {
				if index >= 6 && plen > 7 && strings.Contains(payload[7:], "noreply") {
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

// PayloadParser parse payload
func (h *Hamburg) PayloadParser(d *utils.PacketDetail) {
	if d.Payload != "" {
		switch h.Conf.GetProtocol() {
		case p.RAW:
			p.RAWParser(d)
		case p.DNS:
			p.DNSParser(d)
		case p.HTTP:
			p.HTTPParser(d)
		case p.Redis:
			p.RedisParser(d)
		case p.Memcached:
			p.MemcachedParser(d)
		case p.MySQL:
			p.MySQLParser(d)
		default:
			d.Content = ""
		}
	}
}
