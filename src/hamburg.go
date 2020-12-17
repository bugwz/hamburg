package src

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	p "github.com/bugwz/hamburg/parser"
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
			h.ParsePackets(h.LayersParser(&p))
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
func (h *Hamburg) ParsePackets(d *utils.Packet) {
	s := h.Sniffer
	c := h.Conf

	// Try parse packets with with lua script
	if h.Conf.script.Run(d) == nil {
		return
	}

	srcid := fmt.Sprintf("%s:%s", d.SrcIP, d.SrcPort)
	dstid := fmt.Sprintf("%s:%s", d.DstIP, d.DstPort)
	reqid := fmt.Sprintf("%s -> %s", srcid, dstid)
	rspid := fmt.Sprintf("%s -> %s", dstid, srcid)
	if d.Payload == "" {
		if d.Direction == "REQ" && d.Flag&SYN != 0 {
			s.RequestDict.Remove(reqid)
		}
		if d.Direction == "RSP" && (d.Flag&RST != 0 || d.Flag&FIN != 0) {
			s.RequestDict.Remove(rspid)
		}
		return
	}

	if d.Direction == "REQ" {
		// Filter noreply commands
		if h.IsNoReply(d.Payload) {
			return
		}
		old, exits := s.RequestDict.Get(reqid)
		if !exits {
			s.RequestDict.Put(reqid, d)
		} else {
			old.(*utils.Packet).Content += " " + d.Content
		}
	} else {
		if reqd, exits := s.RequestDict.Get(rspid); exits {
			dura := d.Timestap.Sub(reqd.(*utils.Packet).Timestap)
			h.Stats.AddDuration(dura)
			if dura >= c.GetSlowDura() {
				h.Stats.IncrSlowlog(1)
				msg := fmt.Sprintf("%v | %s | %v | %v",
					(reqd.(*utils.Packet).Timestap).Format("2006-01-02 15:04:05"), rspid, dura,
					reqd.(*utils.Packet).Content)
				if c.GetShowrsp() {
					msg += fmt.Sprintf(" | %v", d.Content)
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

// PayloadParser parse payload
func (h *Hamburg) PayloadParser(d *utils.Packet) {
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
