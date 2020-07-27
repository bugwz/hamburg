package src

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/bugwz/hamburg/utils"
	"github.com/emirpasic/gods/maps/hashmap"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

// tcp/ucp protocol
const (
	TCP = "TCP"
	UDP = "UDP"
)

// tcp flags
const (
	THFIN = 0x01
	THSYN = 0x02
	THRST = 0x04
	THPSH = 0x08
	THACK = 0x10
	THURG = 0x20
	THECE = 0x40
	THCWR = 0x80
)

var noReplyCommands = []string{
	"get", "gets", "stats", "stat", "watch", "lru",
	"set", "add", "incr", "decr", "delete", "replace",
	"append", "prepend", "cas", "touch", "flushall",
}

// Sniffer sniffer
type Sniffer struct {
	PcapHandle     *pcap.Handle
	LocalIPs       map[string]string // local ips
	Promisc        bool              // nic promiscuous mode, default is false
	StartTime      time.Time         // start sniffing time
	EndTime        time.Time         // end sniffing time
	RequestDict    *hashmap.Map      // record request data packets, used to calculate statistics time-consuming
	CapturedCount  int64             // number of captured packets
	OutFileHandle  *os.File          // file handle saved by the packet
	OutFileHWriter *pcapgo.Writer    // write file
	Quit           bool              // whether to stop sniffing packets
}

// InitSniffer init
func (h *Hamburg) InitSniffer() error {
	h.Sniffer = &Sniffer{
		Promisc:     false,
		RequestDict: hashmap.New(),
	}

	return nil
}

// CreatePcapHandle pcap handle with offline file or network interface
func (h *Hamburg) CreatePcapHandle() error {
	var err error
	s := h.Sniffer
	c := h.Conf

	// monitor offline pcap file
	if utils.FileIsExist(c.InterFile) {
		if s.PcapHandle, err = pcap.OpenOffline(c.InterFile); err != nil {
			return fmt.Errorf("Monitor offline pcap file %s failed: %v", c.InterFile, err)
		}

		return nil
	}

	// monitor network interface
	if s.PcapHandle, err = pcap.OpenLive(c.InterFile, c.SnapLen, s.Promisc, c.ReadPacketTimeout); err != nil {
		return fmt.Errorf("Monitor network interface %s failed: %v", c.InterFile, err)
	}
	ips, err := utils.GetInterfaceIPs(c.InterFile)
	if err != nil {
		return err
	}
	s.LocalIPs = ips

	utils.PrintDeviceDetail(c.InterFile)
	return nil
}

// CreatePcapWriter save packets to local file
func (h *Hamburg) CreatePcapWriter() error {
	s := h.Sniffer
	c := h.Conf
	if c.OutFile != "" {
		handle, err := os.Create(c.OutFile)
		if err != nil {
			return fmt.Errorf("Create out file %s failed: %v", c.OutFile, err)
		}
		s.OutFileHandle = handle
		s.OutFileHWriter = pcapgo.NewWriter(s.OutFileHandle)
		s.OutFileHWriter.WriteFileHeader(uint32(c.SnapLen), layers.LinkTypeEthernet)
	}

	return nil
}

// CreateFilter packet filtering rules
func (h *Hamburg) CreateFilter() error {
	var filters []string
	var portf []string
	s := h.Sniffer
	c := h.Conf

	// ports filter
	for _, port := range c.Port {
		if len(port) != 0 {
			portf = append(portf, fmt.Sprintf("(port %s)", port))
		}
	}
	filters = h.AddFilters(filters, portf)

	// servers filter
	var serverf []string
	for _, server := range c.Server {
		if len(server) != 0 {
			serverf = append(serverf, fmt.Sprintf("(host %s)", server))
		}
	}
	filters = h.AddFilters(filters, serverf)

	// custom filter
	if c.CustomFilter != "" {
		filters = h.AddFilters(filters, []string{fmt.Sprintf("(%s)", c.CustomFilter)})
	}

	for i := range filters {
		filters[i] = fmt.Sprintf("(%s)", filters[i])
	}
	if err := s.PcapHandle.SetBPFFilter(strings.Join(filters, " or ")); err != nil {
		return fmt.Errorf("Set bpf filter faile: %v", err)
	}

	fmt.Printf("\r\nStart capturing packet with filter: %v\r\n", strings.Join(filters, " or "))
	return nil
}

// AddFilters add some filter rules
func (h *Hamburg) AddFilters(filters []string, add []string) []string {
	if len(filters) != 0 {
		if len(add) != 0 {
			for i := range filters {
				filters[i] = fmt.Sprintf("%s and (%s)", filters[i], strings.Join(add, " or "))
			}
		}
		return filters
	}

	return add
}

// SavePackets save packets to local file
func (h *Hamburg) SavePackets(packet *gopacket.Packet) {
	s := h.Sniffer
	if s != nil && s.OutFileHWriter != nil {
		s.OutFileHWriter.WritePacket((*packet).Metadata().CaptureInfo, (*packet).Data())
	}
}

// RunCapture start capture packets
func (h *Hamburg) RunCapture(sig chan os.Signal) {
	// TODO: The defer execution takes a long time, how to optimize ?
	defer h.Wg.Done()

	s := h.Sniffer
	s.StartTime = time.Now()

	// pcap handle with local file or network interface
	if err := h.CreatePcapHandle(); err != nil {
		fmt.Println(err)
		return
	}
	defer s.PcapHandle.Close()

	// create pcap filter
	if err := h.CreateFilter(); err != nil {
		fmt.Println(err)
		return
	}

	// create pcap write handle to save packets to local file
	if err := h.CreatePcapWriter(); err != nil {
		fmt.Println(err)
		return
	}
	defer s.OutFileHandle.Close()

	// start capture packets
	packetSource := gopacket.NewPacketSource(s.PcapHandle, s.PcapHandle.LinkType())
	for {
		select {
		case p := <-packetSource.Packets():
			// save packets to local file
			h.SavePackets(&p)

			// process decoded packet by lua or predefined methods
			h.ProcessPackets(&p, h.ParsePacketLayers(&p))
			if !h.IsContinue() {
				h.PrintStats()
				return
			}
		case <-sig:
			s.Quit = true
		default:
			if !h.IsContinue() {
				h.PrintStats()
				return
			}
		}
	}
}

// ProcessPackets process decoding packets
func (h *Hamburg) ProcessPackets(packet *gopacket.Packet, detail *utils.PacketDetail) {
	s := h.Sniffer
	c := h.Conf

	// process packet with lua
	if h.Lua != nil && h.Lua.LState != nil {
		h.ProcessPacketsWithLua(detail)
		return
	}

	reqid := fmt.Sprintf("%15s:%-5s => %15s:%-5s", detail.SrcIP, detail.SrcPort, detail.DstIP, detail.DstPort)
	rspid := fmt.Sprintf("%15s:%-5s => %15s:%-5s", detail.DstIP, detail.DstPort, detail.SrcIP, detail.SrcPort)

	if detail.Payload == "" {
		if detail.Direction == "REQ" && detail.Flag&THSYN != 0 {
			s.RequestDict.Remove(reqid)
		}
		if detail.Direction == "RSP" &&
			(detail.Flag&THRST != 0 || detail.Flag&THFIN != 0) {
			s.RequestDict.Remove(rspid)
		}
		return
	}

	if detail.Direction == "REQ" {
		// noreply commands
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
			h.IncrTimeIntervalCount(dura)
			if dura >= c.Threshold {
				h.IncrSlowlogCount()
				msg := fmt.Sprintf("%v || %s || %v || %v",
					(reqd.(*utils.PacketDetail).Timestap).Format("2006-01-02 15:04:05"), rspid, dura,
					reqd.(*utils.PacketDetail).Content)
				if c.ShowResponse {
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
	switch h.Conf.Protocol {
	case PTRedis:
		return plen > 12 && strings.LastIndex(payload, "REPLCONF ACK") == 0
	case PTMemcached:
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

// IsContinue whether to continue to capture packets
func (h *Hamburg) IsContinue() bool {
	c := h.Conf
	s := h.Sniffer

	if s.Quit {
		return false
	}

	if c.Duration != 0 && time.Now().Sub(s.StartTime) > c.Duration {
		return false
	}

	if c.Count != 0 && s.CapturedCount >= c.Count {
		fmt.Println("Will stop capturing packets...")
		return false
	}

	return true
}
