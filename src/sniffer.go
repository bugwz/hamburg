package src

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/bugwz/hamburg/utils"
	"github.com/emirpasic/gods/maps/hashmap"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

// Protocol type
const (
	TCP = "TCP"
	UDP = "UDP"
)

// Flags for tcp
const (
	FIN = 0x01
	SYN = 0x02
	RST = 0x04
	PSH = 0x08
	ACK = 0x10
	URG = 0x20
	ECE = 0x40
	CWR = 0x80
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
	StartAt        time.Time         // start sniffing time
	RequestDict    *hashmap.Map      // record request data packets, used to calculate statistics time-consuming
	CapturedCount  int64             // number of captured packets
	OutFileHandle  *os.File          // file handle saved by the packet
	OutFileHWriter *pcapgo.Writer    // write file
	Quit           bool              // whether to stop sniffing packets
}

// NewSniffer new sniffer
func NewSniffer() *Sniffer {
	return &Sniffer{
		Promisc:     false,
		RequestDict: hashmap.New(),
	}
}

// CreatePcapHandle pcap handle with offline file or network interface
func (h *Hamburg) CreatePcapHandle() error {
	var err error
	s := h.Sniffer
	c := h.Conf
	interfile := c.GetInterfile()
	snapLen := c.GetSnapLen()
	rtimeout := c.GetReadtimeout()

	// Monitor offline pcap file
	if utils.FileIsExist(interfile) {
		if s.PcapHandle, err = pcap.OpenOffline(interfile); err != nil {
			return fmt.Errorf("Monitor offline pcap file %s failed: %v", interfile, err)
		}

		return nil
	}

	// Monitor network interface
	if s.PcapHandle, err = pcap.OpenLive(interfile, snapLen, s.Promisc, rtimeout); err != nil {
		return fmt.Errorf("Monitor network interface %s failed: %v", interfile, err)
	}
	ips, err := utils.GetInterfaceIPs(interfile)
	if err != nil {
		return err
	}
	s.LocalIPs = ips

	utils.PrintDeviceDetail(interfile)
	return nil
}

// CreatePcapWriter save packets to local file
func (h *Hamburg) CreatePcapWriter() error {
	s := h.Sniffer
	c := h.Conf
	outfile := c.GetOutFile()
	snapLen := c.GetSnapLen()

	if outfile != "" {
		handle, err := os.Create(outfile)
		if err != nil {
			return fmt.Errorf("Create out file %s failed: %v", outfile, err)
		}
		s.OutFileHandle = handle
		s.OutFileHWriter = pcapgo.NewWriter(s.OutFileHandle)
		s.OutFileHWriter.WriteFileHeader(uint32(snapLen), layers.LinkTypeEthernet)
	}

	return nil
}

// CreateFilter packet filtering rules
func (h *Hamburg) CreateFilter() error {
	var fts []string
	var pfts []string

	// Ports filter
	for _, port := range h.Conf.GetPorts() {
		if len(port) != 0 {
			pfts = append(pfts, fmt.Sprintf("(port %s)", port))
		}
	}
	fts = h.AddFilters(fts, pfts)

	// IPs filter
	var serverf []string
	for _, server := range h.Conf.GetIPs() {
		if len(server) != 0 {
			serverf = append(serverf, fmt.Sprintf("(host %s)", server))
		}
	}
	fts = h.AddFilters(fts, serverf)

	// Custom filter
	ft := h.Conf.GetFilter()
	if ft != "" {
		fts = h.AddFilters(fts, []string{fmt.Sprintf("(%s)", ft)})
	}

	for i := range fts {
		fts[i] = fmt.Sprintf("(%s)", fts[i])
	}
	if err := h.Sniffer.PcapHandle.SetBPFFilter(strings.Join(fts, " or ")); err != nil {
		return fmt.Errorf("Set bpf filter faile: %v", err)
	}

	fmt.Printf("\r\nStart capturing packet with filter: %v\r\n", strings.Join(fts, " or "))
	return nil
}

// AddFilters add some filter rules
func (h *Hamburg) AddFilters(fts []string, ret []string) []string {
	if len(fts) != 0 {
		if len(ret) != 0 {
			for i := range fts {
				fts[i] = fmt.Sprintf("%s and (%s)", fts[i], strings.Join(ret, " or "))
			}
		}
		return fts
	}

	return ret
}
