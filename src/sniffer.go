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
	StartTime      time.Time         // start sniffing time
	EndTime        time.Time         // end sniffing time
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
	var filters []string
	var portf []string
	s := h.Sniffer
	c := h.Conf
	ips := c.GetIPs()
	ports := c.GetPorts()
	filter := c.GetFilter()

	// Ports filter
	for _, port := range ports {
		if len(port) != 0 {
			portf = append(portf, fmt.Sprintf("(port %s)", port))
		}
	}
	filters = h.AddFilters(filters, portf)

	// IPs filter
	var serverf []string
	for _, server := range ips {
		if len(server) != 0 {
			serverf = append(serverf, fmt.Sprintf("(host %s)", server))
		}
	}
	filters = h.AddFilters(filters, serverf)

	// Custom filter
	if filter != "" {
		filters = h.AddFilters(filters, []string{fmt.Sprintf("(%s)", filter)})
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
func (h *Hamburg) AddFilters(filters []string, ret []string) []string {
	if len(filters) != 0 {
		if len(ret) != 0 {
			for i := range filters {
				filters[i] = fmt.Sprintf("%s and (%s)", filters[i], strings.Join(ret, " or "))
			}
		}
		return filters
	}

	return ret
}

// SavePackets save packets to local file
func (h *Hamburg) SavePackets(packet *gopacket.Packet) {
	s := h.Sniffer
	if s != nil && s.OutFileHWriter != nil {
		s.OutFileHWriter.WritePacket((*packet).Metadata().CaptureInfo, (*packet).Data())
	}
}
