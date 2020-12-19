package src

import (
	"fmt"
	"time"

	u "github.com/bugwz/hamburg/utils"
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
	ips       []string          // Filtering IPs in packets
	ports     []string          // Filtering Ports in packets
	localip   map[string]string // IP list obtained from local NIC
	pktreader *pcap.Handle      // Packet source
	pktwriter *pcapgo.Writer    // Save packet
	nic       *pcap.Interface   // Monitored NIC
	duration  time.Duration     // Period of packet capture
	promisc   bool              // NIC promiscuous mode
	start     time.Time         // The moment the capture begins
}

// NewSniffer new sniffer
func NewSniffer(c *Conf) (*Sniffer, error) {
	ips, e := u.GetIPs(c.FilterIPs)
	if e != nil {
		return nil, e
	}

	ports, e := u.GetPorts(c.FilterPorts)
	if e != nil {
		return nil, e
	}

	localips, e := u.GetLocalIPs(c.InterFile)
	if e != nil {
		return nil, e
	}

	pktreader, e := u.GetPacketReader(c.InterFile, c.SnapLen, c.ReadTimeout)
	if e != nil {
		return nil, e
	}

	pktwriter, e := u.GetPacketWriter(c.Outfile, c.SnapLen)
	if e != nil {
		return nil, e
	}

	filters, e := u.PacketFilter(c.FilterCustom, c.FilterPorts, c.FilterIPs)
	if e != nil {
		return nil, e
	}
	if e := pktreader.SetBPFFilter(filters); e != nil {
		return nil, fmt.Errorf("Set bpf filter faile: %v", e)
	}

	return &Sniffer{
		ips:       ips,
		ports:     ports,
		localip:   localips,
		pktreader: pktreader,
		pktwriter: pktwriter,
		nic:       u.GetNIC(c.InterFile),
		duration:  time.Duration(c.Duration) * time.Second,
	}, nil
}

// SetStartTime set start time
func (s *Sniffer) SetStartTime() {
	s.start = time.Now()
}

// GetStartTime set start time
func (s *Sniffer) GetStartTime() time.Time {
	return s.start
}

// GetDuration get duration
func (s *Sniffer) GetDuration() time.Duration {
	return s.duration
}

// NICDetail nic detail
func (s *Sniffer) NICDetail() {
	if s.nic == nil {
		return
	}

	fmt.Println("\nName: ", s.nic.Name)
	fmt.Println("Description: ", s.nic.Description)
	fmt.Println("Devices addresses: ", s.nic.Description)
	for _, ads := range s.nic.Addresses {
		fmt.Println("- IP address: ", ads.IP)
		fmt.Println("- Subnet mask: ", ads.Netmask)
	}
}
