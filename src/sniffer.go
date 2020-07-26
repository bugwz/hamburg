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

// Dump dump
type Dump struct {
	File   string
	Handle *os.File
	Writer *pcapgo.Writer
}

// PacketNode node
type PacketNode struct {
	Meta    *gopacket.PacketMetadata
	Command []string
}

// SYNNode syn node
type SYNNode struct {
	IP   string
	Port string
}

// InitSniffer init
func (t *Hamburg) InitSniffer() error {
	t.Sniffer = &Sniffer{
		Promisc:     false,
		RequestDict: hashmap.New(),
	}

	return nil
}

// CreatePcapHandle pcap handle with offline file or network interface
func (t *Hamburg) CreatePcapHandle() error {
	var err error
	s := t.Sniffer
	c := t.Conf

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

// CreateFilter packet filtering rules
func (t *Hamburg) CreateFilter() error {
	var filters []string
	var portf []string
	s := t.Sniffer
	c := t.Conf

	// ports filter
	for _, port := range c.Port {
		if len(port) != 0 {
			portf = append(portf, fmt.Sprintf("(port %s)", port))
		}
	}
	filters = t.AddFilters(filters, portf)

	// servers filter
	var serverf []string
	for _, server := range c.Server {
		if len(server) != 0 {
			serverf = append(serverf, fmt.Sprintf("(host %s)", server))
		}
	}
	filters = t.AddFilters(filters, serverf)

	// custom filter
	if c.CustomFilter != "" {
		filters = t.AddFilters(filters, []string{fmt.Sprintf("(%s)", c.CustomFilter)})
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
func (t *Hamburg) AddFilters(filters []string, add []string) []string {
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

// CreatePcapWriter save packets to local file
func (t *Hamburg) CreatePcapWriter() error {
	s := t.Sniffer
	c := t.Conf
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

// SavePackets save packets to local file
func (t *Hamburg) SavePackets(packet *gopacket.Packet) {
	s := t.Sniffer
	if s != nil && s.OutFileHWriter != nil {
		s.OutFileHWriter.WritePacket((*packet).Metadata().CaptureInfo, (*packet).Data())
	}
}

// RunCapture start capture packets
func (t *Hamburg) RunCapture(sig chan os.Signal) {
	defer t.Wg.Done()

	s := t.Sniffer
	s.StartTime = time.Now()

	// pcap handle with local file or network interface
	if err := t.CreatePcapHandle(); err != nil {
		fmt.Println(err)
		return
	}
	defer s.PcapHandle.Close()

	// create pcap filter
	if err := t.CreateFilter(); err != nil {
		fmt.Println(err)
		return
	}

	// create pcap write handle to save packets to local file
	if err := t.CreatePcapWriter(); err != nil {
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
			t.SavePackets(&p)

			// process decoded packet by lua or predefined methods
			t.ProcessPackets(&p, t.DecodingPackets(&p))
		case <-sig:
			s.Quit = true
		default:
			if !t.IsContinue() {
				t.PrintStats()
				return
			}
		}
	}
}

// IsContinue whether to continue to capture packets
func (t *Hamburg) IsContinue() bool {
	c := t.Conf
	s := t.Sniffer

	if s.Quit || time.Now().Sub(s.StartTime) > c.Duration || s.CapturedCount == c.Count {
		fmt.Println("Will stop capturing packets...")
		return false
	}

	return true
}

// ProcessPackets process packets using predefined rules
func (t *Hamburg) ProcessPackets(packet *gopacket.Packet, detail *utils.PacketDetail) {
	s := t.Sniffer
	c := t.Conf

	// process packet with lua
	if t.Lua != nil && t.Lua.LState != nil {
		t.ProcessPacketsWithLua(detail)
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
		if t.IsNoReply(detail.Payload) {
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
			t.IncrTimeIntervalCount(dura)
			if dura >= c.Threshold {
				t.IncrSlowlogCount()
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

// DecodingPackets decode packets
func (t *Hamburg) DecodingPackets(packet *gopacket.Packet) *utils.PacketDetail {
	s := t.Sniffer
	c := t.Conf

	s.CapturedCount++
	d := &utils.PacketDetail{Type: t.DecodingPacketsLayers(*packet)}
	d.Timestap = (*packet).Metadata().CaptureInfo.Timestamp

	// ethernet layer
	if ethernet := t.DecodingPacketsEthernetLayer(*packet); ethernet != nil {
		d.SrcMAC = ethernet.SrcMAC.String()
		d.DstMAC = ethernet.DstMAC.String()
	}

	// ip layer
	if ip := t.DecodingPacketsIPLayer(*packet); ip != nil {
		d.SrcIP = fmt.Sprintf("%s", ip.SrcIP)
		d.DstIP = fmt.Sprintf("%s", ip.DstIP)

		// set direction
		d.Direction = "None"
		if s.LocalIPs[d.SrcIP] != "" {
			d.Direction = "RSP"
		}
		if s.LocalIPs[d.DstIP] != "" {
			d.Direction = "REQ"
		}
	}

	// udp layer
	if udp := t.DecodingPacketsUDPLayer(*packet); udp != nil {
		d.SrcPort = fmt.Sprintf("%d", udp.SrcPort)
		d.DstPort = fmt.Sprintf("%d", udp.DstPort)
		d.CheckSum = fmt.Sprintf("%d", udp.Checksum)
		d.PayloadLen = int(udp.Length)
		d.Payload = string(udp.BaseLayer.LayerPayload())
	}

	// tcp layer
	if tcp := t.DecodingPacketsTCPLayer(*packet); tcp != nil {
		d.SrcPort = fmt.Sprintf("%d", tcp.SrcPort)
		d.DstPort = fmt.Sprintf("%d", tcp.DstPort)
		d.CheckSum = fmt.Sprintf("%d", tcp.Checksum)
		d.Sequence = fmt.Sprintf("%d", tcp.Seq)

		// parse flag
		var fstr []string
		fint := 0
		if tcp.FIN {
			fint |= THFIN
			fstr = append(fstr, "FIN")
		}
		if tcp.SYN {
			fint |= THSYN
			fstr = append(fstr, "SYN")
		}
		if tcp.RST {
			fint |= THRST
			fstr = append(fstr, "RST")
		}
		if tcp.PSH {
			fint |= THPSH
			fstr = append(fstr, "PSH")
		}
		if tcp.ACK {
			fint |= THACK
			fstr = append(fstr, "ACK")
		}
		if tcp.URG {
			fint |= THURG
			fstr = append(fstr, "URG")
		}
		if tcp.ECE {
			fint |= THECE
			fstr = append(fstr, "ECE")
		}
		if tcp.CWR {
			fint |= THCWR
			fstr = append(fstr, "CWR")
		}
		d.Flag = fint
		d.FlagStr = strings.Join(fstr, ",")
		d.ACK = fmt.Sprintf("%d", tcp.Ack)
	}

	// set direction
	if d.SrcPort != "" && d.DstPort != "" {
		for _, port := range c.Port {
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

	// parse payload
	if app := (*packet).ApplicationLayer(); app != nil {
		if string(app.Payload()) != "" {
			d.Payload = string(app.Payload())
			d.PayloadLen = (*packet).Metadata().CaptureLength
		}
	}
	t.ParsePayload(d)

	// update stats
	if d.Direction == "REQ" {
		t.IncrRequestCount()
	} else if d.Direction == "RSP" {
		t.IncrResponseCount()
	}

	// tmp log
	// fmt.Printf("%s:%s => %s:%s, direction is %s, flags is %s content is %s\r\n",
	// 	d.SrcIP, d.SrcPort, d.DstIP, d.DstPort, d.Direction, d.FlagStr, d.Content)

	return d
}

// DecodingPacketsLayers decoding packets all layers
func (t *Hamburg) DecodingPacketsLayers(packet gopacket.Packet) string {
	var packets []string
	for _, layer := range packet.Layers() {
		v := strings.ReplaceAll(fmt.Sprintln(layer.LayerType()), "\n", "")
		if v != "Ethernet" && v != "Payload" {
			packets = append(packets, v)
		}
	}

	return strings.Join(packets, "/")
}

// DecodingPacketsEthernetLayer parsing the Ethernet layer data of the packet
func (t *Hamburg) DecodingPacketsEthernetLayer(packet gopacket.Packet) *layers.Ethernet {
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		return ethernetPacket
	}

	return nil
}

// DecodingPacketsIPLayer parsing the IP layer data of the packet
func (t *Hamburg) DecodingPacketsIPLayer(packet gopacket.Packet) *layers.IPv4 {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		return ip
	}

	return nil
}

// DecodingPacketsTCPLayer parsing the TCP layer data of the packet
func (t *Hamburg) DecodingPacketsTCPLayer(packet gopacket.Packet) *layers.TCP {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		return tcp
	}

	return nil
}

// DecodingPacketsUDPLayer parsing the UDP layer data of the packet
func (t *Hamburg) DecodingPacketsUDPLayer(packet gopacket.Packet) *layers.UDP {
	tcpLayer := packet.Layer(layers.LayerTypeUDP)
	if tcpLayer != nil {
		udp, _ := tcpLayer.(*layers.UDP)
		return udp
	}

	return nil
}

// IsNoReply match messages with noreply status
func (t *Hamburg) IsNoReply(payload string) bool {
	plen := len(payload)
	switch t.Conf.Protocol {
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
