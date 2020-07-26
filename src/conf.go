package src

import (
	"fmt"
	"time"

	"github.com/bugwz/hamburg/utils"
)

// Conf conf
type Conf struct {
	InterFile         string        // network interface or offline pcap file
	OutFile           string        // file to save the captured package
	Server            []string      // capture packets of the specified ips
	Port              []string      // capture packets of the specified ports
	Protocol          int           // contents protocol of packets, default is raw
	Threshold         time.Duration // packets round trip time threshold, default is 5ms
	Count             int64         // sniff the total amount of all packets, default is 0 (not limit)
	Duration          time.Duration // the duration of the captured packet, default is 0 (not limit)
	LuaFile           string        // use lua scripts to process captured packets
	SnapLen           int32         // maximum length of captured data packet, default is 1500
	CustomFilter      string        // custom filter to capture packets
	ReadPacketTimeout time.Duration // read packet timeout, default is 30s
	ShowResponse      bool          // show the contents of the reply packet, default is false
}

// InitConf init conf
func (t *Hamburg) InitConf() {
	t.Conf = &Conf{
		Threshold:         time.Duration(5) * time.Millisecond,
		Count:             0,
		Duration:          time.Duration(0),
		SnapLen:           1500,
		ReadPacketTimeout: time.Duration(30) * time.Second,
		ShowResponse:      false,
	}
}

// VerifyConf check confs
func (t *Hamburg) VerifyConf() error {
	c := t.Conf
	if c.InterFile == "" {
		return fmt.Errorf("Must specify a network card device or offline pcap data file")
	}

	if utils.FileIsExist(c.OutFile) {
		return fmt.Errorf("The packet output file %s already exists", c.OutFile)
	}

	if err := utils.VerifyIPs(c.Server); err != nil {
		return err
	}

	if err := utils.VerifyPorts(c.Port); err != nil {
		return err
	}

	if c.Protocol <= 0 || c.Protocol > len(ProtocolType) {
		return fmt.Errorf("Protocol %s is illegal", ProtocolType[c.Protocol])
	}

	if c.Threshold < 0 {
		return fmt.Errorf("Packets round trip time threshold must be greater than or equal to 0")
	}

	if c.Count < 0 {
		return fmt.Errorf("Sniff the total amount of all packets must be greater than or equal to 0(not limit)")
	}

	if c.Duration < 0 {
		return fmt.Errorf("Duration of the captured packet must be greater than or equal to 0(not limit)")
	}

	if c.LuaFile != "" {
		if !utils.FileIsExist(c.LuaFile) {
			return fmt.Errorf("Not found lua file %s", c.LuaFile)
		}
	}

	if c.SnapLen <= 0 {
		return fmt.Errorf("Maximum length of captured data packet must be greater than 0")
	}

	if c.ReadPacketTimeout <= 0 {
		return fmt.Errorf("read packet timeout must be greater than 0")
	}

	return nil
}
