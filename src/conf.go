package src

import (
	"fmt"
	"time"

	u "github.com/bugwz/hamburg/utils"
)

// Conf conf
type Conf struct {
	interfile   string        // network interface or offline pcap file
	outfile     string        // file to save the captured package
	ips         []string      // capture packets of the specified ips
	ports       []string      // capture packets of the specified ports
	protocol    string        // contents protocol of packets, default is raw
	slowdura    time.Duration // slow packets round trip time threshold, default is 5ms
	duration    time.Duration // the duration of the captured packet, default is 0 (not limit)
	script      *Script       // use lua scripts to process captured packets
	snapLen     int32         // maximum length of captured data packet, default is 1500
	filter      string        // custom filter to capture packets
	readtimeout time.Duration // read packet timeout, default is 30s
	showrsp     bool          // show the contents of the reply packet, default is false
}

// NewConf new conf
func NewConf() *Conf {
	return &Conf{
		slowdura:    time.Duration(5) * time.Millisecond,
		duration:    time.Duration(0),
		snapLen:     1500,
		readtimeout: time.Duration(30) * time.Second,
		showrsp:     false,
	}
}

// SetScript set lua script
func (c *Conf) SetScript(k string) {
	c.script = NewScript(k)
}

// SetInterfile set interfile
func (c *Conf) SetInterfile(k string) {
	c.interfile = k
}

// SetOutFile set outfile
func (c *Conf) SetOutFile(k string) {
	c.outfile = k
}

// SetIPs set ips for src or dst
func (c *Conf) SetIPs(k []string) {
	if u.VerifyIPs(k) != nil {
		return
	}
	c.ips = k
}

// SetPorts set ports for src or dst
func (c *Conf) SetPorts(k []string) {
	if u.VerifyPorts(k) != nil {
		return
	}
	c.ports = k
}

// SetSlowDura set slow request duration
func (c *Conf) SetSlowDura(k time.Duration) {
	if k < 0 {
		return
	}
	c.slowdura = k
}

// SetDuration set the max time for capturing
func (c *Conf) SetDuration(k time.Duration) {
	if k < 0 {
		return
	}
	c.duration = k
}

// SetSnapLen set the snap len
func (c *Conf) SetSnapLen(k int32) {
	if k <= 0 {
		return
	}
	c.snapLen = k
}

// SetFilter set custom filter
func (c *Conf) SetFilter(k string) {
	c.filter = k
}

// SetShowrsp set slow request duration
func (c *Conf) SetShowrsp(k bool) {
	c.showrsp = k
}

// SetProtocol set the protocol for packets
func (c *Conf) SetProtocol(k string) {
	c.protocol = k
}

// GetScript get
func (c *Conf) GetScript() *Script {
	return c.script
}

// GetInterfile get interfile
func (c *Conf) GetInterfile() string {
	return c.interfile
}

// GetOutFile get outfile
func (c *Conf) GetOutFile() string {
	return c.outfile
}

// GetIPs get ips for src or dst
func (c *Conf) GetIPs() []string {
	return c.ips
}

// GetPorts get ports for src or dst
func (c *Conf) GetPorts() []string {
	return c.ports
}

// GetSlowDura get slow request duration
func (c *Conf) GetSlowDura() time.Duration {
	return c.slowdura
}

// GetDuration get the max time for capturing
func (c *Conf) GetDuration() time.Duration {
	return c.duration
}

// GetSnapLen get the snap len
func (c *Conf) GetSnapLen() int32 {
	return c.snapLen
}

// GetFilter get custom filter
func (c *Conf) GetFilter() string {
	return c.filter
}

// GetShowrsp get slow request duration
func (c *Conf) GetShowrsp() bool {
	return c.showrsp
}

// GetProtocol get the protocol for packets
func (c *Conf) GetProtocol() string {
	return c.protocol
}

// GetReadtimeout get the read timeout for packets
func (c *Conf) GetReadtimeout() time.Duration {
	return c.readtimeout
}

// CheckConfs check confs
func (c *Conf) CheckConfs() error {
	if c.GetInterfile() == "" {
		return fmt.Errorf("The config for interfile is not valid")
	}
	if c.GetSnapLen() == 0 {
		return fmt.Errorf("The config for snapLen is not valid")
	}

	return nil
}
