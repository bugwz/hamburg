package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	flag "github.com/bugwz/go-flag"
	s "github.com/bugwz/hamburg/src"
)

var version = "1.0"
var (
	snaplen                                                   int
	slowdura, count, duration                                 int64
	interfile, outfile, ips, ports, protocol, luafile, filter string
	showrsp, help                                             bool
)

func usage() {
	fmt.Fprintf(os.Stderr, `
     _                     _                     
    | |__   __ _ _ __ ___ | |__  _   _ _ __ __ _ 
    | '_ \ / _' | '_' '_ \| '_ \| | | | '__/ _| |
    | | | | (_| | | | | | | |_) | |_| | | | (_| |
    |_| |_|\__,_|_| |_| |_|_.__/ \__,_|_|  \__, |
                                            |___/ `+version+`

A tool to capture data packets and time-consuming analysis.

Options:

`)
	flag.PrintDefaults()
}

func init() {
	flag.StringVar(&interfile, "i", "", "monitor network card interface or offline pcap file")
	flag.StringVar(&outfile, "o", "", "file to save the captured package")
	flag.StringVar(&ips, "s", "", "capture packets of the specified ips, split multiple with commas")
	flag.StringVar(&ports, "p", "", "capture packets of the specified ports, split multiple with commas")
	flag.StringVar(&protocol, "m", "raw", "parse the contents of packets by raw/dns/http/redis/memcached/mysql")
	flag.Int64Var(&slowdura, "t", 5, "slow request threshold, in units of millisecond")
	flag.Int64Var(&duration, "d", 0, "maximum time of captured packets, in units of second  (default 0, no limit)")
	flag.StringVar(&luafile, "x", "", "process packets with specialed lua script")
	flag.IntVar(&snaplen, "n", 1500, "maximum length of the captured data packet snaplen")
	flag.StringVar(&filter, "e", "", "customized packet filter, the format is the same as tcpdump")
	flag.BoolVar(&showrsp, "a", false, "show the contents of the reply packet (default false)")
	flag.BoolVar(&help, "h", false, "help")

	flag.SetSortFlags(false)
	flag.Usage = usage
}

func initConfs(c *s.Conf) {
	c.SetInterfile(interfile)
	c.SetOutFile(outfile)
	c.SetIPs(strings.Split(ips, ","))
	c.SetPorts(strings.Split(ports, ","))
	c.SetSlowDura(time.Duration(slowdura) * time.Millisecond)
	c.SetDuration(time.Duration(duration) * time.Second)
	c.SetSnapLen(int32(snaplen))
	c.SetFilter(filter)
	c.SetShowrsp(showrsp)
	c.SetScript(luafile)
	c.SetProtocol(protocol)
}

func main() {
	flag.Parse()
	if help {
		flag.Usage()
		return
	}

	h := s.NewHamburg()
	initConfs(h.Conf)

	h.Run()

	return
}
