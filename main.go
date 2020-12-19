package main

import (
	"fmt"
	"os"

	flag "github.com/bugwz/go-flag"
	s "github.com/bugwz/hamburg/src"
)

var version = "1.0"
var (
	snaplen                                                     int
	slow, count, duration                                       int64
	interfile, outfile, fips, fports, protocol, script, fcustom string
	showreply, help                                             bool
)

// var help bool
// var c *s.Conf

// c := s.Conf{}
// c := s.NewConf()

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
	flag.StringVar(&interfile, "i", "", "monitor network interface or offline pcap file")
	flag.StringVar(&outfile, "o", "", "outfile for the captured package")
	flag.StringVar(&fips, "s", "", "filtered ip list, splited with commas")
	flag.StringVar(&fports, "p", "", "filtered port list, splited with commas")
	flag.StringVar(&protocol, "m", "raw", "packet protocol type with raw/dns/http/redis/memcached/mysql")
	flag.Int64Var(&slow, "t", 1, "threshold for slow requests (millisecond)")
	flag.Int64Var(&duration, "d", 0, "running time for capturing packets (second), (default unlimited)")
	flag.StringVar(&script, "x", "", "lua script file")
	flag.IntVar(&snaplen, "n", 1500, "maximum length of the captured data packet snaplen")
	flag.StringVar(&fcustom, "e", "", "customized packet filter")
	flag.BoolVar(&showreply, "a", false, "show the contents of the reply packet (default false)")
	flag.BoolVar(&help, "h", false, "help")

	flag.SetSortFlags(false)
	flag.Usage = usage
}

func setconf(c *s.Conf) {
	c.InterFile = interfile
	c.Outfile = outfile
	c.FilterIPs = fips
	c.FilterPorts = fports
	c.Protocol = protocol
	c.SlowThreshold = slow
	c.Duration = duration
	c.SnapLen = snaplen
	c.Script = script
	c.FilterCustom = fcustom
	c.ShowReply = showreply
}

func main() {
	c := s.NewConf()
	flag.Parse()
	if help {
		flag.Usage()
		return
	}

	setconf(c)
	h, e := s.NewHamburg(c)
	if e != nil {
		fmt.Println(e)
		return
	}

	h.Run()
	return
}
