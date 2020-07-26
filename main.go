package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	flag "github.com/bugwz/go-flag"
	"github.com/bugwz/hamburg/src"
)

var version = "1.0"
var (
	snaplen                                                     int
	threshold, count, duration                                  int64
	interfile, outfile, server, port, protocol, luafile, custom string
	showrsp, help                                               bool
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
	flag.StringVar(&server, "s", "", "capture packets of the specified ips, split multiple with commas")
	flag.StringVar(&port, "p", "", "capture packets of the specified ports, split multiple with commas")
	flag.StringVar(&protocol, "m", "raw", "parse the contents of packets by raw/dns/http/redis/memcached/mysql")
	flag.Int64Var(&threshold, "t", 5, "slow request threshold, in units of millisecond")
	flag.Int64Var(&count, "c", 0, "maximum number of captured packets (default 0, no limit)")
	flag.Int64Var(&duration, "d", 60, "maximum time of captured packets, in units of second")
	flag.StringVar(&luafile, "x", "", "process packets with specialed lua script")
	flag.IntVar(&snaplen, "n", 1500, "maximum length of the captured data packet snaplen")
	flag.StringVar(&custom, "e", "", "customized packet filter, the format is the same as tcpdump")
	flag.BoolVar(&showrsp, "a", false, "show the contents of the reply packet (default false)")
	flag.BoolVar(&help, "h", false, "help")

	flag.SetSortFlags(false)
	flag.Usage = usage
}

func setconf(c *src.Conf) {
	c.InterFile = interfile
	c.OutFile = outfile
	c.Server = strings.Split(server, ",")
	c.Port = strings.Split(port, ",")
	c.Threshold = time.Duration(threshold) * time.Millisecond
	c.Count = count
	c.Duration = time.Duration(duration) * time.Second
	c.LuaFile = luafile
	c.SnapLen = int32(snaplen)
	c.CustomFilter = custom
	c.ShowResponse = showrsp

	for id, p := range src.ProtocolType {
		if p == protocol {
			c.Protocol = id
		}
	}
}

func main() {
	flag.Parse()
	if help {
		flag.Usage()
		return
	}

	t := src.NewHamburg()
	setconf(t.Conf)

	t.Run()

	return
}
