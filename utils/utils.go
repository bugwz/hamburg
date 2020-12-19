package utils

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

// FileIsExist check file
func FileIsExist(f string) bool {
	if _, err := os.Stat(f); err != nil {
		if os.IsNotExist(err) {
			return false
		}
		return false
	}

	return true
}

// GetIPs get ips
func GetIPs(v string) ([]string, error) {
	if v == "" {
		return nil, nil
	}

	ips := strings.Split(v, ",")
	for _, ip := range ips {
		if len(ip) != 0 {
			if net.ParseIP(ip) == nil {
				return nil, fmt.Errorf("IP %s is illegal", ip)
			}
		}
	}

	return ips, nil
}

// GetPorts get ports
func GetPorts(v string) ([]string, error) {
	if v == "" {
		return nil, nil
	}

	ports := strings.Split(v, ",")
	for _, port := range ports {
		if len(port) != 0 {
			p, err := strconv.Atoi(port)
			if err != nil || p < 0 || p > 65535 {
				return nil, fmt.Errorf("Port %s is illegal", port)
			}
		}
	}

	return ports, nil
}

// GetAllDevices get all network interface
func GetAllDevices() ([]*pcap.Interface, error) {
	ds, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}

	var is []*pcap.Interface
	for _, d := range ds {
		if len(d.Addresses) > 0 {
			is = append(is, &d)
		}
	}

	return is, nil
}

// GetPacketReader get packet reader
func GetPacketReader(v string, snaplen int, rtimeout int64) (*pcap.Handle, error) {
	if FileIsExist(v) {
		pcap, e := pcap.OpenOffline(v)
		if e != nil {
			return nil, fmt.Errorf("Open offline pcap file %s failed: %v", v, e)
		}

		return pcap, nil
	}

	rt := time.Duration(rtimeout) * time.Second
	pcap, e := pcap.OpenLive(v, int32(snaplen), false, rt)
	if e != nil {
		return nil, fmt.Errorf("Open network interface %s failed: %v", v, e)
	}

	return pcap, nil
}

// GetLocalIPs get the specified network interface info
func GetLocalIPs(v string) (map[string]string, error) {
	ds, e := pcap.FindAllDevs()
	if e != nil {
		return nil, e
	}

	ips := make(map[string]string)
	for _, d := range ds {
		if d.Name == v {
			for _, item := range d.Addresses {
				ips[item.IP.String()] = item.Netmask.String()
			}
			return ips, nil
		}
	}

	return nil, nil
}

// GetPacketWriter get packet writer
func GetPacketWriter(v string, snaplen int) (*pcapgo.Writer, error) {
	if v == "" {
		return nil, nil
	}

	fh, e := os.Create(v)
	if e != nil {
		return nil, e
	}

	fw := pcapgo.NewWriter(fh)
	fw.WriteFileHeader(uint32(snaplen), layers.LinkTypeEthernet)

	return fw, nil
}

// PacketFilter set packet filtering rules
func PacketFilter(custom, ports, ips string) (string, error) {
	var fts, pfs, sfs []string

	// Port filter
	for _, port := range strings.Split(ports, ",") {
		if len(port) != 0 {
			pfs = append(pfs, fmt.Sprintf("(port %s)", port))
		}
	}
	fts = AddFilters(fts, pfs)

	// IP filter
	for _, ip := range strings.Split(ips, ",") {
		if len(ip) != 0 {
			sfs = append(sfs, fmt.Sprintf("(host %s)", ip))
		}
	}
	fts = AddFilters(fts, sfs)

	// Custom filter
	if custom != "" {
		fts = AddFilters(fts, []string{fmt.Sprintf("(%s)", custom)})
	}

	for i := range fts {
		fts[i] = fmt.Sprintf("(%s)", fts[i])
	}

	return strings.Join(fts, " or "), nil
}

// AddFilters add some filter rules
func AddFilters(v []string, v2 []string) []string {
	if len(v) != 0 {
		if len(v2) != 0 {
			for i := range v {
				v[i] = fmt.Sprintf("%s and (%s)", v[i], strings.Join(v2, " or "))
			}
		}
		return v
	}

	return v2
}

// GetNIC network interface details
func GetNIC(v string) *pcap.Interface {
	ds, e := pcap.FindAllDevs()
	if e != nil {
		return nil
	}

	for _, d := range ds {
		if d.Name == v {
			return &d
		}
	}

	return nil
}
