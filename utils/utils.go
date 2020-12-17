package utils

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/google/gopacket/pcap"
)

// Packet save request/response packets detail
type Packet struct {
	Type       string
	Direction  string
	SrcMAC     string
	SrcIP      string
	SrcPort    string
	DstMAC     string
	DstIP      string
	DstPort    string
	CheckSum   string
	Sequence   string
	ACK        string
	Flag       int
	FlagStr    string
	Payload    string
	PayloadLen int
	Content    string
	Timestap   time.Time
}

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

// VerifyIPs check ips
func VerifyIPs(ips []string) error {
	for _, ip := range ips {
		if len(ip) != 0 {
			if net.ParseIP(ip) == nil {
				return fmt.Errorf("IP %s is illegal", ip)
			}
		}
	}

	return nil
}

// VerifyPorts check ports
func VerifyPorts(ports []string) error {
	for _, port := range ports {
		if len(port) != 0 {
			p, err := strconv.Atoi(port)
			if err != nil || p < 0 || p > 65535 {
				return fmt.Errorf("Port %s is illegal", port)
			}
		}
	}

	return nil
}

// GetAllDevices get all network interface
func GetAllDevices() ([]*pcap.Interface, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}

	var ds []*pcap.Interface
	for _, d := range devices {
		if len(d.Addresses) > 0 {
			ds = append(ds, &d)
		}
	}

	return ds, nil
}

// GetInterfaceIPs get the specified network interface info
func GetInterfaceIPs(name string) (map[string]string, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}

	ips := make(map[string]string)
	for _, device := range devices {
		if device.Name == name {
			for _, item := range device.Addresses {
				ips[item.IP.String()] = item.Netmask.String()
			}
			return ips, nil
		}
	}

	return nil, fmt.Errorf("Not found %s device", name)
}

// PrintDeviceDetail print network interface details
func PrintDeviceDetail(name string) error {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return err
	}

	for _, device := range devices {
		if device.Name == name {
			fmt.Println("\nName: ", device.Name)
			fmt.Println("Description: ", device.Description)
			fmt.Println("Devices addresses: ", device.Description)
			for _, address := range device.Addresses {
				fmt.Println("- IP address: ", address.IP)
				fmt.Println("- Subnet mask: ", address.Netmask)
			}
			return nil
		}
	}

	return fmt.Errorf("not found %s device", name)
}
