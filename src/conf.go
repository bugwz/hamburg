package src

// Conf conf
type Conf struct {
	InterFile     string // Network interface or offline pcap file
	Outfile       string // Save the capture packet file
	FilterIPs     string // Filtering IPs in packets
	FilterPorts   string // Filtering Ports in packets
	FilterCustom  string // Custom filtering rules
	Protocol      string // Application layer protocol of data packet
	Script        string // Lua script for parsing packets
	SlowThreshold int64  // Threshold for slow requests
	Duration      int64  // Time of continuous data capture
	ShowReply     bool   // Whether to display the content of the reply packet
	SnapLen       int    // Capture the data length of the packet
	ReadTimeout   int64  // Timeout for reading packets from NIC
	Promisc       bool   // Whether to use promisc mode to monitor packets
}

// NewConf new conf
func NewConf() *Conf {
	return &Conf{
		SlowThreshold: 5,
		Duration:      0,
		ShowReply:     false,
		SnapLen:       1500,
		Promisc:       false,
		ReadTimeout:   30,
	}
}
