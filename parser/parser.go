package parser

import "time"

// Parse parse packets
const (
	RAW       = "raw"
	DNS       = "dns"
	HTTP      = "http"
	Redis     = "redis"
	Memcached = "memcached"
	MySQL     = "mysql"
)

// DefaultParser default protocol type
const DefaultParser = Redis

// Packet packet
type Packet struct {
	Type       string
	Request    bool
	Direction  string
	SrcID      string
	SrcMAC     string
	SrcIP      string
	SrcPort    string
	DstID      string
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
	Ignore     bool
}

// Parser interface
type Parser interface {
	Run(v *Packet)
}

// NewParser new parser
func NewParser(v string) Parser {
	switch v {
	case RAW:
		return &RAWParser{}
	case DNS:
		return &DNSParser{}
	case HTTP:
		return &HTTPParser{}
	case Redis:
		return &RedisParser{}
	case Memcached:
		return &MemcachedParser{}
	case MySQL:
		return &MySQLParser{}
	}

	return nil
}
