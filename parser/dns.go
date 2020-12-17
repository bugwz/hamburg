package parser

import (
	"fmt"
	"strings"
)

/* DNS payload format (https://www.ietf.org/rfc/rfc1035.txt)

+---------------------+
|        Header       |
+---------------------+
|       Question      |
+---------------------+
|        Answer       |
+---------------------+
|      Authority      |
+---------------------+
|      Additional     |
+---------------------+

* Header

0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15 16
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ID                       |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|  Opcode  |AA|TC|RD|RA|   Z    |   RCODE    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    QDCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ANCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    NSCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ARCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

* Questions

0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15 16
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                     QNAME                     /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     QTYPE                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     QCLASS                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

* Answers

0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15 16
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                      NAME                     /
/                                               /
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      TYPE                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     CLASS                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      TTL                      |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    RDLENGTH                   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/                     RDATA                     /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

*/

// dns type const
const (
	DNSTypeA     = 1
	DNSTypeNS    = 2
	DNSTypeMD    = 3
	DNSTypeMF    = 4
	DNSTypeCNAME = 5
	DNSTypeSOA   = 6
	DNSTypeMB    = 7
	DNSTypeMG    = 8
	DNSTypeMR    = 9
	DNSTypeNULL  = 10
	DNSTypeWKS   = 11
	DNSTypePTR   = 12
	DNSTypeHINFO = 13
	DNSTypeMINFO = 14
	DNSTypeMX    = 15
	DNSTypeTXT   = 16
	DNSTypeAAAA  = 28
)

// DNSType type fields are used in resource records
var DNSType = map[int]string{
	DNSTypeA:     "A",     // a host address
	DNSTypeNS:    "NS",    // an authoritative name server
	DNSTypeMD:    "MD",    // a mail destination (Obsolete - use MX)
	DNSTypeMF:    "MF",    // a mail forwarder (Obsolete - use MX)
	DNSTypeCNAME: "CNAME", // the canonical name for an alias
	DNSTypeSOA:   "SOA",   // marks the start of a zone of authority
	DNSTypeMB:    "MB",    // a mailbox domain name (EXPERIMENTAL)
	DNSTypeMG:    "MG",    // a mail group member (EXPERIMENTAL)
	DNSTypeMR:    "MR",    // a mail rename domain name (EXPERIMENTAL)
	DNSTypeNULL:  "NULL",  // a null RR (EXPERIMENTAL)c
	DNSTypeWKS:   "WKS",   // a well known service description
	DNSTypePTR:   "PTR",   // a domain name pointer
	DNSTypeHINFO: "HINFO", // host information
	DNSTypeMINFO: "MINFO", // mailbox or mail list information
	DNSTypeMX:    "MX",    // mail exchange
	DNSTypeTXT:   "TXT",   // text strings
	DNSTypeAAAA:  "AAAA",  // ipv6
}

// dns class const
const (
	DCIN = 1
	DCCS = 2
	DCCH = 3
	DCHS = 4
)

// DNSClass class fields appear in resource records
var DNSClass = map[int]string{
	DCIN: "IN", // the Internet
	DCCS: "CS", // the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
	DCCH: "CH", // the CHAOS class
	DCHS: "HS", // Hesiod [Dyer 87]
}

// DNSParser dns parser
type DNSParser struct{}

// Run parse packets
func (*DNSParser) Run(v *Packet) {
	var code, qcount, acount, qr, pos, nextpos int
	meta := []byte(v.Payload)

	// Parse header meta info
	if len(meta) < 12 {
		return
	}
	// id = (int(meta[0]) << 8) + int(meta[1])
	code = (int(meta[2]) << 8) + int(meta[3])
	qcount = (int(meta[4]) << 8) + int(meta[5])
	acount = (int(meta[6]) << 8) + int(meta[7])
	// nscount = (int(meta[8]) << 8) + int(meta[9])
	// arcount = (int(meta[10]) << 8) + int(meta[11])
	qr = code >> 15 // qr code is used to distinguish between request(0) and response(1)
	pos = 12

	// Request
	if qr == 0 {
		v.Request = true
		var domains []string
		for i := 0; i < qcount; i++ {
			var dmeta []string
			size := int(meta[pos])
			for size != 0 {
				nextpos = pos + 1 + size
				if len(meta) >= nextpos {
					dmeta = append(dmeta, string(meta[pos+1:nextpos]))
					size = int(meta[nextpos])
					pos = nextpos
				}
			}
			pos++

			// Query type
			qtid := (int(meta[pos]) << 8) | int(meta[pos+1])
			qtype := fmt.Sprintf("%d", qtid)
			if DNSType[qtid] != "" {
				qtype = DNSType[qtid]
			}
			pos += 4 // ignore query class(2 bytes)
			domains = append(domains, fmt.Sprintf("[%s] %s", qtype, strings.Join(dmeta, ".")))

		}
		v.Content = strings.Join(domains, ", ")
		return
	}

	// Response
	v.Request = false
	for i := 0; i < qcount; i++ {
		size := int(meta[pos])
		for size != 0 {
			nextpos = pos + 1 + size
			if len(meta) >= nextpos {
				size = int(meta[nextpos])
				pos = nextpos
			}
		}
		pos += 5
	}

	// Parse dns answer data
	records := make(map[string][]string)
	for i := 0; i < acount; i++ {
		if len(meta) <= pos+10 {
			break
		}
		// Ignore answer name
		pos += 2

		// Answer type
		atid := (int(meta[pos]) << 8) | int(meta[pos+1])
		atype := fmt.Sprintf("%d", atid)
		if DNSType[atid] != "" {
			atype = DNSType[atid]
		}
		pos += 8 // atype(2 bytes), aclass(2 bytes), ttl(2bytes)

		// Answer data length
		datalen := (int(meta[pos]) << 8) | int(meta[pos+1])
		pos += 2

		// Parse answer record
		switch atid {
		case DNSTypeA:
			if len(meta) <= pos+4 {
				break
			}
			records[atype] = append(records[atype], fmt.Sprintf("%d.%d.%d.%d",
				meta[pos], meta[pos+1], meta[pos+2], meta[pos+3]))
			pos += 4
		case DNSTypeCNAME:
			if len(meta) <= pos+datalen {
				break
			}
			size := int(meta[pos])
			records[atype] = append(records[atype], fmt.Sprintf("%s...", string(meta[pos+1:pos+1+size])))
			pos += datalen
			// TODO: unable to resolve the complete record domain name record
			// var cname []string
			// for size != 0 {
			// 	nextpos = pos + 1 + size
			// 	if len(meta) >= nextpos {
			// 		cname = append(cname, string(meta[pos+1:nextpos]))
			// 		size = int(meta[nextpos])
			// 		pos = nextpos
			// 	}
			// }
			// records = append(records, strings.Join(cname, "."))
			// pos++
		default:
			pos += datalen
		}
	}

	// Organize dns reply packets
	var cnts string
	for n, v := range records {
		var rs []string
		for _, record := range v {
			rs = append(rs, record)
		}
		cnts += fmt.Sprintf("[%s] %s; ", n, strings.Join(rs, "/"))
	}

	v.Content = cnts
}
