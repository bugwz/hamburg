package protocol

import (
	"github.com/bugwz/hamburg/utils"
)

/* mysql protocol packet format

https://dev.mysql.com/doc/dev/mysql-server/8.0.11/page_protocol_basic_packets.html#sect_protocol_basic_packets_packet

+---------------+----------+------------------------------------+
|    3 Bytes    |  1 Byte  |              N Bytes               |
+---------------+----------+------------------------------------+
|    payload    | sequence |       payload of the packet        |
|    length     |    id    |                                    |
+---------------+----------+------------------------------------+
|                                                               |
|<=======  header  =======>|<===========   body   =============>|
*/

// mysql client request type
const (
	MySQLSleep            byte = 0x00
	MySQLQuit                  = 0x01
	MySQLInitDB                = 0x02
	MySQLQuery                 = 0x03
	MySQLFieldList             = 0x04
	MySQLCreateDB              = 0x05
	MySQLDropDB                = 0x06
	MySQLRefresh               = 0x07
	MySQLShutdown              = 0x08
	MySQLStatistics            = 0x09
	MySQLProcessInfo           = 0x0A
	MySQLConnect               = 0x0B
	MySQLProcessKill           = 0x0C
	MySQLDebug                 = 0x0D
	MySQLPing                  = 0x0E
	MySQLTime                  = 0x0F
	MySQLDelayedInsert         = 0x10
	MySQLChangeUser            = 0x11
	MySQLBinglogDump           = 0x12
	MySQLTableDump             = 0x13
	MySQLConnectOut            = 0x14
	MySQLRegisterSlave         = 0x15
	MySQLStmtPrepare           = 0x16
	MySQLStmtExecute           = 0x17
	MySQLStmtSendLongData      = 0x18
	MySQLStmtClose             = 0x19
	MySQLStmtReset             = 0x1A
	MySQLSetOption             = 0x1B
	MySQLStmtFetch             = 0x1C
	// MySQLDaemon          = 29
	// MySQLBinglogDumpGitd = 29
	// MySQLResetConnection = 31
	// MySQL0xFF            = 0xFF // begin server response
	// MySQL0x00            = 0x00
)

// mysql server response type
const (
	MySQLOK    = 0x00
	MySQLError = 0xFF
	MySQLEOF   = 0xFE
	// ResultSet = 0x01 - 0xFA
	// Field     = 0x01 - 0xFA
	// RowData   = 0x01 - 0xFA
)

// ParsePayloadWithMySQL parse packets with mysql protocol rules
func ParsePayloadWithMySQL(d *utils.PacketDetail) {
	var pos int
	payload := []byte(d.Payload)
	if len(payload) < 10 {
		return
	}

	// TODO: Why truncated the first 7 bytes?
	// plen := int(uint32(payload[7]) | uint32(payload[8])<<8 | uint32(payload[9])<<16)
	// sid := payload[10]

	// request
	pos = 11
	if d.Direction == "REQ" {
		switch payload[pos] {
		case MySQLInitDB:
			d.Content = string(payload[pos+1:])
		case MySQLDropDB:
			d.Content = string(payload[pos+1:])
		case MySQLCreateDB, MySQLQuery:
			d.Content = string(payload[pos+1:])
		case MySQLStmtPrepare:
			// TODO: parse payload
			d.Content = "MySQLStmtPrepare"
		case MySQLStmtSendLongData:
			// TODO: parse payload
			d.Content = "MySQLStmtSendLongData"
		case MySQLStmtReset:
			// TODO: parse payload
			d.Content = "MySQLStmtReset"
		case MySQLStmtExecute:
			// TODO: parse payload
			d.Content = "MySQLStmtExecute"
		default:
			d.Content = ""
		}

		return
	}

	// response
	pos = 0
	switch payload[pos] {
	case MySQLOK:
		d.Content = "ok"
	case MySQLError:
		d.Content = "error"
	case MySQLEOF:
		d.Content = ""
	default:
		d.Content = "not find case"
	}
}
