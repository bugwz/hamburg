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

// mysql client request type in payload body
const (
	MySQLSleep            = 0x00 // 0
	MySQLQuit             = 0x01 // 1, mysql_close
	MySQLInitDB           = 0x02 // 2, mysql_select_db
	MySQLQuery            = 0x03 // 3, mysql_real_query
	MySQLFieldList        = 0x04 // 4, mysql_list_fields
	MySQLCreateDB         = 0x05 // 5, mysql_create_db
	MySQLDropDB           = 0x06 // 6, mysql_drop_db
	MySQLRefresh          = 0x07 // 7, mysql_refresh
	MySQLShutdown         = 0x08 // 8, mysql_shutdown
	MySQLStatistics       = 0x09 // 9, mysql_stat
	MySQLProcessInfo      = 0x0A // 10, mysql_list_processes
	MySQLConnect          = 0x0B // 11
	MySQLProcessKill      = 0x0C // 12, mysql_kill
	MySQLDebug            = 0x0D // 13, mysql_dump_debug_info
	MySQLPing             = 0x0E // 14, mysql_ping
	MySQLTime             = 0x0F // 15
	MySQLDelayedInsert    = 0x10 // 16
	MySQLChangeUser       = 0x11 // 17, mysql_change_user
	MySQLBinglogDump      = 0x12 // 18
	MySQLTableDump        = 0x13 // 19
	MySQLConnectOut       = 0x14 // 20
	MySQLRegisterSlave    = 0x15 // 21
	MySQLStmtPrepare      = 0x16 // 22, mysql_stmt_prepare
	MySQLStmtExecute      = 0x17 // 23, mysql_stmt_execute
	MySQLStmtSendLongData = 0x18 // 24, mysql_stmt_send_long_data
	MySQLStmtClose        = 0x19 // 25, mysql_stmt_close
	MySQLStmtReset        = 0x1A // 26, mysql_stmt_reset
	MySQLSetOption        = 0x1B // 27, mysql_set_server_option
	MySQLStmtFetch        = 0x1C // 28, mysql_stmt_fetch
	// MySQLDaemon          = 29
	// MySQLBinglogDumpGitd = 29
	// MySQLResetConnection = 31
	// MySQL0xFF            = 0xFF // begin server response
	// MySQL0x00            = 0x00
)

// mysql server response type in payload body
const (
	MySQLOK    = 0x00
	MySQLError = 0xFF
	MySQLEOF   = 0xFE
	// ResultSet = 0x01 - 0xFA
	// Field     = 0x01 - 0xFA
	// RowData   = 0x01 - 0xFA
)

// MySQLParser parse packets with mysql protocol rules
func MySQLParser(d *utils.PacketDetail) {
	var pos int
	p := []byte(d.Payload)
	if len(p) < 5 {
		return
	}

	// TODO: Why truncated the first 7 bytes?
	plen := int(uint32(p[0]) | uint32(p[1])<<8 | uint32(p[2])<<16)
	sid := p[3]
	if sid != 0 || len(p) < plen+4 {
		return
	}

	// request
	pos = 4
	if d.Direction == "REQ" {
		switch p[pos] {
		case MySQLQuit, MySQLInitDB, MySQLQuery, MySQLFieldList, MySQLCreateDB,
			MySQLDropDB, MySQLRefresh, MySQLShutdown, MySQLStatistics,
			MySQLProcessInfo, MySQLProcessKill, MySQLPing, MySQLChangeUser,
			MySQLStmtPrepare:
			d.Content = string(p[pos+1:])
		case MySQLStmtSendLongData:
			// TODO: parse payload
			d.Content = ""
		case MySQLStmtReset:
			// TODO: parse payload
			d.Content = ""
		case MySQLStmtExecute:
			// TODO: parse payload
			d.Content = ""
		default:
			d.Content = ""
		}

		return
	}

	// response
	pos = 0
	switch p[pos] {
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
