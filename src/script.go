package src

import (
	"fmt"

	"github.com/bugwz/hamburg/utils"
	lua "github.com/yuin/gopher-lua"
)

// Script script
type Script struct {
	LState *lua.LState
	LSArgs *lua.LTable
}

// NewScript new lua script
func NewScript(f string) *Script {
	if f == "" {
		return nil
	}

	lstate := lua.NewState()
	if lstate.DoFile(f) != nil {
		lstate.Close()
		return nil
	}

	return &Script{
		LState: lstate,
		LSArgs: lstate.CreateTable(0, 0),
	}
}

// Run try run lua script with packet detail
func (s *Script) Run(d *utils.PacketDetail) error {
	if s == nil {
		return fmt.Errorf("lua script is not available")
	}

	s.LSArgs.RawSetString("type", lua.LString(fmt.Sprintf("[%s]", d.Type)))
	s.LSArgs.RawSetString("direction", lua.LString(d.Direction))
	s.LSArgs.RawSetString("smac", lua.LString(d.SrcMAC))
	s.LSArgs.RawSetString("sip", lua.LString(d.SrcIP))
	s.LSArgs.RawSetString("sport", lua.LString(d.SrcPort))
	s.LSArgs.RawSetString("dmac", lua.LString(d.DstMAC))
	s.LSArgs.RawSetString("dip", lua.LString(d.DstIP))
	s.LSArgs.RawSetString("dport", lua.LString(d.DstPort))
	s.LSArgs.RawSetString("seq", lua.LString(d.Sequence))
	s.LSArgs.RawSetString("ack", lua.LString(d.ACK))
	s.LSArgs.RawSetString("flag", lua.LString(d.FlagStr))
	s.LSArgs.RawSetString("payload", lua.LString(d.Payload))
	s.LSArgs.RawSetString("payloadlen", lua.LString(fmt.Sprintf("%d", d.PayloadLen)))
	if err := s.LState.CallByParam(lua.P{
		Fn:      s.LState.GetGlobal("process"),
		NRet:    1,
		Protect: true,
	}, s.LSArgs); err != nil {
		fmt.Printf("run lua script failed: %v", err)
		return fmt.Errorf("run lua script failed: %v", err)
	}

	return nil
}
