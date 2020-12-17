package src

import (
	"fmt"

	p "github.com/bugwz/hamburg/parser"
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
func (s *Script) Run(v *p.Packet) error {
	if s == nil {
		return fmt.Errorf("lua script is not available")
	}

	s.LSArgs.RawSetString("type", lua.LString(fmt.Sprintf("[%s]", v.Type)))
	s.LSArgs.RawSetString("direction", lua.LString(v.Direction))
	s.LSArgs.RawSetString("smac", lua.LString(v.SrcMAC))
	s.LSArgs.RawSetString("sip", lua.LString(v.SrcIP))
	s.LSArgs.RawSetString("sport", lua.LString(v.SrcPort))
	s.LSArgs.RawSetString("dmac", lua.LString(v.DstMAC))
	s.LSArgs.RawSetString("dip", lua.LString(v.DstIP))
	s.LSArgs.RawSetString("dport", lua.LString(v.DstPort))
	s.LSArgs.RawSetString("seq", lua.LString(v.Sequence))
	s.LSArgs.RawSetString("ack", lua.LString(v.ACK))
	s.LSArgs.RawSetString("flag", lua.LString(v.FlagStr))
	s.LSArgs.RawSetString("payload", lua.LString(v.Payload))
	s.LSArgs.RawSetString("payloadlen", lua.LString(fmt.Sprintf("%d", v.PayloadLen)))
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
