package src

import (
	"fmt"

	"github.com/bugwz/hamburg/utils"
	lua "github.com/yuin/gopher-lua"
)

// Lua lua
type Lua struct {
	LState *lua.LState
	LSArgs *lua.LTable
}

// InitLua init lua
func (h *Hamburg) InitLua() error {
	file := h.Conf.LuaFile
	if file != "" {
		lstate := lua.NewState()
		if err := lstate.DoFile(file); err != nil {
			return fmt.Errorf("Load lua script %s failed: %v", file, err)
		}

		h.Lua = &Lua{
			LState: lstate,
			LSArgs: lstate.CreateTable(0, 0),
		}
	}

	return nil
}

// ProcessPacketsWithLua run lua script with packet detail
func (h *Hamburg) ProcessPacketsWithLua(d *utils.PacketDetail) {
	l := h.Lua
	c := h.Conf

	l.LSArgs.RawSetString("type", lua.LString(fmt.Sprintf("[%s]", d.Type)))
	l.LSArgs.RawSetString("direction", lua.LString(d.Direction))
	l.LSArgs.RawSetString("smac", lua.LString(d.SrcMAC))
	l.LSArgs.RawSetString("sip", lua.LString(d.SrcIP))
	l.LSArgs.RawSetString("sport", lua.LString(d.SrcPort))
	l.LSArgs.RawSetString("dmac", lua.LString(d.DstMAC))
	l.LSArgs.RawSetString("dip", lua.LString(d.DstIP))
	l.LSArgs.RawSetString("dport", lua.LString(d.DstPort))
	l.LSArgs.RawSetString("seq", lua.LString(d.Sequence))
	l.LSArgs.RawSetString("ack", lua.LString(d.ACK))
	l.LSArgs.RawSetString("flag", lua.LString(d.FlagStr))
	l.LSArgs.RawSetString("payload", lua.LString(d.Payload))
	l.LSArgs.RawSetString("payloadlen", lua.LString(fmt.Sprintf("%d", d.PayloadLen)))
	if err := l.LState.CallByParam(lua.P{
		Fn:      l.LState.GetGlobal("process"),
		NRet:    1,
		Protect: true,
	}, l.LSArgs); err != nil {
		fmt.Printf("Run %s lua script failed: %v\r\n", c.LuaFile, err)
	}
}
