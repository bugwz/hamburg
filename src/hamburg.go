package src

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// Hamburg hamburg
type Hamburg struct {
	Conf    *Conf
	Lua     *Lua
	Sniffer *Sniffer
	Stats   *Stats
	Wg      sync.WaitGroup
}

// NewHamburg new
func NewHamburg() *Hamburg {
	t := &Hamburg{}
	t.InitConf()
	return t
}

// Run run
func (h *Hamburg) Run() {
	if err := h.VerifyConf(); err != nil {
		h.Done(err)
		return
	}

	if err := h.InitStats(); err != nil {
		h.Done(err)
		return
	}

	if err := h.InitLua(); err != nil {
		h.Done(err)
		return
	}

	if err := h.InitSniffer(); err != nil {
		h.Done(err)
		return
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	h.Wg.Add(1)
	go h.RunCapture(sig)
	h.Wg.Wait()
}

// Done done
func (h *Hamburg) Done(err error) {
	fmt.Println(err)
	// TODO: clean something
}
