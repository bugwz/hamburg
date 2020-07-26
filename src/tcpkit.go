package src

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// Hamburg tcpkit
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
func (t *Hamburg) Run() {
	if err := t.VerifyConf(); err != nil {
		t.Done(err)
		return
	}

	if err := t.InitStats(); err != nil {
		t.Done(err)
		return
	}

	if err := t.InitLua(); err != nil {
		t.Done(err)
		return
	}

	if err := t.InitSniffer(); err != nil {
		t.Done(err)
		return
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	t.Wg.Add(1)
	go t.RunCapture(sig)
	t.Wg.Wait()
}

// Done done
func (t *Hamburg) Done(err error) {
	fmt.Println(err)
	// TODO: clean something
}
