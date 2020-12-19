package src

import (
	"fmt"
	"math"
	"time"

	"github.com/emirpasic/gods/maps/hashmap"
	"github.com/modood/table"
)

// State status summary
type State struct {
	request   int64             // Total request
	response  int64             // Total response
	slow      int64             // Total slow request/response
	slowline  time.Duration     // Threshold for slow requests
	cost      time.Duration     // Total cost
	curmsg    string            // The latest packet content completed by the lifecycle
	showreply bool              // Displays the contents of the reply packet
	localip   map[string]string // IP list obtained from local NIC
	bks       []*Buckets        // Time consuming interval of packet request reply
	dict      *hashmap.Map      // A dictionary that records all request packets
}

// StatPair stats table
type StatPair struct {
	Item  string // item key
	Value string // item value
}

// Buckets time-consuming interval statistics block
type Buckets struct {
	k time.Duration // minimum time-consuming interval
	v int64         // packet count in this interval
}

// NewState new state
func NewState(c *Conf) (*State, error) {
	var bks []*Buckets

	// The largest time-consuming interval is 50s ~
	bks = append(bks, &Buckets{k: time.Duration(0), v: 0})
	for i := 1; i < 7; i++ {
		bks = append(bks, &Buckets{k: time.Duration(math.Pow10(i)*10) * time.Microsecond, v: 0})
		bks = append(bks, &Buckets{k: time.Duration(math.Pow10(i)*20) * time.Microsecond, v: 0})
		bks = append(bks, &Buckets{k: time.Duration(math.Pow10(i)*50) * time.Microsecond, v: 0})
	}

	return &State{
		slowline: time.Duration(c.SlowThreshold) * time.Millisecond,
		bks:      bks,
		dict:     hashmap.New(),
	}, nil
}

// IncrReqRsp incr request and response
func (s *State) IncrReqRsp(isreq bool) {
	if isreq {
		s.request++
	} else {
		s.response++
	}
}

// AddDuration incr time-consuming interval count
func (s *State) AddDuration(t time.Duration) {
	s.cost += t

	if s.FitSlow(t) {
		s.slow++
	}

	buckets := s.bks
	for i := len(buckets) - 1; i >= 0; i-- {
		if t >= buckets[i].k {
			buckets[i].v++
			return
		}
	}
}

// FitSlow verify that the request is too slow
func (s *State) FitSlow(v time.Duration) bool {
	if v > s.slowline {
		return true
	}

	return false
}

// ShowStats show stats
func (s *State) ShowStats() {
	var m, d []*StatPair

	fmt.Println("\r\nSummary Statistics:")
	m = append(m, &StatPair{Item: "Request", Value: fmt.Sprintf("%d", s.request)})
	m = append(m, &StatPair{Item: "Response", Value: fmt.Sprintf("%d", s.response)})
	m = append(m, &StatPair{Item: "Slow", Value: fmt.Sprintf("%d", s.slow)})
	m = append(m, &StatPair{Item: "Cost", Value: fmt.Sprintf("%v", s.cost)})
	table.Output(m)

	fmt.Println("Summary of time-consuming:")
	bks := s.bks
	for i := 0; i < len(bks)-1; i++ {
		d = append(d, &StatPair{
			Item:  fmt.Sprintf("%s ~ %s", bks[i].k, bks[i+1].k),
			Value: fmt.Sprintf("%d", bks[i].v),
		})
	}
	d = append(d, &StatPair{
		Item:  fmt.Sprintf("%s ~ ", bks[len(bks)-1].k),
		Value: fmt.Sprintf("%d", bks[len(bks)-1].v),
	})
	table.Output(d)
}
