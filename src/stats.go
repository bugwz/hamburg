package src

import (
	"fmt"
	"math"
	"os"
	"time"

	"github.com/modood/table"
)

// Stats status summary
type Stats struct {
	totalreq int64         // total request
	totalrsp int64         // total response
	slownum  int64         // total slow count
	cost     time.Duration // total cost
	bks      []*Buckets    // request time-consuming interval count
}

// StatsTable stats table
type StatsTable struct {
	Item  string // item key
	Value string // item value
}

// Buckets time-consuming interval statistics block
type Buckets struct {
	Duration time.Duration // minimum time-consuming interval
	Count    int64         // packet count in this interval
}

// NewStats new status
func NewStats() *Stats {
	var bks []*Buckets
	// The largest time-consuming interval is 50s ~
	bks = append(bks, &Buckets{Duration: time.Duration(0), Count: 0})
	for i := 1; i < 7; i++ {
		bks = append(bks, &Buckets{Duration: time.Duration(math.Pow10(i)*10) * time.Microsecond, Count: 0})
		bks = append(bks, &Buckets{Duration: time.Duration(math.Pow10(i)*20) * time.Microsecond, Count: 0})
		bks = append(bks, &Buckets{Duration: time.Duration(math.Pow10(i)*50) * time.Microsecond, Count: 0})
	}
	return &Stats{
		bks: bks,
	}
}

// IncrRequest incr request count
func (s *Stats) IncrRequest(n int64) {
	s.totalreq += n
}

// IncrResponse incr response count
func (s *Stats) IncrResponse(n int64) {
	s.totalrsp += n
}

// IncrSlowlog incr slow count
func (s *Stats) IncrSlowlog(n int64) {
	s.slownum += n
}

// AddDuration incr time-consuming interval count
func (s *Stats) AddDuration(t time.Duration) {
	s.cost += t

	buckets := s.bks
	for i := len(buckets) - 1; i >= 0; i-- {
		if t >= buckets[i].Duration {
			buckets[i].Count++
			return
		}
	}
}

// ShowStats show stats
func (s *Stats) ShowStats() {
	var m, d []*StatsTable

	fmt.Println("\r\nSummary Statistics:")
	m = append(m, &StatsTable{Item: "RequestTotal", Value: fmt.Sprintf("%d", s.totalreq)})
	m = append(m, &StatsTable{Item: "ResponseTotal", Value: fmt.Sprintf("%d", s.totalrsp)})
	m = append(m, &StatsTable{Item: "CostTotal", Value: fmt.Sprintf("%v", s.cost)})
	m = append(m, &StatsTable{Item: "SlowTotal", Value: fmt.Sprintf("%d", s.slownum)})
	table.Output(m)

	fmt.Println("Summary of time-consuming:")
	bks := s.bks
	for i := 0; i < len(bks)-1; i++ {
		d = append(d, &StatsTable{
			Item:  fmt.Sprintf("%s ~ %s", bks[i].Duration, bks[i+1].Duration),
			Value: fmt.Sprintf("%d", bks[i].Count),
		})
	}
	d = append(d, &StatsTable{
		Item:  fmt.Sprintf("%s ~ ", bks[len(bks)-1].Duration),
		Value: fmt.Sprintf("%d", bks[len(bks)-1].Count),
	})
	table.Output(d)

	os.Exit(0)
}
