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

// IncrRequestCount incr request count
func (s *Stats) IncrRequestCount() {
	s.totalreq++
}

// IncrResponseCount incr response count
func (s *Stats) IncrResponseCount() {
	s.totalrsp++
}

// IncrSlowlogCount incr slow count
func (s *Stats) IncrSlowlogCount() {
	s.slownum++
}

// IncrTimeIntervalCount incr time-consuming interval count
func (s *Stats) IncrTimeIntervalCount(dura time.Duration) {
	s.cost += dura

	buckets := s.bks
	for i := len(buckets) - 1; i >= 0; i-- {
		if dura >= buckets[i].Duration {
			buckets[i].Count++
			return
		}
	}
}

// ShowStats show stats
func (s *Stats) ShowStats() {
	var sums, duras []*StatsTable

	sums = append(sums, &StatsTable{Item: "RequestTotal", Value: fmt.Sprintf("%d", s.totalreq)})
	sums = append(sums, &StatsTable{Item: "ResponseTotal", Value: fmt.Sprintf("%d", s.totalrsp)})
	sums = append(sums, &StatsTable{Item: "CostTotal", Value: fmt.Sprintf("%v", s.cost)})
	sums = append(sums, &StatsTable{Item: "SlowTotal", Value: fmt.Sprintf("%d", s.slownum)})
	fmt.Println("\r\nSummary Statistics:")
	table.Output(sums)

	buckets := s.bks
	for i := 0; i < len(buckets)-1; i++ {
		duras = append(duras, &StatsTable{
			Item:  fmt.Sprintf("%s ~ %s", buckets[i].Duration, buckets[i+1].Duration),
			Value: fmt.Sprintf("%d", buckets[i].Count),
		})
	}
	duras = append(duras, &StatsTable{
		Item:  fmt.Sprintf("%s ~ ", buckets[len(buckets)-1].Duration),
		Value: fmt.Sprintf("%d", buckets[len(buckets)-1].Count),
	})
	fmt.Println("Summary of time-consuming:")
	table.Output(duras)
	os.Exit(0)
}
