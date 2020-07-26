package src

import (
	"fmt"
	"math"
	"time"

	"github.com/modood/table"
)

// Stats status summary
type Stats struct {
	RequestTotal   int64             // total request
	ResponseTotal  int64             // total response
	CostTotal      time.Duration     // total cost
	SlowTotal      int64             // total slow count
	LatencyBuckets []*LatencyBuckets // request time-consuming interval count
}

// StatsTable stats table
type StatsTable struct {
	Item  string // item key
	Value string // item value
}

// LatencyBuckets time-consuming interval statistics block
type LatencyBuckets struct {
	Duration time.Duration // minimum time-consuming interval
	Count    int64         // packet count in this interval
}

// InitStats init stats
func (t *Hamburg) InitStats() error {
	var buckets []*LatencyBuckets
	// The largest time-consuming interval is 50s ~
	buckets = append(buckets, &LatencyBuckets{Duration: time.Duration(0), Count: 0})
	for i := 1; i < 7; i++ {
		buckets = append(buckets, &LatencyBuckets{Duration: time.Duration(math.Pow10(i)*10) * time.Microsecond, Count: 0})
		buckets = append(buckets, &LatencyBuckets{Duration: time.Duration(math.Pow10(i)*20) * time.Microsecond, Count: 0})
		buckets = append(buckets, &LatencyBuckets{Duration: time.Duration(math.Pow10(i)*50) * time.Microsecond, Count: 0})
	}

	t.Stats = &Stats{LatencyBuckets: buckets}

	return nil
}

// IncrRequestCount incr request count
func (t *Hamburg) IncrRequestCount() {
	t.Stats.RequestTotal++
}

// IncrResponseCount incr response count
func (t *Hamburg) IncrResponseCount() {
	t.Stats.ResponseTotal++
}

// IncrSlowlogCount incr slow count
func (t *Hamburg) IncrSlowlogCount() {
	t.Stats.SlowTotal++
}

// IncrTimeIntervalCount incr time-consuming interval count
func (t *Hamburg) IncrTimeIntervalCount(dura time.Duration) {
	t.Stats.CostTotal += dura

	buckets := t.Stats.LatencyBuckets
	for i := len(buckets) - 1; i >= 0; i-- {
		if dura >= buckets[i].Duration {
			buckets[i].Count++
			return
		}
	}
}

// PrintStats stats
func (t *Hamburg) PrintStats() {
	s := t.Stats
	var sums, duras []*StatsTable
	sums = append(sums, &StatsTable{Item: "RequestTotal", Value: fmt.Sprintf("%d", s.RequestTotal)})
	sums = append(sums, &StatsTable{Item: "ResponseTotal", Value: fmt.Sprintf("%d", s.ResponseTotal)})
	sums = append(sums, &StatsTable{Item: "CostTotal", Value: fmt.Sprintf("%v", s.CostTotal)})
	sums = append(sums, &StatsTable{Item: "SlowTotal", Value: fmt.Sprintf("%d", s.SlowTotal)})
	fmt.Println("Summary Statistics:")
	table.Output(sums)

	buckets := t.Stats.LatencyBuckets
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
}
