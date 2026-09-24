package metrics

import (
	"hash/maphash"
	"math"
	"math/bits"
	"time"
)

const (
	uniqueVisitorWindowHours             = 24
	uniqueVisitorHLLPrecision            = 12
	uniqueVisitorHLLRegisters            = 1 << uniqueVisitorHLLPrecision
	uniqueVisitorHLLError                = 0.01625
	uniqueVisitorEstimateRefreshInterval = time.Second
)

type uniqueVisitorBucket struct {
	hour      int64
	registers []uint8
}

// uniqueVisitorCounter is a fixed-memory, rolling HyperLogLog counter. It
// trades exact membership for a known relative error and prevents a stream of
// unique source addresses from growing the process heap indefinitely.
type uniqueVisitorCounter struct {
	seed               maphash.Seed
	buckets            [uniqueVisitorWindowHours]uniqueVisitorBucket
	unionRegisters     []uint8
	unionHarmonicSum   float64
	unionZeroRegisters int
	windowHour         int64
	windowInitialized  bool
}

func newUniqueVisitorCounter() uniqueVisitorCounter {
	counter := uniqueVisitorCounter{
		seed:               maphash.MakeSeed(),
		unionRegisters:     make([]uint8, uniqueVisitorHLLRegisters),
		unionHarmonicSum:   float64(uniqueVisitorHLLRegisters),
		unionZeroRegisters: uniqueVisitorHLLRegisters,
	}
	for index := range counter.buckets {
		counter.buckets[index].registers = make([]uint8, uniqueVisitorHLLRegisters)
	}
	counter.advanceWindow(time.Now())
	return counter
}

func (c *uniqueVisitorCounter) add(ip string, timestamp time.Time) {
	hour := timestamp.UTC().Unix() / int64(time.Hour.Seconds())
	c.advanceWindow(timestamp)
	if ip == "" {
		return
	}
	if hour < c.windowHour-uniqueVisitorWindowHours+1 {
		return
	}
	bucket := &c.buckets[hour%uniqueVisitorWindowHours]
	if bucket.hour != hour {
		clear(bucket.registers)
		bucket.hour = hour
	}

	var hasher maphash.Hash
	hasher.SetSeed(c.seed)
	_, _ = hasher.WriteString(ip)
	hash := hasher.Sum64()
	register := int(hash >> (64 - uniqueVisitorHLLPrecision))
	rank := uint8(bits.LeadingZeros64(hash<<uniqueVisitorHLLPrecision) + 1)
	maxRank := uint8(64 - uniqueVisitorHLLPrecision + 1)
	if rank > maxRank {
		rank = maxRank
	}
	if rank > bucket.registers[register] {
		bucket.registers[register] = rank
		c.updateUnionRegister(register, rank)
	}
}

func (c *uniqueVisitorCounter) estimate(timestamp time.Time) int64 {
	c.advanceWindow(timestamp)
	if c.unionZeroRegisters == uniqueVisitorHLLRegisters {
		return 0
	}

	m := float64(uniqueVisitorHLLRegisters)
	estimate := uniqueVisitorHLLAlpha() * m * m / c.unionHarmonicSum
	if estimate <= 2.5*m && c.unionZeroRegisters > 0 {
		estimate = m * math.Log(m/float64(c.unionZeroRegisters))
	}
	return int64(math.Round(estimate))
}

func (c *uniqueVisitorCounter) advanceWindow(timestamp time.Time) {
	hour := timestamp.UTC().Unix() / int64(time.Hour.Seconds())
	if c.windowInitialized && hour <= c.windowHour {
		return
	}
	bucket := &c.buckets[hour%uniqueVisitorWindowHours]
	if bucket.hour != hour {
		clear(bucket.registers)
		bucket.hour = hour
	}
	c.windowHour = hour
	c.windowInitialized = true
	c.rebuildUnion()
}

func (c *uniqueVisitorCounter) rebuildUnion() {
	clear(c.unionRegisters)
	c.unionHarmonicSum = 0
	c.unionZeroRegisters = 0
	oldestHour := c.windowHour - uniqueVisitorWindowHours + 1
	for register := range c.unionRegisters {
		maxRank := uint8(0)
		for index := range c.buckets {
			bucket := &c.buckets[index]
			if bucket.hour >= oldestHour && bucket.hour <= c.windowHour && bucket.registers[register] > maxRank {
				maxRank = bucket.registers[register]
			}
		}
		c.unionRegisters[register] = maxRank
		if maxRank == 0 {
			c.unionZeroRegisters++
		}
		c.unionHarmonicSum += math.Ldexp(1, -int(maxRank))
	}
}

func (c *uniqueVisitorCounter) updateUnionRegister(register int, rank uint8) {
	previous := c.unionRegisters[register]
	if rank <= previous {
		return
	}
	if previous == 0 {
		c.unionZeroRegisters--
	}
	c.unionHarmonicSum += math.Ldexp(1, -int(rank)) - math.Ldexp(1, -int(previous))
	c.unionRegisters[register] = rank
}

func uniqueVisitorHLLAlpha() float64 {
	return 0.7213 / (1 + 1.079/float64(uniqueVisitorHLLRegisters))
}
