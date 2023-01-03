package lib

import (
	"errors"
	"io"
	"log"
	"sync"
	"time"
)

type DistributionType string

const (
	DistributionTypeRoundRobin DistributionType = "round_robin"
	DistributionTypeRandom     DistributionType = "random"
)

type LoadBalancer struct {
	DistributionType           DistributionType
	ForceHTTPS                 bool
	Sticky                     bool
	StickySessionResetInterval int // the amount of seconds to hold a sticky session before an IP address is forgotten
	StickySessionMemoryMu      sync.RWMutex
	StickySessionMemory        map[ipAddressWithPrefix]stickySessionMemoryEntry

	DomainHostsMu sync.RWMutex
	DomainHosts   map[string][]Host

	LastHostIndexMu sync.RWMutex
	LastHostIndex   int

	LogChan chan LogEntry
}

type ipAddressWithPrefix string // ipAddressWithPrefix is the IP address with the prefix separated with an underscore
type stickySessionMemoryEntry struct {
	Host        *Host
	LastUsed    time.Time
	ExpireTimer *time.Timer
}

func NewLoadBalancer(distributionType DistributionType, forceHTTPS bool, sticky bool) *LoadBalancer {
	_, err := ParseDistrubutionType(string(distributionType))
	if err != nil {
		panic(err)
	}
	logChan := make(chan LogEntry, 1024)
	lb := &LoadBalancer{
		DomainHosts:      make(map[string][]Host),
		DistributionType: distributionType,
		ForceHTTPS:       forceHTTPS,
		Sticky:           sticky,
		LogChan:          logChan,
	}
	return lb
}

func ParseDistrubutionType(distributionType string) (DistributionType, error) {
	switch distributionType {
	case "round_robin":
		return DistributionTypeRoundRobin, nil
	case "random":
		return DistributionTypeRandom, nil
	default:
		return "", errors.New("invalid distribution type")
	}
}

func (lb *LoadBalancer) GetStickySessionHost(ipAddress string, prefix string) *Host {
	key := ipAddressWithPrefix(ipAddress + "_" + prefix)
	lb.StickySessionMemoryMu.Lock()
	defer lb.StickySessionMemoryMu.Unlock()
	entry, ok := lb.StickySessionMemory[key]
	if !ok {
		return nil
	}
	return entry.Host
}

func (lb *LoadBalancer) SetStickySessionHost(ipAddress string, prefix string, host *Host) error {
	key := ipAddressWithPrefix(ipAddress + "_" + prefix)
	lb.StickySessionMemoryMu.Lock()
	defer lb.StickySessionMemoryMu.Unlock()
	entry, ok := lb.StickySessionMemory[key]
	if !ok {
		timer := time.NewTimer(time.Duration(lb.StickySessionResetInterval) * time.Second)
		entry = stickySessionMemoryEntry{
			Host:        host,
			LastUsed:    time.Now(),
			ExpireTimer: timer,
		}
		go lb.expireStickySession(key)
	} else {
		entry.LastUsed = time.Now()
		entry.ExpireTimer.Reset(time.Duration(lb.StickySessionResetInterval) * time.Second)
	}
	return nil
}

func (lb *LoadBalancer) expireStickySession(key ipAddressWithPrefix) {
	entry, ok := lb.StickySessionMemory[key]
	if !ok {
		lb.LogChan <- LogEntry{
			Type:    LogTypeError,
			Message: "Sticky session memory entry not found",
		}
		return
	}
	<-entry.ExpireTimer.C
	lb.StickySessionMemoryMu.Lock()
	defer lb.StickySessionMemoryMu.Unlock()
	delete(lb.StickySessionMemory, key)
}

// Starts a goroutine that listens on the log channel and logs the messages with an optional writer
func (lb *LoadBalancer) StartLogger(w *io.WriteCloser) {
	go func() {
		if w != nil {
			defer (*w).Close()
		}
		for {
			entry, ok := <-lb.LogChan
			writeLogEntry(entry, ok, w)
		}
	}()
}

func (lb *LoadBalancer) CloseLogger() {
	var e LogEntry
	e, ok := <-lb.LogChan
	if !ok {
		log.Println("SYSTEM: Log channel already closed")
		return
	}
	writeLogEntry(e, ok, nil)
	close(lb.LogChan)
}

// Writes a log entry to the log and the writer if it is not nil
func writeLogEntry(entry LogEntry, ok bool, w *io.WriteCloser) {
	if !ok {
		log.Println("SYSTEM: Log channel closed")
		if w != nil {
			(*w).Write([]byte("SYSTEM: Log channel closed"))
		}
		return
	}
	log.Println(string(entry.Type) + " : " + entry.Message)
	if w != nil {
		(*w).Write([]byte(string(entry.Type) + " : " + entry.Message))
	}
}
