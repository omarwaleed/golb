package main

import (
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"
)

type DistributionType string

const (
	DistributionTypeRoundRobin DistributionType = "round_robin"
	DistributionTypeRandom     DistributionType = "random"
)

type LoadBalancer struct {
	DistributionType  DistributionType
	ForceHTTPS        bool
	CertDomains       []string
	DashboardPassword []byte

	Sticky                     bool
	StickySessionResetInterval int // the amount of seconds to hold a sticky session before an IP address is forgotten
	StickySessionMemoryMu      sync.RWMutex
	StickySessionMemory        map[ipAddressWithPrefix]stickySessionMemoryEntry

	DomainHostsMu sync.RWMutex
	DomainHosts   map[string][]*Host

	LastHostIndexMu sync.RWMutex
	LastHostIndex   int

	rateLimitPerMinute      uint32                          // Number of allowed requests per minute. 0 means no rate limit
	ipAddressToRequestCount map[ipAddress]*ipAddressRequest // Number of requests per IP address

	LogChan chan LogEntry
}

type ipAddress string
type ipAddressRequest struct {
	CountMu    sync.Mutex
	Count      uint32
	ResetTimer *time.Ticker
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
		DomainHosts:             make(map[string][]*Host),
		DistributionType:        distributionType,
		ForceHTTPS:              forceHTTPS,
		Sticky:                  sticky,
		ipAddressToRequestCount: make(map[ipAddress]*ipAddressRequest),
		LogChan:                 logChan,
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

func (lb *LoadBalancer) GetHosts(domain string) []Host {
	var domainHosts []Host
	lb.DomainHostsMu.Lock()
	defer lb.DomainHostsMu.Unlock()
	for _, val := range lb.DomainHosts[domain] {
		domainHosts = append(domainHosts, *val)
	}
	return domainHosts
}

func (lb *LoadBalancer) AddHost(domain string, host *Host) error {
	domainHosts, ok := lb.DomainHosts[domain]
	if !ok {
		if !ok {
			domainHosts = make([]*Host, 0)
		}
	}
	lb.DomainHosts[domain] = append(domainHosts, host)
	err := host.StartHealthCheck()
	return err
}

func (lb *LoadBalancer) RemoveHost(domain string, hostIndex int) {
	lb.DomainHostsMu.Lock()
	defer lb.DomainHostsMu.Unlock()
	host := lb.DomainHosts[domain][hostIndex]
	host.StopHealthCheck()
	lb.DomainHosts[domain] = append(lb.DomainHosts[domain][:hostIndex], lb.DomainHosts[domain][hostIndex+1:]...)
}

func (lb *LoadBalancer) GetRateLimit() uint32 {
	return lb.rateLimitPerMinute
}

func (lb *LoadBalancer) SetRateLimit(limit uint32) {
	lb.rateLimitPerMinute = limit
}

func (lb *LoadBalancer) CheckRateLimit(ipAddress ipAddress) bool {
	log.Println("Checking rate limit of:", lb.rateLimitPerMinute, "for IP address:", ipAddress)
	if lb.rateLimitPerMinute == 0 {
		return true
	}
	val, ok := lb.ipAddressToRequestCount[ipAddress]
	if !ok {
		lb.ipAddressToRequestCount[ipAddress] = &ipAddressRequest{
			Count:      uint32(1),
			ResetTimer: time.NewTicker(time.Minute),
		}
		go lb.resetRequestCount(ipAddress)
		return true
	}
	val.CountMu.Lock()
	defer val.CountMu.Unlock()
	log.Println("Current count:", val.Count)
	if val.Count >= lb.rateLimitPerMinute {
		return false
	}
	val.Count += 1
	return true
}

func (lb *LoadBalancer) resetRequestCount(ipAddress ipAddress) {
	val, ok := lb.ipAddressToRequestCount[ipAddress]
	if !ok {
		return
	}
	<-val.ResetTimer.C
	val.CountMu.Lock()
	defer val.CountMu.Unlock()
	val.Count = 0
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

func (lb *LoadBalancer) DoRequest(w http.ResponseWriter, r *http.Request, host *Host) {
	// http.Redirect(w, r, r.URL.Scheme+"//"+host.IPAddress, http.StatusFound)
	allowed := lb.CheckRateLimit(ipAddress(r.RemoteAddr))
	if !allowed {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte("Too many requests"))
		return
	}
	r.URL = &url.URL{
		Scheme: "http",
		Host:   host.IPAddress,
		Path:   r.URL.Path,
	}
	r.RequestURI = ""
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		log.Println("do request error:", err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Bad gateway"))
		return
	}
	defer resp.Body.Close()
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
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
