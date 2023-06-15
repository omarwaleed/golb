package main

import (
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
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
	SigningKey        []byte
	EncryptionKey     []byte

	Sticky                     bool
	StickySessionResetInterval int // the amount of seconds to hold a sticky session before an IP address is forgotten

	DomainHostsMu sync.RWMutex
	DomainHosts   []RoutePrefixToHost

	LastHostIndexMu sync.RWMutex
	LastHostIndex   int

	rateLimitPerMinute      uint32                          // Number of allowed requests per minute. 0 means no rate limit
	ipAddressToRequestCount map[IPAddress]*ipAddressRequest // Number of requests per IP address

	LogChan chan LogEntry
}

type IPAddress string
type ipAddressRequest struct {
	CountMu    sync.Mutex
	Count      uint32
	ResetTimer *time.Ticker
}

/*
type ipAddressWithPrefix string // ipAddressWithPrefix is the IP address with the prefix separated with an underscore

	type stickySessionMemoryEntry struct {
		Host        *Host
		LastUsed    time.Time
		ExpireTimer *time.Timer
	}
*/
type NewLoadBalancerParams struct {
	DistributionType DistributionType
	ForceHTTPS       bool
	Sticky           bool
}

func NewLoadBalancer(params *NewLoadBalancerParams) *LoadBalancer {
	_, err := ParseDistrubutionType(string(params.DistributionType))
	if err != nil {
		panic(err)
	}
	logChan := make(chan LogEntry, 1024)
	lb := &LoadBalancer{
		DomainHosts:             []RoutePrefixToHost{},
		DistributionType:        params.DistributionType,
		ForceHTTPS:              params.ForceHTTPS,
		Sticky:                  params.Sticky,
		ipAddressToRequestCount: make(map[IPAddress]*ipAddressRequest),
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

func (lb *LoadBalancer) GetHosts(domain string) []Host {
	var domainHosts []Host
	lb.DomainHostsMu.Lock()
	defer lb.DomainHostsMu.Unlock()
	for index := range lb.DomainHosts {
		val := &lb.DomainHosts[index]
		if val.RoutePrefix == domain {
			for _, host := range val.Hosts {
				domainHosts = append(domainHosts, *host)
			}
		}
	}
	return domainHosts
}

func (lb *LoadBalancer) AddHost(domain string, host *Host) error {
	lb.DomainHostsMu.Lock()
	defer lb.DomainHostsMu.Unlock()
	for index := range lb.DomainHosts {
		routeToHost := &lb.DomainHosts[index]
		if routeToHost.RoutePrefix == domain {
			lb.DomainHosts[index].Hosts = append(lb.DomainHosts[index].Hosts, host)
		}
	}

	lb.DomainHosts = append(lb.DomainHosts, RoutePrefixToHost{
		RoutePrefix: domain,
		Hosts:       []*Host{host},
	})
	err := host.StartHealthCheck()
	return err
}

func (lb *LoadBalancer) RemoveHost(domain string, hostIndex int) {
	lb.DomainHostsMu.Lock()
	defer lb.DomainHostsMu.Unlock()
	for index := range lb.DomainHosts {
		routeToHost := &lb.DomainHosts[index]
		if routeToHost.RoutePrefix == domain {
			if len(lb.DomainHosts[index].Hosts) <= hostIndex {
				return // Host index out of range
			}
			lb.DomainHosts[index].Hosts[hostIndex].StopHealthCheck()
			lb.DomainHosts[index].Hosts = append(lb.DomainHosts[index].Hosts[:hostIndex], lb.DomainHosts[index].Hosts[hostIndex+1:]...)
		}
	}
}

func (lb *LoadBalancer) GetRateLimit() uint32 {
	return lb.rateLimitPerMinute
}

func (lb *LoadBalancer) SetRateLimit(limit uint32) {
	lb.rateLimitPerMinute = limit
}

func (lb *LoadBalancer) CheckRateLimit(ipAddress IPAddress) bool {
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

func (lb *LoadBalancer) resetRequestCount(ipAddress IPAddress) {
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
	allowed := lb.CheckRateLimit(IPAddress(r.RemoteAddr))
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

func (lb *LoadBalancer) MatchHostList(r *http.Request) (*RoutePrefixToHost, error) {

	// Proceed with finding host
	for index := range lb.DomainHosts {
		routeTohosts := &lb.DomainHosts[index]
		key := routeTohosts.RoutePrefix
		hosts := routeTohosts.Hosts
		splitKey := strings.Split(key, "*")
		for i, part := range splitKey {
			splitKey[i] = regexp.QuoteMeta(part)
		}
		modifiedKey := strings.Join(splitKey, ".*")
		match, err := regexp.Match(modifiedKey, []byte(r.Host))
		log.Println("Trying to match", key, "modified to", modifiedKey, "with", r.Host, "result", match)
		if err != nil {
			return nil, err
		}
		if !match {
			continue
		}
		log.Println("Matched key", key)
		return &RoutePrefixToHost{
			RoutePrefix:    key,
			Hosts:          hosts,
			StickySessions: make(map[IPAddress]*StickySessionEntry),
		}, nil
	}
	return nil, errors.New("no hosts found")
}

// Sets the sticky session for the given request. If session is already set and hasn't expried, function does nothing
func (lb *LoadBalancer) SetStickySession(r *http.Request, rpth *RoutePrefixToHost, host *Host) {
	ipAddress := r.RemoteAddr
	rpth.StickySessionMu.Lock()
	defer rpth.StickySessionMu.Unlock()
	currentSession, ok := rpth.StickySessions[IPAddress(ipAddress)]
	if ok && time.Now().Before(currentSession.ExpireAt) {
		return
	}
	rpth.StickySessions[IPAddress(ipAddress)] = &StickySessionEntry{
		Host:     host,
		ExpireAt: time.Now().Add(time.Duration(lb.StickySessionResetInterval) * time.Second),
	}
}

func (lb *LoadBalancer) GetStickySessionHost(r *http.Request, rpth *RoutePrefixToHost) *Host {
	ipAddress := r.RemoteAddr
	rpth.StickySessionMu.Lock()
	defer rpth.StickySessionMu.Unlock()
	currentSession, ok := rpth.StickySessions[IPAddress(ipAddress)]
	if ok && time.Now().Before(currentSession.ExpireAt) {
		return currentSession.Host
	}
	return nil
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
