package main

import (
	"errors"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

type RoutePrefixToHost struct {
	RoutePrefix     string
	Hosts           []*Host
	StickySessionMu sync.Mutex
	StickySessions  map[IPAddress]*StickySessionEntry
}

type StickySessionEntry struct {
	Host     *Host
	ExpireAt time.Time
}

type Host struct {
	IPAddress           string // IP address of host including optional port
	HealthCheckRoute    string
	HealthCheckInterval int
	Status              HostStatus
	healthCheckTicker   *time.Ticker
}

type HostStatus string

const (
	HostStatusUp      HostStatus = "up"
	HostStatusDown    HostStatus = "down"
	HostStatusUnknown HostStatus = "unknown"
)

func NewHost(ipAddress string, healthCheckRoute string, healthCheckInterval int) (*Host, error) {
	if !strings.HasPrefix(healthCheckRoute, "/") {
		return nil, errors.New("health check route must start with a slash")
	}
	if strings.HasPrefix(healthCheckRoute, "//") {
		return nil, errors.New("health check route must not start with two slashes")
	}
	if healthCheckInterval < 1 {
		return nil, errors.New("health check interval must be greater than 0")
	}
	if strings.HasPrefix(ipAddress, "http://") || strings.HasPrefix(ipAddress, "https://") {
		ipAddress = strings.Replace(ipAddress, "http://", "", 1)
		ipAddress = strings.Replace(ipAddress, "https://", "", 1)
	}
	return &Host{
		IPAddress:           ipAddress,
		HealthCheckRoute:    healthCheckRoute,
		HealthCheckInterval: healthCheckInterval,
		Status:              HostStatusUnknown,
	}, nil
}

func (h *Host) StartHealthCheck() error {
	if h.healthCheckTicker != nil {
		return errors.New("health check already started")
	}
	ticker := time.NewTicker(time.Duration(h.HealthCheckInterval) * time.Second)
	h.healthCheckTicker = ticker
	go func() {
		log.Println("Started health check ticker for", h.IPAddress)
		defer ticker.Stop()
		for ; true; <-ticker.C {
			log.Println("Health Tick for", h.IPAddress)
			_, err := http.DefaultClient.Get("http://" + h.IPAddress + h.HealthCheckRoute)
			if err != nil {
				log.Println("Health Tick for", h.IPAddress, "is", h.Status, "with error", err)
				h.Status = HostStatusDown
				continue
			}
			if h.Status != HostStatusUp {
				h.Status = HostStatusUp
			}
			log.Println("Health Tick for", h.IPAddress, "is", h.Status)
		}
	}()
	return nil
}

func (h *Host) StopHealthCheck() error {
	if h.healthCheckTicker == nil {
		return errors.New("health check not started")
	}
	h.healthCheckTicker.Stop()
	h.healthCheckTicker = nil
	h.Status = HostStatusUnknown
	return nil
}

func (h *Host) IsUp() bool {
	return h.Status == HostStatusUp
}
