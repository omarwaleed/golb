package lib

import (
	"errors"
	"net/http"
	"strings"
	"time"
)

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
		for range ticker.C {
			_, err := http.DefaultClient.Get(h.IPAddress + h.HealthCheckRoute)
			if err != nil {
				h.Status = HostStatusDown
				continue
			}
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
