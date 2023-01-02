package lib

type Host struct {
	IPAddress           string
	HealthCheckRoute    string
	HealthCheckInterval int
	Status              HostStatus
}

type HostStatus string

const (
	HostStatusUp      HostStatus = "up"
	HostStatusDown    HostStatus = "down"
	HostStatusUnknown HostStatus = "unknown"
)

func NewHost(ipAddress string, healthCheckRoute string, healthCheckInterval int) *Host {
	return &Host{
		IPAddress:           ipAddress,
		HealthCheckRoute:    healthCheckRoute,
		HealthCheckInterval: healthCheckInterval,
		Status:              HostStatusUnknown,
	}
}
