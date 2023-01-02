package lib

import "sync"

type DistributionType string

const (
	DistributionTypeRoundRobin DistributionType = "round_robin"
	DistributionTypeRandom     DistributionType = "random"
)

type LoadBalancer struct {
	DistributionType DistributionType
	ForceHTTPS       bool
	Sticky           bool

	DomainHostsMu sync.RWMutex
	DomainHosts   map[string][]Host

	LastHostIndexMu sync.RWMutex
	LastHostIndex   int
}

func NewLoadBalancer(distributionType DistributionType, forceHTTPS bool, sticky bool) *LoadBalancer {
	return &LoadBalancer{
		DomainHosts:      make(map[string][]Host),
		DistributionType: distributionType,
		ForceHTTPS:       forceHTTPS,
		Sticky:           sticky,
	}
}
