package lib

import (
	"errors"
	"sync"
)

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
	_, err := ParseDistrubutionType(string(distributionType))
	if err != nil {
		panic(err)
	}
	return &LoadBalancer{
		DomainHosts:      make(map[string][]Host),
		DistributionType: distributionType,
		ForceHTTPS:       forceHTTPS,
		Sticky:           sticky,
	}
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
