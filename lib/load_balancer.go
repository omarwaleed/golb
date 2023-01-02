package lib

type DistributionType string

const (
	DistributionTypeRoundRobin DistributionType = "round_robin"
	DistributionTypeRandom     DistributionType = "random"
)

type LoadBalancer struct {
	DomainHosts      map[string][]Host
	DistributionType DistributionType
	ForceHTTPS       bool
	Sticky           bool
}

func NewLoadBalancer(distributionType DistributionType, forceHTTPS bool, sticky bool) *LoadBalancer {
	return &LoadBalancer{
		DomainHosts:      make(map[string][]Host),
		DistributionType: distributionType,
		ForceHTTPS:       forceHTTPS,
		Sticky:           sticky,
	}
}
