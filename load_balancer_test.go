package main

import "testing"

func TestLoadBalancerInitializing(t *testing.T) {
	lb := NewLoadBalancer(&NewLoadBalancerParams{DistributionType: DistributionTypeRoundRobin, ForceHTTPS: false, Sticky: false})
	if lb.DistributionType != DistributionTypeRoundRobin {
		t.Fatal("DistributionType should be round_robin")
	}
	if lb.ForceHTTPS != false {
		t.Fatal("ForceHTTPS should be false")
	}
	if lb.Sticky != false {
		t.Fatal("Sticky should be false")
	}
	if len(lb.DomainHosts) != 0 {
		t.Fatal("DomainHosts should be empty")
	}
	if lb.LastHostIndex != 0 {
		t.Fatal("LastHostIndex should be 0")
	}
}

func TestLoadBalancerInitializingWithWrongDistributionType(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("The code did not panic")
		}
	}()
	NewLoadBalancer(&NewLoadBalancerParams{DistributionType: "wrong", ForceHTTPS: false, Sticky: false})
}

func TestDistributionTypeParsing(t *testing.T) {
	distributionType, err := ParseDistrubutionType("round_robin")
	if err != nil {
		t.Fatalf("round_robin DistributionType should be parsed: %v", err)
	}
	if distributionType != DistributionTypeRoundRobin {
		t.Fatal("DistributionType should be round_robin")
	}
	distributionType, err = ParseDistrubutionType("random")
	if err != nil {
		t.Fatalf("random DistributionType should be parsed: %v", err)
	}
	if distributionType != DistributionTypeRandom {
		t.Fatal("DistributionType should be random")
	}
	distributionType, err = ParseDistrubutionType("wrong")
	if err == nil {
		t.Fatal("wrong DistributionType should not return an error")
	}
	if distributionType != "" {
		t.Fatal("DistributionType should be empty")
	}
}
