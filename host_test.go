package main

import "testing"

func TestCreatingNewHost(t *testing.T) {
	host, err := NewHost("example.com", "/", 1)
	if err != nil {
		t.Fatalf("host should be created: %v", err)
	}
	// t.Log(*host)
	if host.IPAddress != "example.com" {
		t.Error("host ip address should be example.com")
	}
	if host.HealthCheckRoute != "/" {
		t.Error("host health check route should be /")
	}
	if host.HealthCheckInterval != 1 {
		t.Error("host health check interval should be 1")
	}
}

func TestHostCreateWithWrongInterval(t *testing.T) {
	_, err := NewHost("example.com", "/", -1)
	if err == nil {
		t.Fatalf("host should have thrown an error")
	}
	_, err = NewHost("example.com", "/", 0)
	if err == nil {
		t.Fatalf("host should have thrown an error")
	}
}
