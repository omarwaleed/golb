package main

import (
	"errors"
	"flag"
	"log"
	"math/rand"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	lib "github.com/omarwaleed/golb/lib"
)

func main() {

	// Define flags
	configPort := flag.Int("config-port", 8080, "Port to listen on for configuration requests")
	hostsConfig := flag.String("hosts", "", "Comma-separated list of domain regex to host ex. *.example.com=1.2.3.4")

	flag.Parse()

	// Initialize load balancer
	lb := lib.NewLoadBalancer(lib.DistributionTypeRoundRobin, false, false)
	hostStrings := strings.Split(*hostsConfig, ",")
	for _, hostString := range hostStrings {
		hostSplit := strings.Split(hostString, "=")
		if len(hostSplit) != 2 {
			panic("Invalid host configuration")
		}
		domainHosts, ok := lb.DomainHosts[hostSplit[0]]
		if !ok {
			domainHosts = make([]lib.Host, 0)
		}
		host, err := lib.NewHost(hostSplit[1], "/", 30)
		if err != nil {
			panic(err)
		}
		domainHosts = append(domainHosts, *host)
		lb.DomainHosts[hostSplit[0]] = domainHosts
	}

	// Initialize HTTP and HTTPS listeners
	go ListenInsecure(lb)
	go ListenSecure(lb)

	// Initialize configuration listener
	err := http.ListenAndServe(":"+strconv.Itoa(*configPort), HandleConfigRequest(lb))
	if err != nil {
		log.Fatalln(err)
	}
}

// Start a listener for HTTP requests
func ListenInsecure(lb *lib.LoadBalancer) {
	err := http.ListenAndServe(":80", HandleRequestInsecure(lb))
	if err != nil {
		log.Fatalln(err)
	}
}

// Start a listener for HTTPS requests
func ListenSecure(lb *lib.LoadBalancer) {
	err := http.ListenAndServe(":443", HandleRequestSecure(lb))
	if err != nil {
		log.Fatalln(err)
	}
}

// Handle HTTP requests
func HandleRequestInsecure(lb *lib.LoadBalancer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if lb.ForceHTTPS {
			pathPrefix := ""
			if strings.HasPrefix(r.URL.String(), "/") {
				pathPrefix = "/"
			}
			http.Redirect(w, r, "https://"+r.Host+pathPrefix+r.URL.String(), http.StatusMovedPermanently)
			return
		}
	})
}

// Handle HTTPS requests
func HandleRequestSecure(lb *lib.LoadBalancer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch lb.DistributionType {
		case lib.DistributionTypeRoundRobin:
			HandleRoundRobinRequest(w, r, lb)
		case lib.DistributionTypeRandom:
			HandleRandomRequest(w, r, lb)
		default:
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Bad gateway"))
			return
		}
	})
}

// Handle configuration requests for the load balancer
func HandleConfigRequest(lb *lib.LoadBalancer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO
	})
}

// Actual implementation of the round robin algorithm
func HandleRoundRobinRequest(w http.ResponseWriter, r *http.Request, lb *lib.LoadBalancer) {
	hosts, err := MatchHostList(r, lb)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Bad gateway"))
		return
	}
	validHosts := GetValidHosts(*hosts)
	if len(validHosts) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("No host available"))
		return
	}
	lb.LastHostIndex++
	if lb.LastHostIndex >= len(validHosts) {
		lb.LastHostIndex = 0
	}
	host := validHosts[lb.LastHostIndex]
	http.Redirect(w, r, r.URL.Scheme+"//"+host.IPAddress, http.StatusFound)
}

// Actual implementation of the round robin algorithm
func HandleRandomRequest(w http.ResponseWriter, r *http.Request, lb *lib.LoadBalancer) {
	hosts, err := MatchHostList(r, lb)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Bad gateway"))
		return
	}
	validHosts := GetValidHosts(*hosts)
	if len(validHosts) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("No host available"))
		return
	}
	var host lib.Host
	if len(validHosts) == 1 {
		host = (validHosts)[0]
	} else {
		rand.Intn(len(validHosts))
		host = validHosts[rand.Intn(len(validHosts))]
	}
	http.Redirect(w, r, r.URL.Scheme+"//"+host.IPAddress, http.StatusFound)
}

func MatchHostList(r *http.Request, lb *lib.LoadBalancer) (*[]lib.Host, error) {
	for key, hosts := range lb.DomainHosts {
		match, err := regexp.Match(key, []byte(r.Host))
		if err != nil {
			return nil, err
		}
		if !match {
			continue
		}
		return &hosts, nil
	}
	return nil, errors.New("no hosts found")
}

// Return only the hosts that are up
func GetValidHosts(hosts []lib.Host) []lib.Host {
	validHosts := make([]lib.Host, 0)
	for _, host := range hosts {
		if host.Status == lib.HostStatusUp {
			validHosts = append(validHosts, host)
		}
	}
	return validHosts
}
