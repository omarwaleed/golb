package main

import (
	crand "crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	lib "github.com/omarwaleed/golb/lib"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/bcrypt"
)

func main() {

	// Define flags
	configPort := flag.Int("config-port", 8080, "Port to listen on for configuration requests")
	certDomains := flag.String("cert-domains", "", "Comma-separated list of domains to use for TLS certificate")
	hostsConfig := flag.String("hosts", "", "Comma-separated list of domain regex to host ex. *.example.com=1.2.3.4")
	typeConfig := flag.String("type", string(lib.DistributionTypeRoundRobin), "Type of load balancing to use. Defaults to round_robin")
	forceHttpsConfig := flag.Bool("force-https", false, "Force HTTPS on all requests")
	stickyConfig := flag.Bool("sticky", false, "Enable sticky sessions")
	dashboardPasswordConfig := flag.String("dashboard-password", "", "Password to use for dashboard")

	flag.Parse()

	distributionType, err := lib.ParseDistrubutionType(*typeConfig)
	if err != nil {
		panic(err)
	}

	// Initialize load balancer
	lb := lib.NewLoadBalancer(distributionType, *forceHttpsConfig, *stickyConfig)
	if len(*hostsConfig) > 0 {
		hostStrings := strings.Split(*hostsConfig, ",")
		for _, hostString := range hostStrings {
			hostSplit := strings.Split(hostString, "=")
			if len(hostSplit) != 2 {
				panic("Invalid host configuration")
			}
			host, err := lib.NewHost(hostSplit[1], "/", 30)
			if err != nil {
				panic(err)
			}
			lb.AddHost(hostSplit[0], host)
		}
	}

	// Set certificate domains
	if len(*certDomains) > 0 {
		domains := strings.Split(*certDomains, ",")
		lb.CertDomains = domains
	}

	// Set dashboard password
	var dashboardPassword string
	if len(*dashboardPasswordConfig) == 0 {
		generatedPassword := make([]byte, 16)
		_, err = crand.Read(generatedPassword)
		if err != nil {
			panic(err)
		}
		generatedPasswordbase64 := make([]byte, len(generatedPassword)*2)
		base64.URLEncoding.Encode(generatedPasswordbase64, generatedPassword)
		dashboardPassword = string(generatedPasswordbase64)
		log.Println("Generated dashboard password:", dashboardPassword)
	} else {
		dashboardPassword = *dashboardPasswordConfig
	}
	encryptedPassword, err := bcrypt.GenerateFromPassword([]byte(dashboardPassword), 10)
	if err != nil {
		panic(err)
	}
	lb.DashboardPassword = encryptedPassword

	// Initialize HTTP and HTTPS listeners
	go ListenInsecure(lb)
	go ListenSecure(lb)

	// Initialize configuration listener
	configMux := http.NewServeMux()
	configMux.Handle("/*", HandleConfigRequest(lb))
	configServer := http.Server{
		Addr:    ":" + strconv.Itoa(*configPort),
		Handler: configMux,
	}
	log.Println("Load balancer started. Config server listening on port", *configPort)
	err = configServer.ListenAndServe()
	if err != nil {
		log.Fatalln(err)
	}
}

// Start a listener for HTTP requests
func ListenInsecure(lb *lib.LoadBalancer) {
	log.Println("Listening on port 80")
	err := http.ListenAndServe(":80", HandleRequestInsecure(lb))
	if err != nil {
		log.Fatalln(err)
	}
}

// Start a listener for HTTPS requests
func ListenSecure(lb *lib.LoadBalancer) {
	if len(lb.CertDomains) != 0 {
		log.Println("Listening on port 443 with AutoTLS for domains", lb.CertDomains)
		err := http.Serve(autocert.NewListener(lb.CertDomains...), HandleRequestSecure(lb))
		if err != nil {
			log.Fatalln(err)
		}
		return
	}
	log.Println("Listening on port 443")
	err := http.ListenAndServe(":443", HandleRequestSecure(lb))
	if err != nil {
		log.Fatalln(err)
	}
}

// Handle HTTP requests
func HandleRequestInsecure(lb *lib.LoadBalancer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("Received request on port 80", time.Now(), r.URL.String())
		if lb.ForceHTTPS {
			pathPrefix := ""
			if strings.HasPrefix(r.URL.String(), "/") {
				pathPrefix = "/"
			}
			http.Redirect(w, r, "https://"+r.Host+pathPrefix+r.URL.String(), http.StatusMovedPermanently)
			return
		}
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

// Handle HTTPS requests
func HandleRequestSecure(lb *lib.LoadBalancer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("Received request on port 443", time.Now(), r.URL.String())
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
		w.WriteHeader(http.StatusNotImplemented)
		w.Write([]byte("Not implemented"))
	})
}

// Actual implementation of the round robin algorithm
func HandleRoundRobinRequest(w http.ResponseWriter, r *http.Request, lb *lib.LoadBalancer) {
	lb.DomainHostsMu.Lock()
	defer lb.DomainHostsMu.Unlock()
	hosts, err := MatchHostList(r, lb)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Bad gateway"))
		return
	}
	validHosts := GetValidHosts(hosts)
	if len(validHosts) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("No host available"))
		return
	}
	lb.LastHostIndexMu.Lock()
	defer lb.LastHostIndexMu.Unlock()
	lb.LastHostIndex++
	if lb.LastHostIndex >= len(validHosts) {
		lb.LastHostIndex = 0
	}
	host := validHosts[lb.LastHostIndex]
	DoRequest(w, r, host)
}

// Actual implementation of the round robin algorithm
func HandleRandomRequest(w http.ResponseWriter, r *http.Request, lb *lib.LoadBalancer) {
	lb.DomainHostsMu.Lock()
	defer lb.DomainHostsMu.Unlock()
	hosts, err := MatchHostList(r, lb)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Bad gateway"))
		return
	}
	validHosts := GetValidHosts(hosts)
	if len(validHosts) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("No host available"))
		return
	}
	var host *lib.Host
	if len(validHosts) == 1 {
		host = (validHosts)[0]
	} else {
		rand.Intn(len(validHosts))
		host = validHosts[rand.Intn(len(validHosts))]
	}
	DoRequest(w, r, host)
}

func DoRequest(w http.ResponseWriter, r *http.Request, host *lib.Host) {
	// http.Redirect(w, r, r.URL.Scheme+"//"+host.IPAddress, http.StatusFound)
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

func MatchHostList(r *http.Request, lb *lib.LoadBalancer) ([]*lib.Host, error) {
	for key, hosts := range lb.DomainHosts {
		modifiedKey := strings.Replace(key, "*", "(.)*", -1)
		match, err := regexp.Match(modifiedKey, []byte(r.Host))
		log.Println("Trying to match", key, "modified to", modifiedKey, "with", r.Host, "result", match)
		if err != nil {
			return nil, err
		}
		if !match {
			continue
		}
		log.Println("Matched key", key)
		return hosts, nil
	}
	return nil, errors.New("no hosts found")
}

// Return only the hosts that are up
func GetValidHosts(hosts []*lib.Host) []*lib.Host {
	validHosts := make([]*lib.Host, 0)
	for _, host := range hosts {
		if host.Status == lib.HostStatusUp {
			validHosts = append(validHosts, host)
		}
	}
	return validHosts
}
