package main

import (
	"context"
	"flag"
	"log"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	nanoid "github.com/matoous/go-nanoid/v2"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/bcrypt"
)

func main() {

	lb := InitializeLB()

	// Initialize HTTP and HTTPS listeners
	go ListenInsecure(lb)
	go ListenSecure(lb)

	// Initialize configuration listener
	configMux := http.NewServeMux()
	configMux.Handle("/*", HandleConfigRequest(lb))
	configServer := http.Server{
		Addr:    ":" + strconv.Itoa(lb.ConfigPort),
		Handler: configMux,
	}
	log.Println("Load balancer started. Config server listening on port", lb.ConfigPort)
	err := configServer.ListenAndServe()
	if err != nil {
		log.Fatalln(err)
	}
}

const (
	STATUS_BAD_GATEWAY = "Bad Gateway"
	NO_HOST_AVAILABLE  = "No host available"
	HTTP_PREFIX        = "http://"
	HTTPS_PREFIX       = "https://"
	TCP_PREFIX         = "tcp://"
	UDP_PREFIX         = "udp://"
	UNIX_PREFIX        = "unix://"
)

func InitializeLB() *LoadBalancer {
	// Define flags
	configPort := flag.Int("config-port", 8080, "Port to listen on for configuration requests. Defaults to 8080")
	certDomains := flag.String("cert-domains", "", "Comma-separated list of domains to use for TLS certificate")
	hostsConfig := flag.String("hosts", "", "Comma-separated list of domain regex to host ex. *.example.com=1.2.3.4")
	typeConfig := flag.String("type", string(DistributionTypeRoundRobin), "Type of load balancing to use. Defaults to round_robin")
	forceHttpsConfig := flag.Bool("force-https", false, "Force HTTPS on all requests. Defaults to false")
	rateLimitConfig := flag.Int("rate-limit", 0, "Rate limit requests per minute. 0 means no rate limit. Defaults to 0")
	stickyConfig := flag.Bool("sticky", false, "Enable sticky sessions. Defaults to false")
	dashboardPasswordConfig := flag.String("dashboard-password", "", "Password to use for dashboard. Defaults to random password printed to console")
	tokenConfig := flag.String("token", "", "Token to use for dashboard authentication. Defaults to random token printed to console")

	flag.Parse()

	distributionType, err := ParseDistrubutionType(*typeConfig)
	if err != nil {
		panic(err)
	}

	// Initialize load balancer
	lb := NewLoadBalancer(&NewLoadBalancerParams{
		DistributionType: distributionType,
		ForceHTTPS:       *forceHttpsConfig,
		Sticky:           *stickyConfig,
	})

	parseHostsConfig(lb, hostsConfig)

	// Set certificate domains
	if len(*certDomains) > 0 {
		domains := strings.Split(*certDomains, ",")
		lb.CertDomains = domains
	}

	if *rateLimitConfig > 0 {
		lb.SetRateLimit(uint32(*rateLimitConfig))
	}

	if *configPort == 80 || *configPort == 443 {
		panic("Config port cannot be assigned to ports 80 or 443")
	}
	lb.ConfigPort = *configPort

	// Set dashboard password
	var dashboardPassword string = setDashboardPassword(dashboardPasswordConfig)

	// Set dashboard token
	var token string = setDashboardToken(tokenConfig)

	encryptedPassword, err := bcrypt.GenerateFromPassword([]byte(dashboardPassword), 10)
	if err != nil {
		panic(err)
	}
	lb.DashboardPassword = encryptedPassword
	lb.ApiToken = []byte(token)

	return lb
}

// Start a listener for HTTP requests
func ListenInsecure(lb *LoadBalancer) {
	log.Println("Listening on port 80")
	err := http.ListenAndServe(":80", HandleRequestInsecure(lb))
	if err != nil {
		log.Fatalln(err)
	}
}

// Start a listener for HTTPS requests
func ListenSecure(lb *LoadBalancer) {
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

func ListenNetwork(lb *LoadBalancer, network string) {
	networkHosts := []RoutePrefixToHost{}
	if network != "tcp" && network != "udp" && network != "unix" {
		panic("Invalid network type")
	}
	lb.DomainHostsMu.Lock()
	for index := range lb.DomainHosts {
		domainHost := lb.DomainHosts[index].Copy()
		if strings.HasPrefix(domainHost.RoutePrefix, TCP_PREFIX) {
			networkHosts = append(networkHosts, *domainHost.Copy())
		}
	}
	lb.DomainHostsMu.Unlock()
	for index := range networkHosts {
		tcpHost := networkHosts[index].Copy()
		// TODO: don't listen on all network ports, instead listen on specific ports by parsing the route prefix
		listener, err := net.Listen(network, "")
		if err != nil {
			log.Fatalln(err)
		}
		go HandleNonHTTPRequest(network, listener, tcpHost.Hosts)
	}
}

// Handle HTTP requests
func HandleRequestInsecure(lb *LoadBalancer) http.Handler {
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
		case DistributionTypeRoundRobin:
			HandleRoundRobinRequest(w, r, lb)
		case DistributionTypeRandom:
			HandleRandomRequest(w, r, lb)
		default:
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(STATUS_BAD_GATEWAY))
			return
		}
	})
}

// Handle HTTPS requests
func HandleRequestSecure(lb *LoadBalancer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("Received request on port 443", time.Now(), r.URL.String())
		switch lb.DistributionType {
		case DistributionTypeRoundRobin:
			HandleRoundRobinRequest(w, r, lb)
		case DistributionTypeRandom:
			HandleRandomRequest(w, r, lb)
		default:
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(STATUS_BAD_GATEWAY))
			return
		}
	})
}

func HandleNonHTTPRequest(network string, listener net.Listener, hosts []*Host) {
	// accept connection on port
	// connect to host and pipe data to it
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatalln(err)
		}
		defer conn.Close()
		hConn, err := net.Dial(network, hosts[0].IPAddress)
		if err != nil {
			log.Fatalln(err)
		}
		defer hConn.Close()
		if err != nil {
			log.Fatalln(err)
		}
		fromClientChan := make(chan []byte)
		fromHostChan := make(chan []byte)
		ctx, cancelFn := context.WithCancel(context.Background())
		go handleTCPConnectionfunc(&conn, fromClientChan, cancelFn)
		go handleTCPConnectionfunc(&hConn, fromHostChan, cancelFn)
		for {
			select {
			case <-ctx.Done():
				return
			case data := <-fromClientChan:
				_, err := hConn.Write(data)
				if err != nil {
					cancelFn()
					log.Fatalln(err)
				}
			case data := <-fromHostChan:
				_, err := conn.Write(data)
				if err != nil {
					cancelFn()
					log.Fatalln(err)
				}
			}
		}
	}
}

// Awaits data from a TCP connection and sends it to the data channel. Cancels the context on error.
func handleTCPConnectionfunc(conn *net.Conn, dataChan chan []byte, cancelFn context.CancelFunc) {
	buf := make([]byte, 1024)
	for {
		n, err := (*conn).Read(buf)
		if err != nil {
			cancelFn()
			log.Fatalln(err)
		}
		dataChan <- buf[:n]
	}
}

// Handle configuration requests for the load balancer
func HandleConfigRequest(lb *LoadBalancer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO
		w.WriteHeader(http.StatusNotImplemented)
		w.Write([]byte("Not implemented"))
	})
}

// Actual implementation of the round robin algorithm
func HandleRoundRobinRequest(w http.ResponseWriter, r *http.Request, lb *LoadBalancer) {
	lb.DomainHostsMu.Lock()
	defer lb.DomainHostsMu.Unlock()
	routeToHosts, err := lb.MatchHostList(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(STATUS_BAD_GATEWAY))
		return
	}
	validHosts := GetValidHosts(routeToHosts.Hosts)
	if len(validHosts) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(NO_HOST_AVAILABLE))
		return
	}
	lb.LastHostIndexMu.Lock()
	defer lb.LastHostIndexMu.Unlock()
	lb.LastHostIndex++
	if lb.LastHostIndex >= len(validHosts) {
		lb.LastHostIndex = 0
	}
	host := validHosts[lb.LastHostIndex]
	if lb.Sticky {
		lb.SetStickySession(r, routeToHosts, host)
	}
	lb.DoRequest(w, r, host)
}

// Actual implementation of the round robin algorithm
func HandleRandomRequest(w http.ResponseWriter, r *http.Request, lb *LoadBalancer) {
	lb.DomainHostsMu.Lock()
	defer lb.DomainHostsMu.Unlock()
	routeToHosts, err := lb.MatchHostList(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(STATUS_BAD_GATEWAY))
		return
	}
	if lb.Sticky {
		host := lb.GetStickySessionHost(r, routeToHosts)
		if host != nil && host.IsUp() {
			lb.DoRequest(w, r, host)
			return
		}
	}
	validHosts := GetValidHosts(routeToHosts.Hosts)
	if len(validHosts) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(NO_HOST_AVAILABLE))
		return
	}
	var host *Host
	host = getRandomHost(validHosts)
	/* if len(validHosts) == 1 {
		host = (validHosts)[0]
	} else {
		rand.Intn(len(validHosts))
		host = validHosts[rand.Intn(len(validHosts))]
	} */
	if lb.Sticky {
		lb.SetStickySession(r, routeToHosts, host)
	}
	lb.DoRequest(w, r, host)
}

// Return only the hosts that are up
func GetValidHosts(hosts []*Host) []*Host {
	validHosts := make([]*Host, 0)
	for _, host := range hosts {
		if host.Status == HostStatusUp {
			validHosts = append(validHosts, host)
		}
	}
	return validHosts
}

func parseHostsConfig(lb *LoadBalancer, hostsConfig *string) {
	if len(*hostsConfig) > 0 {
		hostStrings := strings.Split(*hostsConfig, ",")
		for _, hostString := range hostStrings {
			hostSplit := strings.Split(hostString, "=")
			if len(hostSplit) != 2 {
				panic("Invalid host configuration")
			}
			host, err := NewHost(hostSplit[1], "/", 30)
			if err != nil {
				panic(err)
			}
			lb.AddHost(hostSplit[0], host)
		}
	}
}

func setDashboardPassword(dashboardPasswordConfig *string) string {
	if len(*dashboardPasswordConfig) == 0 {
		// generatedPassword := make([]byte, 16)
		// _, err = crand.Read(generatedPassword)
		generatedPassword, err := nanoid.New(16)
		if err != nil {
			panic(err)
		}
		// generatedPasswordbase64 := make([]byte, len(generatedPassword)*2)
		// base64.URLEncoding.Encode(generatedPasswordbase64, generatedPassword)
		// dashboardPassword = string(generatedPasswordbase64)
		log.Println("Generated dashboard password:", generatedPassword)
		return generatedPassword
	} else {
		return *dashboardPasswordConfig
	}
}

func setDashboardToken(tokenConfig *string) string {
	if len(*tokenConfig) == 0 {
		// generatedToken := make([]byte, 64)
		// _, err = crand.Read(generatedToken)
		token, err := nanoid.New(32)
		if err != nil {
			panic(err)
		}
		log.Println("Generated API token:", token)
		return token
	} else {
		return *tokenConfig
	}
}

func getRandomHost(hosts []*Host) *Host {
	if len(hosts) == 0 {
		// NOTE: maybe should panic?
		return nil
	}
	return hosts[rand.Intn(len(hosts))]
}
