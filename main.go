package main

import (
	"flag"
	"net/http"
	"strconv"

	lib "github.com/omarwaleed/golb/lib"
)

func main() {

	// Define flags
	configPort := flag.Int("config-port", 8080, "Port to listen on for configuration requests")

	flag.Parse()

	// Initialize load balancer
	lb := lib.NewLoadBalancer(lib.DistributionTypeRoundRobin, false, false)

	// Initialize HTTP and HTTPS listeners
	go ListenInsecure(lb)
	go ListenSecure(lb)

	// Initialize configuration listener
	http.ListenAndServe(":"+strconv.Itoa(*configPort), HandleConfigRequest(lb))
}

func ListenInsecure(lb *lib.LoadBalancer) {
	http.ListenAndServe(":80", HandleRequestInsecure(lb))
}

func ListenSecure(lb *lib.LoadBalancer) {
	http.ListenAndServe(":443", HandleRequestSecure(lb))
}

func HandleRequestInsecure(lb *lib.LoadBalancer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if lb.ForceHTTPS {
			http.Redirect(w, r, "https://"+r.Host+r.URL.String(), http.StatusMovedPermanently)
			return
		}
	})
}

func HandleRequestSecure(lb *lib.LoadBalancer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO
	})
}

func HandleConfigRequest(lb *lib.LoadBalancer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO
	})
}

func HandleRoundRobinRequest(w http.ResponseWriter, r *http.Request, lb *lib.LoadBalancer) {
	// TODO
}

func HandleRandomRequest(w http.ResponseWriter, r *http.Request, lb *lib.LoadBalancer) {
	// TODO
}
