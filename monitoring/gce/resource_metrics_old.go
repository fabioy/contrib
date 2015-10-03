package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/api/compute/v1"
)

// Various command line flags for this tool
var (
	project      = flag.String("project", "", "name of project to monitor resources")
	port         = flag.Int("port", 8400, "default port for prometheus metrics end point")
	scrapePeriod = flag.Duration("scrape_period", 5*time.Minute, "frequency of metrics scraping")
)

// Metrics published
var (
	firewallRulesMetric = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "gce_firewall_rules",
			Help: "Count of firewall rules in the project, labeled by network",
		},
		[]string{"network"},
	)
	targetPoolsMetric = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "gce_target_pools",
			Help: "Count of target pools in the project",
		})
	forwardingRulesMetric = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "gce_forwarding_rules",
			Help: "Count of forwarding rules in the project",
		})
	externalIPAddressesMetric = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "gce_ip_addresses",
			Help: "Count of external IP addresses in the project, labeled by status",
		},
		[]string{"status"})
	networksMetric = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "gce_networks",
			Help: "Count of networks in the project",
		})
	routesMetric = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "gce_routes",
			Help: "Count of routes in the project",
		})
)

func checkArgs() {
	if *project == "" {
		log.Fatalf("Error: Empty project. A project name must be specified.")
	}
}

func main() {
	flag.Parse()

	checkArgs()

	prometheus.MustRegister(firewallRulesMetric)
	prometheus.MustRegister(targetPoolsMetric)
	prometheus.MustRegister(forwardingRulesMetric)
	prometheus.MustRegister(externalIPAddressesMetric)
	prometheus.MustRegister(networksMetric)
	prometheus.MustRegister(routesMetric)

	go runPrometheusHandler(*port)
	runScraper(*project, *scrapePeriod)
}

func runPrometheusHandler(port int) {
	http.Handle("/metricsz", prometheus.Handler())
	http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
}

func runScraper(project string, period time.Duration) {
	for {
		log.Println("INFO: Starting scrape loop.")

		processFirewallRules(project)
		processForwadingRules(project)
		processTargetPools(project)
		processRoutes(project)
		processNetworks(project)
		processAddresses(project)

		time.Sleep(period)
	}
}

func processFirewallRules(project string) {
	out, err := getRawResource(project, "firewall-rules")
	if err != nil {
		log.Printf("WARN: Error calling gcloud(%v): %s\n", err, string(out))
		return
	}

	var firewalls []compute.Firewall
	if err := json.Unmarshal(out, &firewalls); err != nil {
		log.Printf("WARN: Error json decoding firewalls: %v\n", err)
		return
	}
	log.Printf("Num firewalls: %d", len(firewalls))

	metrics := make(map[string]int) // map of network : count
	for _, a := range firewalls {
		metrics[a.Network]++
	}

	for s, c := range metrics {
		firewallRulesMetric.WithLabelValues(s).Set(float64(c))
	}
}

func processTargetPools(project string) {
	out, err := getRawResource(project, "target-pools")
	if err != nil {
		log.Printf("WARN: Error calling gcloud(%v): %s\n", err, string(out))
		return
	}

	var targetPools []compute.TargetPool
	if err := json.Unmarshal(out, &targetPools); err != nil {
		log.Printf("WARN: Error json decoding targetPools: %v\n", err)
		return
	}
	log.Printf("Num targetPools: %d", len(targetPools))
	targetPoolsMetric.Set(float64(len(targetPools)))
}

func processForwadingRules(project string) {
	out, err := getRawResource(project, "forwarding-rules")
	if err != nil {
		log.Printf("WARN: Error calling gcloud(%v): %s\n", err, string(out))
		return
	}

	var fwdRules []compute.ForwardingRule
	if err := json.Unmarshal(out, &fwdRules); err != nil {
		log.Printf("WARN: Error json decoding fwdRules: %v\n", err)
		return
	}
	log.Printf("Num fwdRules: %d", len(fwdRules))
	forwardingRulesMetric.Set(float64(len(fwdRules)))
}

func processAddresses(project string) {
	out, err := getRawResource(project, "addresses")
	if err != nil {
		log.Printf("WARN: Error calling gcloud(%v): %s\n", err, string(out))
		return
	}

	var addresses []compute.Address
	if err := json.Unmarshal(out, &addresses); err != nil {
		log.Printf("WARN: Error json decoding addresses: %v\n", err)
		return
	}
	log.Printf("Num addresses: %d", len(addresses))

	metrics := make(map[string]int) // map of status : count
	for _, a := range addresses {
		metrics[a.Status]++
	}

	for s, c := range metrics {
		externalIPAddressesMetric.WithLabelValues(s).Set(float64(c))
	}
}

func processNetworks(project string) {
	out, err := getRawResource(project, "networks")
	if err != nil {
		log.Printf("WARN: Error calling gcloud(%v): %s\n", err, string(out))
		return
	}

	var networks []compute.Network
	if err := json.Unmarshal(out, &networks); err != nil {
		log.Printf("WARN: Error json decoding networks: %v\n", err)
		return
	}
	log.Printf("Num networks: %d", len(networks))
	networksMetric.Set(float64(len(networks)))
}

func processRoutes(project string) {
	out, err := getRawResource(project, "routes")
	if err != nil {
		log.Printf("WARN: Error fetching routes(%v): %s\n", err, string(out))
		return
	}

	var routes []compute.Route
	if err := json.Unmarshal(out, &routes); err != nil {
		log.Printf("WARN: Error json decoding routes: %v\n", err)
		return
	}
	log.Printf("Num routes: %d", len(routes))
	routesMetric.Set(float64(len(routes)))
}

func getRawResource(project, resource string) ([]byte, error) {
	args := []string{
		fmt.Sprintf("--project=%s", project),
		"compute",
		resource,
		"list",
		"--format=json",
		"--quiet",
	}

	log.Printf("Running: gcloud %s", args)
	cmd := exec.Command("gcloud", args...)
	return cmd.CombinedOutput()
}
