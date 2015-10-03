package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"golang.org/x/net/context"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/cloudmonitoring/v2beta2"
	"google.golang.org/api/compute/v1"
)

// Various command line flags for this tool
var (
	project      = flag.String("project", "", "name of project to monitor resources")
	scrapePeriod = flag.Duration("scrape_period", 5*time.Minute, "frequency of metrics scraping")
)

// Metrics published
var (
	metricDescriptions = []MetricDescription{
		MetricDescription{
			Name:        "gce_firewall_rules",
			Description: "Count of firewall rules in the project, labeled by network",
			Labels:      []string{"network"},
		},
		MetricDescription{
			Name:        "gce_target_pools",
			Description: "Count of target pools in the project",
		},
		MetricDescription{
			Name:        "gce_forwarding_rules",
			Description: "Count of forwarding rules in the project",
		},
		MetricDescription{
			Name:        "gce_ip_addresses",
			Description: "Count of external IP addresses in the project, labeled by status",
			Labels:      []string{"status"},
		},
		MetricDescription{
			Name:        "gce_networks",
			Description: "Count of networks in the project",
			Labels:      []string{"network"},
		},
		MetricDescription{
			Name:        "gce_routes",
			Description: "Count of routes in the project",
			Labels:      []string{"network"},
		},
	}
)

type MetricDescription struct {
	Name        string
	Description string
	Labels      []string
}

type Monitor struct {
	Project    string
	Compute    *compute.Service
	Monitoring *cloudmonitoring.Service
}

func main() {
	flag.Parse()

	if *project == "" {
		log.Fatalf("Error: Empty project. A project name must be specified.")
	}

	ctx := context.TODO()

	client, err := google.DefaultClient(ctx, compute.CloudPlatformScope, compute.ComputeReadonlyScope, cloudmonitoring.MonitoringScope)
	if err != nil {
		log.Fatalf("Error creating client: $v", err)
	}
	computeService, err := compute.New(client)
	if err != nil {
		log.Fatalf("Error creating compute service: %v", err)
	}
	monitoringService, err := cloudmonitoring.New(client)
	if err != nil {
		log.Fatalf("Error creating monitoring service: %v", err)
	}

	monitor := &Monitor{*project, computeService, monitoringService}

	monitor.CreateMetricDescriptors(metricDescriptions)

	for {
		log.Println("INFO: Starting scrape loop.")

		monitor.ProcessFirewallRules()
		monitor.ProcessIPAddresses()
		monitor.ProcessForwardingRules()
		monitor.ProcessNetworks()
		monitor.ProcessRoutes()
		monitor.ProcessTargetPools()

		time.Sleep(*scrapePeriod)
	}
}

func (m *Monitor) CreateMetricDescriptors(descs []MetricDescription) {
	for _, metric := range descs {
		md := &cloudmonitoring.MetricDescriptor{
			Project:     m.Project,
			Name:        fmt.Sprintf("custom.cloudmonitoring.googleapis.com/%s", metric.Name),
			Description: metric.Description,
			TypeDescriptor: &cloudmonitoring.MetricDescriptorTypeDescriptor{
				MetricType: "gauge",
				ValueType:  "double",
			},
		}
		if len(metric.Labels) != 0 {
			labels := []*cloudmonitoring.MetricDescriptorLabelDescriptor{}
			for _, l := range metric.Labels {
				labels = append(labels, &cloudmonitoring.MetricDescriptorLabelDescriptor{
					Key:         fmt.Sprintf("custom.cloudmonitoring.googleapis.com/%s", l),
					Description: l,
				})
			}
			md.Labels = labels
		}

		res, err := m.Monitoring.MetricDescriptors.Create(m.Project, md).Do()
		if err != nil {
			log.Fatalf("Error creating firewall metric: %v", err)
		}
		log.Printf("Created metric: %s\n", res)
	}
}

func (m *Monitor) reportLabeledTimeseries(name string, values []float64, labels []map[string]string) error {
	nowTime := time.Now().Format(time.RFC3339)
	points := []*cloudmonitoring.TimeseriesPoint{}

	for i, val := range values {
		refVal := val
		desc := &cloudmonitoring.TimeseriesDescriptor{
			Metric:  fmt.Sprintf("custom.cloudmonitoring.googleapis.com/%s", name),
			Project: m.Project,
		}
		if len(labels) > i {
			// Munge the labels to have the proper custom prefix
			desc.Labels = fixLabels(labels[i])
		}
		p := &cloudmonitoring.TimeseriesPoint{
			Point: &cloudmonitoring.Point{
				DoubleValue: &refVal,
				Start:       nowTime,
				End:         nowTime,
			},
			TimeseriesDesc: desc,
		}
		points = append(points, p)
	}

	req := &cloudmonitoring.WriteTimeseriesRequest{
		Timeseries: points,
	}

	resp, err := m.Monitoring.Timeseries.Write(m.Project, req).Do()
	log.Printf("Resp: %v\nErr: %v\n", resp, err)

	return err
}

func fixLabels(labels map[string]string) map[string]string {
	if labels == nil {
		return nil
	}
	munged := map[string]string{}
	for l, v := range labels {
		munged[fmt.Sprintf("custom.cloudmonitoring.googleapis.com/%s", l)] = v
	}

	return munged
}

func (m *Monitor) reportTimeseries(name string, value float64) error {
	return m.reportLabeledTimeseries(name, []float64{value}, nil)
}

func (m *Monitor) ProcessFirewallRules() {
	list, err := m.Compute.Firewalls.List(m.Project).Do()
	if err != nil {
		log.Printf("ERROR: Listing firewall: %v\n", err)
		return
	}

	log.Printf("Num firewalls: %d", len(list.Items))

	metrics := make(map[string]int) // map of network : count
	for _, f := range list.Items {
		metrics[f.Network]++
	}

	values := []float64{}
	labels := []map[string]string{}
	for s, c := range metrics {
		values = append(values, float64(c))
		labels = append(labels, map[string]string{"network": s})
	}

	if err := m.reportLabeledTimeseries("gce_firewall_rules", values, labels); err != nil {
		log.Printf("Err: %v\n", err)
	}
}

func (m *Monitor) ProcessTargetPools() {
	list, err := m.Compute.TargetPools.AggregatedList(m.Project).Do()
	if err != nil {
		log.Printf("ERROR: Listing target pools: %v\n", err)
		return
	}

	log.Printf("Num target pools: %d", len(list.Items))

	if err := m.reportTimeseries("gce_target_pools", float64(len(list.Items))); err != nil {
		log.Printf("Err: %v\n", err)
	}
}

func (m *Monitor) ProcessForwardingRules() {
	list, err := m.Compute.GlobalForwardingRules.List(m.Project).Do()
	if err != nil {
		log.Printf("ERROR: Listing forwarding rules: %v\n", err)
		return
	}

	log.Printf("Num forwarding rules: %d", len(list.Items))

	if err := m.reportTimeseries("gce_forwarding_rules", float64(len(list.Items))); err != nil {
		log.Printf("Err: %v\n", err)
	}
}

func (m *Monitor) ProcessNetworks() {
	list, err := m.Compute.Networks.List(m.Project).Do()
	if err != nil {
		log.Printf("ERROR: Listing Networks: %v\n", err)
		return
	}

	log.Printf("Num networks: %d", len(list.Items))

	if err := m.reportTimeseries("gce_networks", float64(len(list.Items))); err != nil {
		log.Printf("Err: %v\n", err)
	}
}

func (m *Monitor) ProcessRoutes() {
	list, err := m.Compute.Routes.List(m.Project).Do()
	if err != nil {
		log.Printf("ERROR: Listing routes: %v\n", err)
		return
	}

	log.Printf("Num routes: %d", len(list.Items))

	if err := m.reportTimeseries("gce_routes", float64(len(list.Items))); err != nil {
		log.Printf("Err: %v\n", err)
	}
}

func (m *Monitor) ProcessIPAddresses() {
	list, err := m.Compute.GlobalAddresses.List(m.Project).Do()
	if err != nil {
		log.Printf("ERROR: Listing addresses: %v\n", err)
		return
	}

	log.Printf("Num addresses: %d", len(list.Items))

	metrics := make(map[string]int) // map of status : count
	for _, a := range list.Items {
		metrics[a.Status]++
	}

	values := []float64{}
	labels := []map[string]string{}
	for s, c := range metrics {
		values = append(values, float64(c))
		labels = append(labels, map[string]string{"status": s})
	}

	if err := m.reportLabeledTimeseries("gce_ip_addresses", values, labels); err != nil {
		log.Printf("Err: %v\n", err)
	}
}
