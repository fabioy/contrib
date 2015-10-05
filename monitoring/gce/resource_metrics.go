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

// Monitor is the main struct for this class, holding the global config and
// the various clients needed to talk to GCE.
type Monitor struct {
	Project    string
	Compute    *compute.Service
	Monitoring *cloudmonitoring.Service
}

// MetricDescription defines the name and label for the custom metrics to be
// registered and published. Note that all metrics are of type "int64" for now.
type MetricDescription struct {
	Name        string
	Description string
	Labels      []string
}

// CustomGaugeMetric defines the methods that need to be implemented to have a
// custom metric be registered and processed.
type CustomGaugeMetric interface {
	// MetricDescription should return a MetricDescription struct defining the
	// custom metric.
	MetricDescription() MetricDescription

	// ProcessMetric is called periodically, and should gather any data it needs
	// and call into Monitor object's Report**TimeSeries method to report it.
	ProcessMetric(m *Monitor) error
}

// Metrics published
var customMetrics = []CustomGaugeMetric{
	new(FirewallRules),
	new(TargetPools),
	new(ForwardingRules),
	new(GlobalForwardingRules),
	new(Addresses),
	new(GlobalAddresses),
	new(Networks),
	new(Routes),
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

	// Register all metrics
	for _, m := range customMetrics {
		monitor.createMetricDescriptor(m.MetricDescription())
	}

	for {
		log.Println("INFO: Starting scrape loop.")

		for _, m := range customMetrics {
			if err := m.ProcessMetric(monitor); err != nil {
				log.Printf("ERROR: Error processing metric %s. Err: %v", m.MetricDescription().Name, err)
			}
		}

		time.Sleep(*scrapePeriod)
	}
}

func (m *Monitor) createMetricDescriptor(metric MetricDescription) {
	md := &cloudmonitoring.MetricDescriptor{
		Project:     m.Project,
		Name:        fmt.Sprintf("custom.cloudmonitoring.googleapis.com/%s", metric.Name),
		Description: metric.Description,
		TypeDescriptor: &cloudmonitoring.MetricDescriptorTypeDescriptor{
			MetricType: "gauge",
			ValueType:  "int64",
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

func (m *Monitor) ReportLabeledTimeseries(name string, values []int64, labels []map[string]string) error {
	nowTime := time.Now().Format(time.RFC3339)
	points := []*cloudmonitoring.TimeseriesPoint{}

	if len(values) == 0 {
		return nil
	}

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
				Int64Value: &refVal,
				Start:      nowTime,
				End:        nowTime,
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

func (m *Monitor) ReportTimeseries(name string, value int64) error {
	return m.ReportLabeledTimeseries(name, []int64{value}, nil)
}

///////////////////////////////////////////////////////////////////////////////
// Firewall rules metric
///////////////////////////////////////////////////////////////////////////////
type FirewallRules struct{}

func (_ *FirewallRules) MetricDescription() MetricDescription {
	return MetricDescription{
		Name:        "gce_firewall_rules",
		Description: "Count of firewall rules in the project, labeled by network",
		Labels:      []string{"network"},
	}
}

func (_ *FirewallRules) ProcessMetric(m *Monitor) error {
	list, err := m.Compute.Firewalls.List(m.Project).Do()
	if err != nil {
		return err
	}

	log.Printf("Num firewalls: %d", len(list.Items))

	metrics := make(map[string]int) // map of network : count
	for _, f := range list.Items {
		metrics[f.Network]++
	}

	values := []int64{}
	labels := []map[string]string{}
	for s, c := range metrics {
		values = append(values, int64(c))
		labels = append(labels, map[string]string{"network": s})
	}

	if err := m.ReportLabeledTimeseries("gce_firewall_rules", values, labels); err != nil {
		return err
	}

	return nil
}

///////////////////////////////////////////////////////////////////////////////
// Target pools metric
///////////////////////////////////////////////////////////////////////////////
type TargetPools struct{}

func (_ *TargetPools) MetricDescription() MetricDescription {
	return MetricDescription{
		Name:        "gce_target_pools",
		Description: "Count of target pools in the project",
	}
}

func (_ *TargetPools) ProcessMetric(m *Monitor) error {
	list, err := m.Compute.TargetPools.AggregatedList(m.Project).Do()
	if err != nil {
		return err
	}

	log.Printf("Num target pools: %d", len(list.Items))

	if err := m.ReportTimeseries("gce_target_pools", int64(len(list.Items))); err != nil {
		return err
	}

	return nil
}

///////////////////////////////////////////////////////////////////////////////
// Forwarding rules metric
///////////////////////////////////////////////////////////////////////////////
type ForwardingRules struct{}

func (_ *ForwardingRules) MetricDescription() MetricDescription {
	return MetricDescription{
		Name:        "gce_forwarding_rules",
		Description: "Count of forwarding rules in the project",
	}
}

func (_ *ForwardingRules) ProcessMetric(m *Monitor) error {
	list, err := m.Compute.ForwardingRules.AggregatedList(m.Project).Do()
	if err != nil {
		return err
	}

	log.Printf("Num forwarding rules: %d", len(list.Items))

	if err := m.ReportTimeseries("gce_forwarding_rules", int64(len(list.Items))); err != nil {
		return err
	}

	return nil
}

///////////////////////////////////////////////////////////////////////////////
// Global forwarding rules metric
///////////////////////////////////////////////////////////////////////////////
type GlobalForwardingRules struct{}

func (_ *GlobalForwardingRules) MetricDescription() MetricDescription {
	return MetricDescription{
		Name:        "gce_global_forwarding_rules",
		Description: "Count of global forwarding rules in the project",
	}
}

func (_ *GlobalForwardingRules) ProcessMetric(m *Monitor) error {
	list, err := m.Compute.GlobalForwardingRules.List(m.Project).Do()
	if err != nil {
		return err
	}

	log.Printf("Num global forwarding rules: %d", len(list.Items))

	if err := m.ReportTimeseries("gce_global_forwarding_rules", int64(len(list.Items))); err != nil {
		return err
	}

	return nil
}

///////////////////////////////////////////////////////////////////////////////
// Networks metric
///////////////////////////////////////////////////////////////////////////////
type Networks struct{}

func (_ *Networks) MetricDescription() MetricDescription {
	return MetricDescription{
		Name:        "gce_networks",
		Description: "Count of networks in the project",
		Labels:      []string{"network"},
	}
}

func (_ *Networks) ProcessMetric(m *Monitor) error {
	list, err := m.Compute.Networks.List(m.Project).Do()
	if err != nil {
		return err
	}

	log.Printf("Num networks: %d", len(list.Items))

	if err := m.ReportTimeseries("gce_networks", int64(len(list.Items))); err != nil {
		return err
	}

	return nil
}

///////////////////////////////////////////////////////////////////////////////
// Routes metric
///////////////////////////////////////////////////////////////////////////////
type Routes struct{}

func (_ *Routes) MetricDescription() MetricDescription {
	return MetricDescription{
		Name:        "gce_routes",
		Description: "Count of routes in the project",
		Labels:      []string{"network"},
	}
}

func (_ *Routes) ProcessMetric(m *Monitor) error {
	list, err := m.Compute.Routes.List(m.Project).Do()
	if err != nil {
		return err
	}

	log.Printf("Num routes: %d", len(list.Items))

	if err := m.ReportTimeseries("gce_routes", int64(len(list.Items))); err != nil {
		return err
	}

	return nil
}

///////////////////////////////////////////////////////////////////////////////
// Addresses metric
///////////////////////////////////////////////////////////////////////////////
type Addresses struct{}

func (_ *Addresses) MetricDescription() MetricDescription {
	return MetricDescription{
		Name:        "gce_addresses",
		Description: "Count of external IP addresses in the project, labeled by status",
		Labels:      []string{"status"},
	}
}

func (_ *Addresses) ProcessMetric(m *Monitor) error {
	list, err := m.Compute.Addresses.AggregatedList(m.Project).Do()
	if err != nil {
		return err
	}

	log.Printf("Num addresses: %d", len(list.Items))

	metrics := make(map[string]int) // map of status : count
	for _, scopedList := range list.Items {
		for _, addr := range scopedList.Addresses {
			metrics[addr.Status]++
		}
	}

	values := []int64{}
	labels := []map[string]string{}
	for s, c := range metrics {
		values = append(values, int64(c))
		labels = append(labels, map[string]string{"status": s})
	}

	if err := m.ReportLabeledTimeseries("gce_addresses", values, labels); err != nil {
		return err
	}

	return nil
}

///////////////////////////////////////////////////////////////////////////////
// Global addresses metric
///////////////////////////////////////////////////////////////////////////////
type GlobalAddresses struct{}

func (_ *GlobalAddresses) MetricDescription() MetricDescription {
	return MetricDescription{
		Name:        "gce_global_addresses",
		Description: "Count of global external IP addresses in the project, labeled by status",
		Labels:      []string{"status"},
	}
}

func (_ *GlobalAddresses) ProcessMetric(m *Monitor) error {
	list, err := m.Compute.GlobalAddresses.List(m.Project).Do()
	if err != nil {
		return err
	}

	log.Printf("Num global addresses: %d", len(list.Items))

	metrics := make(map[string]int) // map of status : count
	for _, a := range list.Items {
		metrics[a.Status]++
	}

	values := []int64{}
	labels := []map[string]string{}
	for s, c := range metrics {
		values = append(values, int64(c))
		labels = append(labels, map[string]string{"status": s})
	}

	if err := m.ReportLabeledTimeseries("gce_global_addresses", values, labels); err != nil {
		return err
	}

	return nil
}
