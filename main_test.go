package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/joho/godotenv"
	"github.com/miekg/dns"

	acmetest "github.com/cert-manager/cert-manager/test/acme"
	"github.com/cert-manager/webhook-example/example"
)

// MockServer wraps httptest.Server so that we can refer to it as a MockServer.
type MockServer struct {
	*httptest.Server
}

// startMockA10APIServer creates a dummy HTTP server for the A10 API.
func startMockA10APIServer(t *testing.T) *MockServer {

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Mock server received request: %s %s", r.Method, r.URL)
		switch {
		case r.URL.Path == "/axapi/v3/auth":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			resp := map[string]interface{}{
				"authresponse": map[string]string{
					"signature": "dummy-token",
				},
			}
			_ = json.NewEncoder(w).Encode(resp)
		case r.URL.Path == fmt.Sprintf("/axapi/v3/gslb/zone/%s/service/%s/dns-txt-record/_acme-challenge",
			"gslb.irembo-test.org", fmt.Sprintf("%s+%s", os.Getenv("A10_DNS_PORT"), os.Getenv("A10_SERVICE"))):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
		}
	})
	ts := httptest.NewServer(handler)
	return &MockServer{ts}

}

func TestRunsSuite(t *testing.T) {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}

	// Create a mock A10 API server.
	mockServer := startMockA10APIServer(t)
	defer mockServer.Close()

	// Create config with values from environment; override BaseURL with mock server URL.
	config := example.A10Config{
		IPAddress:          os.Getenv("A10_IP_ADDRESS"),
		Username:           os.Getenv("A10_USERNAME"),
		Password:           os.Getenv("A10_PASSWORD"),
		Zone:               os.Getenv("A10_ZONE") + ".", // Add trailing dot
		DNSPort:            os.Getenv("A10_DNS_PORT"),
		Service:            os.Getenv("A10_SERVICE"),
		InsecureSkipVerify: true, // For testing purposes
		IdleTimeout:        30 * time.Second,
		RequestTimeout:     30 * time.Second,
		DNSTTL:             120,            // or parse from os.Getenv("A10_DNS_TTL")
		BaseURL:            mockServer.URL, // override the baseURL for tests
	}

	solver, err := example.NewA10Solver(config)
	if err != nil {
		t.Fatal(err)
	}

	// Start a DNS server to serve TXT records from example.txtRecords.
	dnsAddr := "127.0.0.1:5353"
	dnsServer := example.StartDNSServer(dnsAddr)
	defer dnsServer.Shutdown()

	// Custom DNS propagation check that queries our fake DNS server.
	customDNSPropagationCheck := func(ch *acme.ChallengeRequest) error {
		// Build a DNS query message.
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(ch.ResolvedFQDN), dns.TypeTXT)
		client := new(dns.Client)
		timeout := time.After(10 * time.Second)
		tick := time.Tick(500 * time.Millisecond)
		for {
			select {
			case <-timeout:
				return fmt.Errorf("DNS propagation timeout")
			case <-tick:
				r, _, err := client.Exchange(m, dnsAddr)
				if err == nil && len(r.Answer) > 0 {
					return nil
				}
			}
		}
	}

	fixture := acmetest.NewFixture(
		solver,
		acmetest.SetResolvedZone(config.Zone),
		acmetest.SetManifestPath("testdata/a10-solver"),
	)
	// (Optional) Run the solver's Present method and then check DNS propagation manually.
	// You would simulate a challenge request here. For example:
	challenge := &acme.ChallengeRequest{
		ResolvedFQDN: "_acme-challenge.gslb.irembo-test.org.",
		Key:          "dummy-key",
	}
	if err := solver.Present(challenge); err != nil {
		t.Fatalf("Present failed: %v", err)
	}
	if err := customDNSPropagationCheck(challenge); err != nil {
		t.Fatalf("DNS propagation check failed: %v", err)
	}
	// Continue with the rest of the fixture tests.
	fixture.RunBasic(t) // Changed from Run to RunBasic
}
