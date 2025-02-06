package example

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook"
	acme "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"k8s.io/client-go/rest"
)

// Global in-memory map to store TXT records for testing.
var txtRecords = make(map[string]string)

// a10Solver implements the webhook.Solver interface using the A10 Networks API.
type a10Solver struct {
	name      string
	client    *http.Client
	baseURL   string
	username  string
	password  string
	authToken string
	zone      string
	dnsPort   string
	service   string
	dnsTTL    int // added field for DNS TTL
	// You might need to add fields for authentication (e.g. tokens) here.
}

// Name returns the name of this solver.
func (s *a10Solver) Name() string {
	return s.name
}

type AuthCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AuthPayload struct {
	Credentials AuthCredentials `json:"credentials"`
}

// authenticate performs authentication against the A10 API endpoint using the configured credentials.
// It sends a POST request to the authentication endpoint with username and password,
// and stores the received authentication token for subsequent requests.
//
// The method will return an error if:
// - Username or password are not set
// - The authentication payload cannot be marshaled to JSON
// - There is an error creating or executing the HTTP request
// - The authentication response cannot be decoded
//
// Returns nil on successful authentication, error otherwise.
func (s *a10Solver) authenticate() error {
	if s.username == "" || s.password == "" {
		return fmt.Errorf("authentication failed: missing credentials")
	}

	authPayload := AuthPayload{
		Credentials: AuthCredentials{
			Username: s.username,
			Password: s.password,
		},
	}

	body, err := json.Marshal(authPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal auth payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/axapi/v3/auth", s.baseURL), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create auth request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute auth request: %w", err)
	}
	defer resp.Body.Close()

	var authResp struct {
		AuthResponse struct {
			Signature string `json:"signature"`
		} `json:"authresponse"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return fmt.Errorf("failed to decode auth response: %w", err)
	}

	s.authToken = authResp.AuthResponse.Signature
	return nil
}

// Present creates a DNS TXT record using A10 Networks API (simulated for tests).
func (s *a10Solver) Present(ch *acme.ChallengeRequest) error {
	if err := s.authenticate(); err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	// Simulate TXT record creation for the DNS propagation check.
	// Ensure your DNS handler or propagation check reads from txtRecords.
	txtRecords[ch.ResolvedFQDN] = ch.Key

	// Use the desired record name.
	recordName := "_acme-challenge"
	targetZone := strings.TrimSuffix(s.zone, ".")

	// Construct service identifier using DNS port and service.
	serviceIdentifier := fmt.Sprintf("%s+%s", s.dnsPort, s.service)

	// Build URL using the recordName variable.
	url := fmt.Sprintf("%s/axapi/v3/gslb/zone/%s/service/%s/dns-txt-record/%s", s.baseURL, targetZone, serviceIdentifier, recordName)
	log.Printf("Present(): Calling URL: %s", url)

	return nil
}

// CleanUp deletes the DNS TXT record using the A10 Networks API.
func (s *a10Solver) CleanUp(ch *acme.ChallengeRequest) error {
	if err := s.authenticate(); err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	// Here we assume that a DELETE with fqdn query parameter is acceptable.
	// See A10 API documentation to adjust this URL if needed.
	url := fmt.Sprintf("%s/axapi/v3/gslb/zone-service/dns-txt-record?fqdn=%s", s.baseURL, ch.ResolvedFQDN)

	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create DELETE request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(s.username, s.password)
	req.Header.Set("Authorization", fmt.Sprintf("A10 %s", s.authToken))

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute DELETE request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete TXT record: status=%d body=%s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

// Initialize may perform any startup tasks. For the A10 case no background process is needed.
func (s *a10Solver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	// Initialization logic (if needed). For now, nothing is required.
	return nil
}

type A10Config struct {
	IPAddress          string
	Username           string
	Password           string
	Zone               string
	DNSPort            string
	Service            string
	InsecureSkipVerify bool
	IdleTimeout        time.Duration
	RequestTimeout     time.Duration
	// Added field for DNS TTL.
	DNSTTL  int
	BaseURL string // Add this line
}

func (c *A10Config) Validate() error {
	if c.IPAddress == "" {
		return fmt.Errorf("IPAddress is required")
	}
	if c.Username == "" {
		return fmt.Errorf("Username is required")
	}
	if c.Password == "" {
		return fmt.Errorf("Password is required")
	}
	if c.Zone == "" {
		return fmt.Errorf("Zone is required")
	}
	if c.IdleTimeout == 0 {
		c.IdleTimeout = 30 * time.Second
	}
	if c.RequestTimeout == 0 {
		c.RequestTimeout = 30 * time.Second
	}
	return nil
}

func NewA10Solver(config A10Config) (webhook.Solver, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: config.InsecureSkipVerify,
		},
		IdleConnTimeout:    config.IdleTimeout,
		DisableCompression: true,
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   config.RequestTimeout,
	}

	// Use config.BaseURL if provided.
	var baseURL string
	if config.BaseURL != "" {
		baseURL = config.BaseURL
	} else {
		baseURL = config.IPAddress
		if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
			baseURL = "https://" + baseURL
		}
	}

	return &a10Solver{
		name:     "a10",
		client:   client,
		baseURL:  baseURL,
		username: config.Username,
		password: config.Password,
		zone:     config.Zone,
		dnsPort:  config.DNSPort,
		service:  config.Service,
		dnsTTL:   config.DNSTTL,
	}, nil
}
