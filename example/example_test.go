package example

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook"
	acme "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type Solver interface {
	webhook.Solver
	Name() string
}

// setupSolver creates a new solver instance for testing
func setupSolver(t *testing.T) (Solver, chan struct{}) {
	// Load environment variables
	if err := godotenv.Load("../.env"); err != nil {
		t.Fatalf("Error loading .env file: %v", err)
	}

	// Verify required environment variables
	required := []string{
		"A10_IP_ADDRESS",
		"A10_USERNAME",
		"A10_PASSWORD",
		"A10_ZONE",
	}

	for _, env := range required {
		if os.Getenv(env) == "" {
			t.Fatalf("Required environment variable %s is not set", env)
		}
	}

	done := make(chan struct{})
	config := A10Config{
		IPAddress:          os.Getenv("A10_IP_ADDRESS"),
		Username:           os.Getenv("A10_USERNAME"),
		Password:           os.Getenv("A10_PASSWORD"),
		Zone:               os.Getenv("A10_ZONE"),
		DNSPort:            os.Getenv("A10_DNS_PORT"),
		Service:            os.Getenv("A10_SERVICE"),
		InsecureSkipVerify: true,
		IdleTimeout:        30 * time.Second,
		RequestTimeout:     30 * time.Second,
	}

	solver, err := NewA10Solver(config)
	require.NoError(t, err, "Failed to create solver")

	err = solver.Initialize(nil, done)
	require.NoError(t, err, "Failed to initialize solver")

	return solver, done
}

// setupTestServer creates a test HTTP server for mocking A10 API responses
func setupTestServer() (*httptest.Server, *a10Solver) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/axapi/v3/auth":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"authresponse": map[string]string{
					"signature": "test-token",
				},
			})
		}
	}))

	solver := &a10Solver{
		client:   server.Client(),
		baseURL:  server.URL,
		username: "admin",
		password: "a10",
		zone:     "gslb.irembo-test.org",
	}

	return server, solver
}

func TestA10Solver_Name(t *testing.T) {
	solver, done := setupSolver(t)
	defer close(done)

	assert.Equal(t, "a10", solver.Name(), "Solver name should be 'a10'")
}

func TestA10Solver_Initialize(t *testing.T) {
	solver := &a10Solver{}
	done := make(chan struct{})
	defer close(done)

	err := solver.Initialize(nil, done)
	assert.NoError(t, err, "Initialize should not return an error")
}

func TestA10Solver_Present(t *testing.T) {
	server, solver := setupTestServer()
	defer server.Close()

	testCases := []struct {
		name    string
		fqdn    string
		key     string
		wantErr bool
	}{
		{
			name:    "valid request",
			fqdn:    "gslb.irembo-test.org.",
			key:     "test-key",
			wantErr: false,
		},
		// Add more test cases as needed
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ch := &acme.ChallengeRequest{
				ResolvedFQDN: tc.fqdn,
				Key:          tc.key,
			}

			err := solver.Present(ch)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestA10Solver_CleanUp(t *testing.T) {
	server, solver := setupTestServer()
	defer server.Close()

	testCases := []struct {
		name    string
		fqdn    string
		wantErr bool
	}{
		{
			name:    "valid cleanup",
			fqdn:    "test.example.com",
			wantErr: false,
		},
		// Add more test cases as needed
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ch := &acme.ChallengeRequest{
				ResolvedFQDN: tc.fqdn,
			}

			err := solver.CleanUp(ch)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestA10Config_Validate(t *testing.T) {
	testCases := []struct {
		name    string
		config  A10Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: A10Config{
				IPAddress: "10.0.0.1",
				Username:  "admin",
				Password:  "password",
				Zone:      "example.com",
			},
			wantErr: false,
		},
		{
			name: "missing IP",
			config: A10Config{
				Username: "admin",
				Password: "password",
				Zone:     "example.com",
			},
			wantErr: true,
		},
		// Add more test cases as needed
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.config.Validate()
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestA10Solver_Authenticate(t *testing.T) {
	server, solver := setupTestServer()
	defer server.Close()

	err := solver.authenticate()
	require.NoError(t, err)
	assert.Equal(t, "test-token", solver.authToken)
}
