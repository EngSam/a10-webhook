a10-solver/
├── cmd/
│   └── webhook.go          # main entry point for the webhook server
├── pkg/
│   ├── a10client/
│   │   └── client.go       # handles A10 AXAPI calls (create/delete TXT record, session mgmt)
│   ├── solver.go           # cert-manager solver implementation (Present(), CleanUp())
│   └── apitypes.go         # define configuration struct 
├── Dockerfile
├── go.mod
├── go.sum
└── main.go                 # main entry 


# cmd/webhook.go: Bootstraps the webhook server using the cert-manager “webhook runtime” libraries.
# pkg/a10client/client.go: A10 API client logic:
# authenticate (login/logout)
# create TXT record
# delete TXT record
# pkg/solver.go: Implements the DNS solver with methods Name(), Present(), CleanUp(), plus a config parsing function.
# pkg/apitypes.go (optional): Defines the custom config format that your solver expects from the user in their cert-manager # Issuer/ClusterIssuer.