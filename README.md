# Project Structure
```sh
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
```

# Summary
* cmd/webhook.go: Bootstraps the webhook server using the cert-manager “webhook runtime” libraries.
* pkg/a10client/client.go: A10 API client logic:
  * authenticate (login/logout)
  * create TXT record
  * delete TXT record
* pkg/solver.go: Implements the DNS solver with methods Name(), Present(), CleanUp(), plus a config parsing function.
* pkg/apitypes.go (optional): Defines the custom config format that your solver expects from the user in their cert-manager # Issuer/ClusterIssuer.

# Flowchart Representation
```sh
                          ┌──────────────────────────────┐
                          │  User Requests Certificate   │
                          └──────────────▲──────────────┘
                                         │
                                         ▼
                          ┌──────────────────────────────┐
                          │  Cert-Manager Starts DNS-01  │
                          │    Validation Process        │
                          └──────────────┬──────────────┘
                                         │
                                         ▼
                          ┌──────────────────────────────┐
                          │  Calls A10 Webhook Server    │
                          ├──────────────────────────────┤
                          │  - Present(): Create TXT     │
                          │  - CleanUp(): Delete TXT     │
                          └──────────────┬──────────────┘
                                         │
                                         ▼
                          ┌──────────────────────────────┐
                          │  Webhook Reads Configuration │
                          │  - Fetch A10 API Details     │
                          │  - Get Credentials from K8s  │
                          └──────────────┬──────────────┘
                                         │
                                         ▼
                          ┌──────────────────────────────┐
                          │  A10Client Logs into A10 API │
                          ├──────────────────────────────┤
                          │  - Sends Authentication Req  │
                          │  - Receives Session Token    │
                          └──────────────┬──────────────┘
                                         │
                                         ▼
                          ┌──────────────────────────────┐
                          │  A10Client Creates TXT Record│
                          ├──────────────────────────────┤
                          │  - Sends POST to A10 API     │
                          │  - Stores TXT Record         │
                          └──────────────┬──────────────┘
                                         │
                                         ▼
                          ┌──────────────────────────────┐
                          │  Cert-Manager Polls DNS      │
                          │  - Let's Encrypt Validates   │
                          ├──────────────────────────────┤
                          │  Cert Issued if Successful   │
                          └──────────────┬──────────────┘
                                         │
                                         ▼
                          ┌──────────────────────────────┐
                          │  Webhook Calls CleanUp()     │
                          ├──────────────────────────────┤
                          │  - Deletes TXT Record        │
                          ├──────────────────────────────┤
                          │  A10 API Removes TXT         │
                          └──────────────────────────────┘
```

# Step-by-Step Breakdown
**1. Cert-Manager Calls the Webhook**

    Cert-manager requests the webhook to create a TXT record in A10 GSLB.
    It sends a request to the webhook with:
        * The FQDN (_acme-challenge.example.com)
        * The TXT value (ACME token)
        * The Issuer configuration
    
**2. Webhook Reads Configuration**

    The webhook extracts A10 API details from the Issuer configuration.
    It retrieves username and password from Kubernetes Secrets.

**3. Webhook Authenticates with A10**

    It sends a login request to the A10 API (/axapi/v3/auth).
    Receives an authentication token (SessionID).
    Uses this token in all future API calls.

**4. Webhook Creates TXT Record**

    Calls the A10 API to create a TXT record (/axapi/v3/gslb/zone/.../dns-txt-record/...).
    A10 GSLB stores the TXT record for validation.
   
**5. Let's Encrypt Validates the TXT Record**

    Cert-manager waits for Let's Encrypt to verify the TXT record.
    If successful, Let's Encrypt issues the certificate.

**6. Webhook Deletes the TXT Record**

    Cert-manager requests the webhook to delete the TXT record (CleanUp).
    The webhook calls A10 API to remove the TXT record.

# Key Components in the Code
**1. A10Solver Struct**

```go

type A10Solver struct {
    client *kubernetes.Clientset
}
```
Implements the cert-manager webhook Solver.
Calls A10 AXAPI to create/delete TXT records.

**2. Present(): Create TXT Record**
```go

func (s *A10Solver) Present(ch *cmacme.ChallengeRequest) error {
    cfg, err := loadConfig(ch.Config)
    username, password, err := s.getCreds(&cfg, ch.ResourceNamespace)
    
    client := NewA10Client(cfg.Host, username, password)
    if err := client.Login(); err != nil {
        return fmt.Errorf("failed to login to A10: %w", err)
    }

    recordName := ch.ResolvedFQDN // "_acme-challenge.example.com"
    tokenValue := ch.Key          // The TXT record content

    err = client.CreateTXTRecord(cfg.Zone, cfg.Service, recordName, tokenValue, cfg.TTL)
    return err
}
```

Calls Login() to authenticate with A10.
Sends a POST request to A10 API to create a TXT record.

**3. CleanUp(): Remove TXT Record**
```go
func (s *A10Solver) CleanUp(ch *cmacme.ChallengeRequest) error {
    cfg, err := loadConfig(ch.Config)
    username, password, err := s.getCreds(&cfg, ch.ResourceNamespace)

    client := NewA10Client(cfg.Host, username, password)
    if err := client.Login(); err != nil {
        return fmt.Errorf("failed to login to A10: %w", err)
    }

    recordName := ch.ResolvedFQDN
    err = client.DeleteTXTRecord(cfg.Zone, cfg.Service, recordName)
    return err
}
```
Calls Login() to authenticate with A10.
Sends a DELETE request to A10 API to remove the TXT record.

**4. A10 API Authentication**
```go
func (c *A10Client) Login() error {
    url := fmt.Sprintf("%s/axapi/v3/auth", c.Host)
    
    body := map[string]interface{}{
        "credentials": map[string]string{
            "username": c.Username,
            "password": c.Password,
        },
    }
    b, _ := json.Marshal(body)

    req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
    req.Header.Set("Content-Type", "application/json")

    resp, err := c.HttpClient.Do(req)
    defer resp.Body.Close()

    var respObj map[string]interface{}
    json.NewDecoder(resp.Body).Decode(&respObj)

    authResp, _ := respObj["authresponse"].(map[string]interface{})
    c.SessionID, _ = authResp["signature"].(string)

    return nil
}
```
Logs into A10 using username/password.
Receives a session token for further API requests.

**5. Creating a TXT Record**
```go
func (c *A10Client) CreateTXTRecord(zone, servicePortAndName, recordName, txtValue string, ttl int) error {
    url := fmt.Sprintf("%s/axapi/v3/gslb/zone/%s/service/%s/dns-txt-record/%s", c.Host, zone, servicePortAndName, recordName)
    
    payload := map[string]interface{}{
        "dns-txt-record": map[string]interface{}{
            "record-name": recordName,
            "txt-data":    txtValue,
            "ttl":         ttl,
        },
    }
    b, _ := json.Marshal(payload)

    req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
    req.Header.Set("Authorization", "A10 "+c.SessionID)

    resp, err := c.HttpClient.Do(req)
    defer resp.Body.Close()

    return err
}
```
Sends POST request to A10 API to create a TXT record.    y

# Deploying the A10 Webhook in Kubernetes
Now that we have the A10 Webhook implemented, let's deploy it in Kubernetes so that it integrates with cert-manager.

**🔹 Step 1: Prepare Kubernetes Resources**
We need to create the following Kubernetes resources:

*Namespace* (optional but recommended)
*Deployment* for the webhook server
*Service* to expose the webhook
*Webhook Configuration* for cert-manager
*RBAC* (Roles & Service Accounts) for access to Kubernetes secrets
*Secrets* to store A10 API credentials
*Issuer/ClusterIssuer* to configure cert-manager

**🔹 Step 2: Create Namespace**
Create a namespace for the webhook:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: cert-manager-webhook-a10
```  
Apply it:

```sh
kubectl apply -f namespace.yaml
```
**🔹 Step 3: Store A10 Credentials in a Kubernetes Secret**
The webhook retrieves A10 credentials from Kubernetes secrets.

```yaml

apiVersion: v1
kind: Secret
metadata:
  name: a10-credentials
  namespace: cert-manager-webhook-a10
type: Opaque
data:
  username: YWRtaW4=   # base64 encoded "admin"
  password: YTEw       # base64 encoded "a10"
```
Apply it:

```sh

kubectl apply -f secret.yaml
```

**🔹 Step 4: Create a Deployment for the Webhook**
The A10 webhook server will run in a Kubernetes Deployment.

```yaml

apiVersion: apps/v1
kind: Deployment
metadata:
  name: cert-manager-webhook-a10
  namespace: cert-manager-webhook-a10
spec:
  replicas: 1
  selector:
    matchLabels:
      app: cert-manager-webhook-a10
  template:
    metadata:
      labels:
        app: cert-manager-webhook-a10
    spec:
      containers:
        - name: webhook
          image: myrepo/a10-webhook:v1   # Replace with your built image
          args:
            - --tls-cert-file=/tls/tls.crt
            - --tls-private-key-file=/tls/tls.key
          ports:
            - containerPort: 443
          volumeMounts:
            - name: tls
              mountPath: /tls
              readOnly: true
      volumes:
        - name: tls
          secret:
            secretName: cert-manager-webhook-a10-tls
``
Apply it:

```sh
kubectl apply -f deployment.yaml
```

**🔹 Step 5: Expose Webhook via Kubernetes Service**
We expose the webhook internally using a Service.

```yaml
apiVersion: v1
kind: Service
metadata:
  name: cert-manager-webhook-a10
  namespace: cert-manager-webhook-a10
spec:
  ports:
    - port: 443
      targetPort: 443
  selector:
    app: cert-manager-webhook-a10
```
Apply it:

```sh
kubectl apply -f service.yaml
```

**🔹 Step 6: Create Webhook Configuration**
Cert-manager needs to communicate with our webhook.

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: cert-manager-webhook-a10
webhooks:
  - name: a10.acme.cert-manager.io
    admissionReviewVersions: ["v1"]
    sideEffects: None
    timeoutSeconds: 5
    clientConfig:
      service:
        name: cert-manager-webhook-a10
        namespace: cert-manager-webhook-a10
        path: "/validate"
      caBundle: Cg== # Replace with actual CA bundle
    rules:
      - apiGroups: ["acme.cert-manager.io"]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["challenges"]
```
Apply it:

```sh
kubectl apply -f webhook.yaml
```

**🔹 Step 7: Setup RBAC Permissions**
The webhook requires permissions to access Kubernetes secrets.
The provided YAML configuration defines a `ClusterRole` and a `ClusterRoleBinding` for the `cert-manager-webhook-a10` service in Kubernetes. 

The `ClusterRole` named `cert-manager-webhook-a10` specifies a set of permissions that are granted to the webhook. It includes two sets of rules. The first rule allows the webhook to `get` and `list` `configmaps` within the `kube-system` namespace, specifically targeting the `extension-apiserver-authentication` resource. This is necessary for the webhook to authenticate and interact with the Kubernetes API server. The second rule grants the webhook full access (`get`, `list`, `watch`, `create`, `update`, `delete`) to all resources within the `a10.webhook.acme` API group, which is likely related to the custom ACME DNS-01 challenge solver.

The `ClusterRoleBinding` named `cert-manager-webhook-a10` binds the `ClusterRole` to a specific `ServiceAccount` named `cert-manager-webhook-a10` in the `cert-manager` namespace. This binding ensures that the service account has the permissions defined in the `ClusterRole`, allowing the webhook to perform its necessary operations within the cluster.
```yaml

apiVersion: v1
kind: ServiceAccount
metadata:
  name: cert-manager-webhook-a10
  namespace: cert-manager-webhook-a10
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: cert-manager-webhook-a10
  namespace: cert-manager-webhook-a10
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: cert-manager-webhook-a10
  namespace: cert-manager-webhook-a10
subjects:
  - kind: ServiceAccount
    name: cert-manager-webhook-a10
    namespace: cert-manager-webhook-a10
roleRef:
  kind: Role
  name: cert-manager-webhook-a10
  apiGroup: rbac.authorization.k8s.io
```

Apply it:

```sh
kubectl apply -f rbac.yaml
```

**🔹 Step 8: Configure Cert-Manager ClusterIssuer**
The webhook is now running, so let’s configure cert-manager to use it.

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: a10-issuer
spec:
  acme:
    email: admin@example.com
    server: https://acme-staging-v02.api.letsencrypt.org/directory
    privateKeySecretRef:
      name: a10-issuer-account-key
    solvers:
      - dns01:
          webhook:
            groupName: a10.acme.cert-manager.io
            solverName: a10
            config:
              host: "https://a10.example.com"
              usernameSecretRef:
                name: a10-credentials
                key: username
              passwordSecretRef:
                name: a10-credentials
                key: password
              zone: "irembo.test"
              service: "53+dns"
              ttl: 120
```
Apply it:

```sh
kubectl apply -f issuer.yaml
```

**🔹 Step 9: Request a Certificate***
Finally, request an SSL certificate with cert-manager.

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: example-com
  namespace: default
spec:
  secretName: example-com-tls
  issuerRef:
    name: a10-issuer
    kind: ClusterIssuer
  dnsNames:
    - example.com
```    
Apply it:

```sh
kubectl apply -f certificate.yaml
```

# 🎯 Verifying the Deployment
Run these commands to check the deployment:

1️⃣ Check if the webhook is running:

```sh
kubectl get pods -n cert-manager-webhook-a10
```

2️⃣ Check the webhook logs for errors:

```sh
kubectl logs -l app=cert-manager-webhook-a10 -n cert-manager-webhook-a10
```

3️⃣ Check if cert-manager is requesting certificates:
```sh
kubectl describe certificate example-com
```

4️⃣ Check if DNS records are created in A10:

```sh
curl -k -X GET "https://a10.example.com/axapi/v3/gslb/zone/irembo.test/service/53+dns/dns-txt-record"
```
