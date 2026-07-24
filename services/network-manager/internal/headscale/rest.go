// This file implements Client, the real HTTP-backed Service (client.go)
// and PolicyPusher (policy.go) - see client.go's own package doc comment
// for the full architectural reasoning (why REST, wire shapes confirmed
// against Headscale's own generated swagger).
package headscale

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// maxResponseBodyBytes bounds every response this package reads - none of
// Headscale's REST responses this package calls (a single user/pre-auth-
// key/node, a node list, or the ACL policy document) plausibly approaches
// this size; generous headroom, not a value with any other significance,
// same reasoning as every other maxRequestBodyBytes-shaped constant in
// this codebase (e.g. internal/httpapi's own).
const maxResponseBodyBytes = 1 << 20 // 1 MiB

// Client is a REST-backed connection to Headscale's own HTTP API, reached
// through the reverse proxy deployments/docker/headscale/ fronts it with -
// see client.go's package doc comment for the full design and why this is
// the one deliberately-public-network call in the system. httpClient must
// already be configured with:
//   - Network-Manager's own bootstrapped mTLS client certificate
//     (organization=NetworkManager, PKI-F-02/NM-F-12) - presented to the
//     reverse proxy's `/api/v1/*` location, which requires and verifies it;
//     every other path the proxy serves (Headscale's own public
//     coordination endpoints, NM-F-14) never asks for one.
//   - Trust for the reverse proxy's OWN public-facing TLS server
//     certificate - a normal HTTPS certificate (self-signed dev-only in
//     this project's Compose stack, Let's Encrypt in production), NEVER
//     RAM-USB's internal Certificate-Authority: real Tailscale clients
//     (this system's own Users, via CL-F-04) must be able to trust this
//     same certificate too, and they have no reason to ever trust RAM-USB's
//     private internal CA.
//
// See cmd/network-manager/main.go's buildHeadscaleAPIClient for exactly
// how that *http.Client is assembled - this package makes no TLS decision
// of its own, the same separation of concerns pkg/pki/pkg/mtls already
// establish everywhere else in this codebase.
type Client struct {
	baseURL    string
	httpClient *http.Client
	apiKey     string
}

// NewClient returns a Client that sends every request to baseURL (e.g.
// "https://headscale.ram-usb.example:8080") via httpClient, authenticating
// with Headscale's own bearer API key (apiKey) on every call - Headscale's
// own httpAuthenticationMiddleware requires this regardless of transport
// or of the reverse proxy's own separate mTLS check (confirmed by reading
// hscontrol/app.go's createRouter this session: r.Route("/api", ...)
// wraps h.httpAuthenticationMiddleware around every /v1/* route) - so this
// package must still send it, exactly as the earlier gRPC-based version's
// tokenAuth PerRPCCredentials did.
func NewClient(baseURL string, httpClient *http.Client, apiKey string) *Client {
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: httpClient,
		apiKey:     apiKey,
	}
}

// do sends method/path (body JSON-marshaled if non-nil) and JSON-decodes a
// successful (2xx) response body into out (skipped if out is nil) - the
// one HTTP-transport helper every Service/PolicyPusher method below is
// built on.
func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("headscale: marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return fmt.Errorf("headscale: build request %s %s: %w", method, path, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("headscale: %s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
	if err != nil {
		return fmt.Errorf("headscale: %s %s: read response body: %w", method, path, err)
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("headscale: %s %s: status %d: %s", method, path, resp.StatusCode, string(respBody))
	}

	if out == nil {
		return nil
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("headscale: %s %s: decode response: %w", method, path, err)
	}
	return nil
}

// parseID converts one of Headscale's REST-API numeric-ID-as-string
// fields (user/pre-auth-key/node "id", confirmed via headscale.swagger.
// json: `"format": "uint64"` on a `"type": "string"` field - protobuf
// JSON's own well-known uint64 mapping) into a real Go uint64. An empty
// string (a field genuinely absent from a response, e.g. a node with no
// pre-auth key) maps to 0, the same "zero means absent" convention
// Node.PreAuthKeyID documents.
func parseID(s string) (uint64, error) {
	if s == "" {
		return 0, nil
	}
	id, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("headscale: parse id %q: %w", s, err)
	}
	return id, nil
}

// formatID is parseID's inverse - Headscale's REST API expects the same
// string-carrying-a-uint64 shape on the way in (e.g.
// CreatePreAuthKeyRequest.User) as it returns on the way out.
func formatID(id uint64) string {
	return strconv.FormatUint(id, 10)
}

// --- User (headscale.swagger.json's v1CreateUserRequest/Response) -----

type createUserRequest struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

type restUser struct {
	ID string `json:"id"`
}

type createUserResponse struct {
	User restUser `json:"user"`
}

// CreateUser implements Service.CreateUser via POST /api/v1/user.
func (c *Client) CreateUser(ctx context.Context, name, email string) (uint64, error) {
	var resp createUserResponse
	if err := c.do(ctx, http.MethodPost, "/api/v1/user", createUserRequest{Name: name, Email: email}, &resp); err != nil {
		return 0, err
	}
	return parseID(resp.User.ID)
}

// --- PreAuthKey (v1CreatePreAuthKeyRequest/Response) -------------------

type createPreAuthKeyRequest struct {
	User       string    `json:"user"`
	Reusable   bool      `json:"reusable"`
	Ephemeral  bool      `json:"ephemeral"`
	Expiration time.Time `json:"expiration"`
	ACLTags    []string  `json:"aclTags"`
}

type restPreAuthKey struct {
	ID  string `json:"id"`
	Key string `json:"key"`
}

type createPreAuthKeyResponse struct {
	PreAuthKey restPreAuthKey `json:"preAuthKey"`
}

// CreatePreAuthKey implements Service.CreatePreAuthKey via
// POST /api/v1/preauthkey. Reusable/Ephemeral are always false - NM-F-08's
// own business rule (a single registration, single use), not exposed to
// this method's caller.
func (c *Client) CreatePreAuthKey(ctx context.Context, userID uint64, expiration time.Time, aclTags []string) (string, uint64, error) {
	reqBody := createPreAuthKeyRequest{
		User:       formatID(userID),
		Reusable:   false,
		Ephemeral:  false,
		Expiration: expiration,
		ACLTags:    aclTags,
	}

	var resp createPreAuthKeyResponse
	if err := c.do(ctx, http.MethodPost, "/api/v1/preauthkey", reqBody, &resp); err != nil {
		return "", 0, err
	}

	keyID, err := parseID(resp.PreAuthKey.ID)
	if err != nil {
		return "", 0, err
	}
	return resp.PreAuthKey.Key, keyID, nil
}

// --- Node (v1ListNodesResponse/v1GetNodeResponse/v1Node,
//     HeadscaleServiceSetTagsBody/v1SetTagsResponse) --------------------

type restNode struct {
	ID         string          `json:"id"`
	Tags       []string        `json:"tags"`
	PreAuthKey *restPreAuthKey `json:"preAuthKey,omitempty"`
}

func (n restNode) toNode() (Node, error) {
	id, err := parseID(n.ID)
	if err != nil {
		return Node{}, err
	}

	node := Node{ID: id, Tags: n.Tags}
	if n.PreAuthKey != nil {
		keyID, err := parseID(n.PreAuthKey.ID)
		if err != nil {
			return Node{}, err
		}
		node.PreAuthKeyID = keyID
	}
	return node, nil
}

type listNodesResponse struct {
	Nodes []restNode `json:"nodes"`
}

// ListNodes implements Service.ListNodes via GET /api/v1/node (no "user"
// query parameter - see GrantStorageAccess's own doc comment for why this
// package never filters by user).
func (c *Client) ListNodes(ctx context.Context) ([]Node, error) {
	var resp listNodesResponse
	if err := c.do(ctx, http.MethodGet, "/api/v1/node", nil, &resp); err != nil {
		return nil, err
	}

	nodes := make([]Node, 0, len(resp.Nodes))
	for _, n := range resp.Nodes {
		node, err := n.toNode()
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, node)
	}
	return nodes, nil
}

type getNodeResponse struct {
	Node restNode `json:"node"`
}

// GetNode implements Service.GetNode via GET /api/v1/node/{nodeId}.
func (c *Client) GetNode(ctx context.Context, nodeID uint64) (Node, error) {
	var resp getNodeResponse
	path := "/api/v1/node/" + formatID(nodeID)
	if err := c.do(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return Node{}, err
	}
	return resp.Node.toNode()
}

type setTagsRequestBody struct {
	Tags []string `json:"tags"`
}

// SetTags implements Service.SetTags via POST /api/v1/node/{nodeId}/tags.
func (c *Client) SetTags(ctx context.Context, nodeID uint64, tags []string) error {
	path := "/api/v1/node/" + formatID(nodeID) + "/tags"
	return c.do(ctx, http.MethodPost, path, setTagsRequestBody{Tags: tags}, nil)
}

// --- Policy (v1SetPolicyRequest/Response, v1GetPolicyResponse) ---------

type setPolicyRequest struct {
	Policy string `json:"policy"`
}

// SetPolicy implements PolicyPusher.SetPolicy via PUT /api/v1/policy.
func (c *Client) SetPolicy(ctx context.Context, policy string) error {
	return c.do(ctx, http.MethodPut, "/api/v1/policy", setPolicyRequest{Policy: policy}, nil)
}

type getPolicyResponse struct {
	Policy string `json:"policy"`
}

// GetPolicy implements PolicyPusher.GetPolicy via GET /api/v1/policy.
func (c *Client) GetPolicy(ctx context.Context) (string, error) {
	var resp getPolicyResponse
	if err := c.do(ctx, http.MethodGet, "/api/v1/policy", nil, &resp); err != nil {
		return "", err
	}
	return resp.Policy, nil
}
