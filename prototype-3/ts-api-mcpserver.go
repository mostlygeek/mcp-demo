package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/oauth2/clientcredentials"
)

func main() {

	server := mcp.NewServer(&mcp.Implementation{Name: "tailscale-api", Version: "v0.0.1"}, nil)

	tsBridge := NewTailscale(os.Getenv("TS_OAUTH_CLIENT_ID"), os.Getenv("TS_OAUTH_CLIENT_SECRET"))
	tsBridge.AddToolsTo(server)

	transport := &mcp.LoggingTransport{Transport: &mcp.StdioTransport{}, Writer: os.Stderr}
	if err := server.Run(context.Background(), transport); err != nil {
		log.Printf("Server failed: %v", err)
	}
}

type TailscaleAPI struct {
	clientID     string
	clientSecret string
	config       *clientcredentials.Config
}

func NewTailscale(clientID, clientSecret string) *TailscaleAPI {
	return &TailscaleAPI{
		clientID:     clientID,
		clientSecret: clientSecret,
		config: &clientcredentials.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			TokenURL:     "https://api.tailscale.com/api/v2/oauth/token",
		},
	}
}

// AddToolsTo adds all the tools to the mcp server
func (t *TailscaleAPI) AddToolsTo(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{Name: "get_policy_file", Description: "Get the tailnet ACL policy file"}, t.GetPolicyFile)
	mcp.AddTool(server, &mcp.Tool{Name: "list_devices", Description: "List devices on tailnet"}, t.ListDevices)
	mcp.AddTool(server, &mcp.Tool{Name: "list_users", Description: "List users on tailnet"}, t.ListUsers)
	mcp.AddTool(server, &mcp.Tool{Name: "list_contacts", Description: "List contacts on tailnet"}, t.ListContacts)
}

// get makes a GET call to the Tailscale API
func (t *TailscaleAPI) get(ctx context.Context, path string) ([]byte, error) {
	client := t.config.Client(ctx)
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.tailscale.com/api/v2/"+path, nil)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error calling api: %w", err)
	}
	return io.ReadAll(resp.Body)
}

func (t *TailscaleAPI) GetPolicyFile(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
	body, err := t.get(ctx, "tailnet/-/acl")
	if err != nil {
		return nil, nil, err
	}

	var preformatted any
	if err := json.Unmarshal(body, &preformatted); err != nil {
		return nil, nil, fmt.Errorf("error unmarshaling JSON: %w", err)
	}
	// marshall with indent
	pretty, err := json.MarshalIndent(preformatted, "", "  ")
	if err != nil {
		return nil, nil, err
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: fmt.Sprintf("Policy file (json): \n%s\n", string(pretty))},
		},
	}, nil, nil
}

func (t *TailscaleAPI) ListUsers(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
	body, err := t.get(ctx, "tailnet/-/users")
	if err != nil {
		return nil, nil, err
	}

	var result struct {
		Users []struct {
			ID                 string `json:"id"`
			DisplayName        string `json:"displayName"`
			LoginName          string `json:"loginName"`
			ProfilePicUrl      string `json:"profilePicUrl"`
			Role               string `json:"role"`
			Status             string `json:"status"`
			DeviceCount        int    `json:"deviceCount"`
			Created            string `json:"created"`
			LastSeen           string `json:"lastSeen"`
			CurrentlyConnected bool   `json:"currentlyConnected"`
		} `json:"users"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, nil, fmt.Errorf("error unmarshaling JSON: %w", err)
	}

	// build the text content output
	var b strings.Builder
	b.WriteString(fmt.Sprintf("User count: %d\n\n", len(result.Users)))
	for _, user := range result.Users {
		b.WriteString(fmt.Sprintf("User: %s\n", user.ID))
		b.WriteString(fmt.Sprintf(" - Name: %s\n", user.DisplayName))
		b.WriteString(fmt.Sprintf(" - Login Name: %s\n", user.LoginName))
		b.WriteString(fmt.Sprintf(" - Role: %s\n", user.Role))
		b.WriteString(fmt.Sprintf(" - Status: %s\n", user.Status))
		b.WriteString(fmt.Sprintf(" - Device Count: %d\n", user.DeviceCount))
		b.WriteString(fmt.Sprintf(" - Created: %s\n", user.Created))
		b.WriteString(fmt.Sprintf(" - Last Seen: %s\n", user.LastSeen))
		b.WriteString(fmt.Sprintf(" - Currently Connected: %v\n", user.CurrentlyConnected))
		b.WriteString("\n")
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: b.String()},
		},
	}, nil, nil

}

func (t *TailscaleAPI) ListDevices(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
	body, err := t.get(ctx, "tailnet/-/devices")
	if err != nil {
		return nil, nil, err
	}

	// parse body into JSON and format it nicely
	// it is a json object like {"device: [ (device objects) ] }
	var result struct {
		Devices []struct {
			Addresses []string `json:"addresses"`
			Name      string   `json:"name"`
			ID        string   `json:"id"`
			Hostname  string   `json:"hostname"`
			OS        string   `json:"os"`
			User      string   `json:"user"`
			Tags      []string `json:"tags"`
		} `json:"devices"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, nil, fmt.Errorf("error unmarshaling JSON: %w", err)
	}

	// build the text content output
	var b strings.Builder
	for _, device := range result.Devices {
		b.WriteString(fmt.Sprintf("Device count: %d\n", len(result.Devices)))
		b.WriteString(fmt.Sprintf("Device: %s\n", device.Hostname))
		b.WriteString(fmt.Sprintf(" - ID: %s\n", device.ID))
		b.WriteString(fmt.Sprintf(" - Name: %s\n", device.Name))
		b.WriteString(fmt.Sprintf(" - Hostname: %s\n", device.Hostname))
		b.WriteString(fmt.Sprintf(" - OS: %s\n", device.OS))
		b.WriteString(fmt.Sprintf(" - User: %s\n", device.User))
		b.WriteString(fmt.Sprintf(" - Addresses: %v\n", strings.Join(device.Addresses, ", ")))
		b.WriteString(fmt.Sprintf(" - Tags: %v\n", strings.Join(device.Tags, ", ")))
		b.WriteString("\n")
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(b.String())},
		},
	}, nil, nil
}

func (t *TailscaleAPI) ListContacts(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
	body, err := t.get(ctx, "tailnet/-/contacts")
	if err != nil {
		return nil, nil, err
	}

	var result struct {
		Account struct {
			Email             string `json:"email"`
			FallbackEmail     string `json:"fallbackEmail"`
			NeedsVerification bool   `json:"needsVerification"`
		} `json:"account"`
		Support struct {
			Email             string `json:"email"`
			FallbackEmail     string `json:"fallbackEmail"`
			NeedsVerification bool   `json:"needsVerification"`
		} `json:"support"`
		Security struct {
			Email             string `json:"email"`
			FallbackEmail     string `json:"fallbackEmail"`
			NeedsVerification bool   `json:"needsVerification"`
		} `json:"security"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, nil, fmt.Errorf("error unmarshaling JSON: %w", err)
	}

	// build the text content output
	var b strings.Builder
	b.WriteString("Tailnet Contacts:\n\n")

	b.WriteString("Account Contact:\n")
	b.WriteString(fmt.Sprintf(" - Email: %s\n", result.Account.Email))
	b.WriteString(fmt.Sprintf(" - Fallback Email: %s\n", result.Account.FallbackEmail))
	b.WriteString(fmt.Sprintf(" - Needs Verification: %v\n", result.Account.NeedsVerification))
	b.WriteString("\n")

	b.WriteString("Support Contact:\n")
	b.WriteString(fmt.Sprintf(" - Email: %s\n", result.Support.Email))
	b.WriteString(fmt.Sprintf(" - Fallback Email: %s\n", result.Support.FallbackEmail))
	b.WriteString(fmt.Sprintf(" - Needs Verification: %v\n", result.Support.NeedsVerification))
	b.WriteString("\n")

	b.WriteString("Security Contact:\n")
	b.WriteString(fmt.Sprintf(" - Email: %s\n", result.Security.Email))
	b.WriteString(fmt.Sprintf(" - Fallback Email: %s\n", result.Security.FallbackEmail))
	b.WriteString(fmt.Sprintf(" - Needs Verification: %v\n", result.Security.NeedsVerification))

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: b.String()},
		},
	}, nil, nil
}
