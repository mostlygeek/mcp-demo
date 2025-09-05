package main

// ported from: https://raw.githubusercontent.com/mark3labs/mcp-go/refs/heads/main/examples/oauth_client/main.go

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
	log "github.com/sirupsen/logrus"
)

const (
	// Replace with your MCP server URL
	serverURL = "http://localhost:8080/mcp"
	// Use a localhost redirect URI for this example
	redirectURI = "http://localhost:8085/oauth/callback"
)

var browserLogin bool

func main() {
	// Parse command line flags
	flag.BoolVar(&browserLogin, "browserLogin", false, "Use browser-based login instead of zero-click authentication")
	flag.Parse()

	// Configure logging based on LOG_LEVEL environment variable
	logLevel := strings.ToLower(os.Getenv("LOG_LEVEL"))
	switch logLevel {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	default:
		log.SetLevel(log.InfoLevel) // Default to info level
	}

	log.Debug("Starting MCP OAuth client")

	// Create a token store to persist tokens
	tokenStore := client.NewMemoryTokenStore()

	// Create OAuth configuration
	log.Debug("Creating OAuth configuration")
	oauthConfig := client.OAuthConfig{
		// Client ID can be empty if using dynamic registration

		// NOTE: tsidp only uses these when it is operating in funnel mode.
		// Within the tailnet these are effectively ignored. So they can
		// be blank when sent to tsidp.
		//
		// when running in funnel mode, use dynamic client registration or
		// provide these values. See tsidp.go :: allowRelyingParty(...)
		ClientID:     os.Getenv("MCP_CLIENT_ID"),
		ClientSecret: os.Getenv("MCP_CLIENT_SECRET"),

		RedirectURI: redirectURI,
		Scopes:      []string{"email", "profile"},
		TokenStore:  tokenStore,
		PKCEEnabled: true, // Enable PKCE for public clients
	}

	// Create the client with OAuth support
	log.Debug("Creating OAuth streamable HTTP client")
	c, err := client.NewOAuthStreamableHttpClient(serverURL, oauthConfig)
	if err != nil {
		log.WithError(err).Error("Failed to create client")
		os.Exit(1)
	}

	// Start the client
	if err := c.Start(context.Background()); err != nil {
		log.WithError(err).Info("Client.Start() failed! Unexpected")
		os.Exit(1)
	} else {
		log.Info("✅ Client.Start() Successful")
	}

	defer func() {
		log.Debug("Closing client connection")
		c.Close()
	}()

	mcpInitRequest := mcp.InitializeRequest{
		Params: struct {
			ProtocolVersion string                 `json:"protocolVersion"`
			Capabilities    mcp.ClientCapabilities `json:"capabilities"`
			ClientInfo      mcp.Implementation     `json:"clientInfo"`
		}{
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
			ClientInfo: mcp.Implementation{
				Name:    "mcp-go-oauth-example",
				Version: "0.1.0",
			},
		},
	}

	// Try to initialize the client ... it will fail and trigger the log in flow
	// TBD: what is in c.Initialize() that causes this to fail and expect token?
	_, err = c.Initialize(context.Background(), mcpInitRequest)
	if err != nil {
		log.Info("🛑 Client.Initialize() failed (expected), token missing at this point. Running maybeAuthorize() again.")

		// this maybeAuthorize and c.Initialize does the oauth flow
		maybeAuthorize(err)

		_, err := c.Initialize(context.Background(), mcpInitRequest)

		if err != nil {
			log.WithError(err).Error("Failed to initialize client after authorization")
			os.Exit(1)
		} else {
			// this is hit after the token is is obtained
			log.Info("✅ Client initialized after authorization")
		}
	} else {
		log.Info("Client.Initialize passed (UNEXPECTED), requires auth")
		os.Exit(1)
	}

	tools, err := c.ListTools(context.Background(), mcp.ListToolsRequest{})
	if err != nil {
		log.WithError(err).Error("Failed to list tools")
		os.Exit(1)
	} else {
		log.Info("✅ Tools listed successfully")
	}
	if len(tools.Tools) > 0 {
		log.Info("Available tools:")
		for _, tool := range tools.Tools {
			log.Infof("  - %s: %s\n", tool.Name, tool.Description)
		}
	}

	// call the sum tool with parameters

	// make x, y random numbers
	x := rand.Intn(100)
	y := rand.Intn(100)
	log.Infof("Calling sum tool with x=%d, y=%d", x, y)
	toolResult, err := c.CallTool(context.Background(), mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "sum",
			Arguments: map[string]any{
				"x": x,
				"y": y,
			},
		},
	})
	if err != nil || toolResult.IsError {
		log.WithError(err).Error("Failed to call tool")
		os.Exit(1)
	} else {
		log.Info("✅ Tool called successfully")
		if len(toolResult.Content) > 0 {
			if textContent, ok := toolResult.Content[0].(mcp.TextContent); ok {
				log.Infof("  - result: '%s'\n", textContent.Text)
			}
		}
	}

	resources, err := c.ListResources(context.Background(), mcp.ListResourcesRequest{})
	if err != nil {
		log.Errorf("Failed to list resources: %v", err)
	} else {
		log.Info("✅ Resources listed successfully")
		if len(resources.Resources) > 0 {
			log.Info("Available resources:")
			for _, resource := range resources.Resources {
				log.Infof("  - %s: %s\n", resource.URI, resource.Name)
				contents, err := c.ReadResource(context.Background(), mcp.ReadResourceRequest{
					Params: mcp.ReadResourceParams{
						URI: resource.URI,
					},
				})
				if err != nil {
					log.WithError(err).Error("Failed to read resource")
				} else {
					log.Info("✅ Resource contents retrieved:")
					if len(contents.Contents) > 0 {
						if textContent, ok := contents.Contents[0].(mcp.TextResourceContents); ok {
							fmt.Println(textContent.Text)
						}
					}
				}
			}
		}
	}

}

func maybeAuthorize(err error) {
	log.Debug("🔐 maybeAuthorize() - Enter")
	defer func() {
		log.Debug("🔓 maybeAuthorize() - Exit")
	}()
	// Check if we need OAuth authorization
	if client.IsOAuthAuthorizationRequiredError(err) {
		log.Info("✅ OAuth authorization required, starting flow")

		// Get the OAuth handler from the error
		oauthHandler := client.GetOAuthHandler(err)

		// Start a local server to handle the OAuth callback
		callbackChan := make(chan map[string]string)
		server := startCallbackServer(callbackChan)
		defer server.Close()

		// Generate PKCE code verifier and challenge
		codeVerifier, err := client.GenerateCodeVerifier()
		if err != nil {
			log.WithError(err).Error("Failed to generate code verifier")
			os.Exit(1)
		}
		codeChallenge := client.GenerateCodeChallenge(codeVerifier)

		// Generate state parameter
		state, err := client.GenerateState()
		if err != nil {
			log.WithError(err).Error("Failed to generate state")
			os.Exit(1)
		}

		// BEN: commented out client registration since we're using a pre-registered client
		// err = oauthHandler.RegisterClient(context.Background(), "mcp-go-oauth-example")
		// if err != nil {
		// 	log.Fatalf("Failed to register client: %v", err)
		// }

		// Get the authorization URL ...

		log.Debug("👀 Discoverying authorization endpoint and generating a URL for it ...")
		authURL, err := oauthHandler.GetAuthorizationURL(context.Background(), state, codeChallenge)
		if err != nil {
			log.WithError(err).Error("Failed to discover authorization URL")
			os.Exit(1)
		} else {
			log.Info("✅ Authorization URL obtained")
			log.Debugf("auth url: %s", authURL)
		}

		// Choose authentication method based on flag
		if browserLogin {
			// Open the browser to the authorization URL .. then tsidp will redirect to our callback url: localhost:8085/oauth/callback
			log.WithField("url", authURL).Info("Opening browser to authorization URL")
			openBrowser(authURL)
		} else {
			// Use zero-click authentication
			err := zeroClick(authURL, callbackChan)
			if err != nil {
				log.WithError(err).Warn("Zero-click authorization failed, falling back to browser")
				openBrowser(authURL)
			} else {
				log.Info("✅ Zero-click authorization initiated")
			}
		}

		// Wait for the callback
		log.Debug("🕦 Waiting for authorization callback on callbackChan")
		params := <-callbackChan
		log.Debug("⬅️ Received callback parameters")

		// Verify state parameter
		if params["state"] != state {
			log.WithFields(log.Fields{
				"expected": state,
				"got":      params["state"],
			}).Error("State mismatch in OAuth callback")
			os.Exit(1)
		}

		// Exchange the authorization code for a token
		code := params["code"]
		if code == "" {
			log.Error("No authorization code received")
			os.Exit(1)
		}

		log.Debug("➡️ Exchanging authorization code for token")
		err = oauthHandler.ProcessAuthorizationResponse(context.Background(), code, state, codeVerifier)
		if err != nil {
			log.WithError(err).Error("Failed to process authorization response")
			os.Exit(1)
		} else {
			log.Info("✅ Authorization Token Obtained")
		}
	} else {
		log.Debug("Authorization not required for this error")
	}
}

// startCallbackServer starts a local HTTP server to handle the OAuth callback
func startCallbackServer(callbackChan chan<- map[string]string) *http.Server {
	server := &http.Server{
		Addr: "localhost:8085",
	}

	http.HandleFunc("/oauth/callback", func(w http.ResponseWriter, r *http.Request) {
		// Extract query parameters
		params := make(map[string]string)
		for key, values := range r.URL.Query() {
			if len(values) > 0 {
				params[key] = values[0]
			}
		}

		// Send parameters to the channel
		callbackChan <- params

		// Respond to the user
		w.Header().Set("Content-Type", "text/html")
		_, err := w.Write([]byte(`
			<html>
				<body>
					<h1>Authorization Successful</h1>
					<p>You can now close this window and return to the application.</p>
					<p>This window will close automatically in <span id="countdown">3</span> seconds.</p>
					<button onclick="closeWindow()">Close Now</button>
					<script>
					let seconds = 3;
					const countdownElement = document.getElementById('countdown');

					const countdown = setInterval(() => {
						seconds--;
						countdownElement.textContent = seconds;

						if (seconds <= 0) {
							clearInterval(countdown);
							window.close();
						}
					}, 1000);

					function closeWindow() {
						window.close();
					}
					</script>
				</body>
			</html>
		`))
		if err != nil {
			log.WithError(err).Error("Error writing OAuth callback response")
		}
	})

	go func() {
		log.Debug("🔄 Starting http handler for /oauth/callback ")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.WithError(err).Error("HTTP server error")
		}
	}()

	return server
}

// zeroClick performs the authorization request directly without opening a browser
// It makes the HTTP request and extracts the callback parameters
func zeroClick(authURL string, callbackChan chan<- map[string]string) error {
	log.Debug("Performing zero-click authorization")

	// Create a custom HTTP client that doesn't follow redirects
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Stop following redirects
			return http.ErrUseLastResponse
		},
	}

	// Make the HTTP request
	resp, err := client.Get(authURL)
	if err != nil {
		return fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	log.WithField("status", resp.StatusCode).Debug("Recieved /authorize/... response")

	// Check if the response is a redirect to the callback URL
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		log.WithField("location", location).Debug("Following redirect ...")

		if location != "" && strings.HasPrefix(location, redirectURI) {
			// Parse the callback URL to extract parameters
			callbackURL, err := parseURL(location)
			if err != nil {
				return fmt.Errorf("failed to parse callback URL: %w", err)
			}

			// Extract query parameters
			params := make(map[string]string)
			for key, values := range callbackURL.Query() {
				if len(values) > 0 {
					params[key] = values[0]
				}
			}

			//log.WithField("params", params).Debug("Extracted parameters")

			// Make an async request to the callback server which will send to callbackChan
			// This must be async to avoid blocking while the main code waits on the channel
			go func() {
				callbackResp, err := http.Get(location)
				if err != nil {
					log.WithError(err).Error("Failed to hit callback server")
					// If the callback fails, send an error state to unblock
					callbackChan <- map[string]string{"error": err.Error()}
				} else {
					callbackResp.Body.Close()
				}
			}()
			return nil
		}
	}

	// If not a redirect or unexpected response, return error
	return fmt.Errorf("unexpected response: status %d", resp.StatusCode)
}

// parseURL is a helper function to parse URL strings
func parseURL(urlStr string) (*url.URL, error) {
	return url.Parse(urlStr)
}

// openBrowser opens the default browser to the specified URL
func openBrowser(url string) {
	var err error

	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}

	if err != nil {
		log.WithError(err).Debug("Failed to open browser automatically")
		log.WithField("url", url).Info("Please open the following URL in your browser")
	}
}
