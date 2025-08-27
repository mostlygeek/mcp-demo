package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/mark3labs/mcp-go/server"
	"github.com/mostlygeek/mcp-demo/mcp"
	"github.com/mostlygeek/mcp-demo/oauth"
)

var discoveryHost string
var discoveryURL string

// authMiddleware wraps an http.Handler with OAuth authentication
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[AUTH] Request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		log.Printf("[AUTH] Headers: %v", r.Header)

		authHeader := r.Header.Get("Authorization")

		log.Printf("[AUTH] Authorization header: %s", authHeader)

		token := oauth.ExtractBearerToken(authHeader)
		log.Printf("[AUTH] Extracted token: %v", token != "")

		validator := oauth.NewValidator(discoveryURL)

		if token == "" {
			log.Printf("[AUTH] No token provided, fetching OpenID configuration")
			config, err := validator.FetchOpenIDConfiguration()
			if err == nil {
				authHeader := fmt.Sprintf(`Bearer realm="%s", authorization_uri="%s"`,
					config.Issuer, config.AuthorizationEndpoint)
				w.Header().Set("WWW-Authenticate", authHeader)
				log.Printf("[AUTH] Set WWW-Authenticate header: %s", authHeader)
			} else {
				log.Printf("[AUTH] Failed to fetch OpenID config: %v", err)
			}

			log.Printf("[AUTH] Returning 401 - No token")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized"))
			return
		}

		log.Printf("[AUTH] Validating access token via userinfo endpoint")
		userInfo, err := validator.ValidateAccessToken(token)
		if err != nil {
			log.Printf("[AUTH] Token validation failed: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized"))
			return
		}

		log.Printf("[AUTH] Token validation successful for user: %s (sub: %s)", userInfo.Name, userInfo.Sub)
		// Token is valid, pass the request to the next handler
		next.ServeHTTP(w, r)
	})
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("[PROTECTED] Request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("You got through to a protected endpoint!"))
	log.Printf("[PROTECTED] Response sent successfully")
}

func configHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("[CONFIG] Request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)

	validator := oauth.NewValidator(discoveryURL)
	log.Printf("[CONFIG] Fetching OpenID configuration from: %s", discoveryURL)

	config, err := validator.FetchOpenIDConfiguration()
	if err != nil {
		log.Printf("[CONFIG] Error fetching OpenID configuration: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf("Failed to fetch OpenID configuration: %v", err)))
		return
	}

	log.Printf("[CONFIG] Successfully fetched config - Issuer: %s", config.Issuer)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
	log.Printf("[CONFIG] Response sent successfully")
}

func userinfoHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("[USERINFO] Request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)

	authHeader := r.Header.Get("Authorization")
	token := oauth.ExtractBearerToken(authHeader)

	if token == "" {
		log.Printf("[USERINFO] No token provided")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Unauthorized: Missing bearer token"))
		return
	}

	validator := oauth.NewValidator(discoveryURL)
	log.Printf("[USERINFO] Fetching user info for token")

	userInfo, err := validator.FetchUserInfo(token)
	if err != nil {
		log.Printf("[USERINFO] Error fetching user info: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(fmt.Sprintf("Failed to fetch user info: %v", err)))
		return
	}

	log.Printf("[USERINFO] Successfully fetched user info for: %s", userInfo.Sub)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userInfo)
	log.Printf("[USERINFO] Response sent successfully")
}

func oauthProtectedResourceHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("[OAUTH-PROTECTED-RESOURCE] Request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)

	// OAuth Protected Resource Discovery metadata
	// This follows the OAuth 2.0 Protected Resource Metadata specification
	metadata := map[string]interface{}{
		"resource":                              "https://localhost:8080",
		"authorization_servers":                 []string{"https://" + discoveryHost},
		"bearer_methods_supported":              []string{"header"},
		"resource_documentation":                "https://github.com/mostlygeek/mcp-demo",
		"resource_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"mcp:read", "mcp:write"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metadata)
	log.Printf("[OAUTH-PROTECTED-RESOURCE] Response sent successfully")
}

func main() {
	flag.StringVar(&discoveryHost, "idp", "", "OIDC provider hostname (e.g., auth.example.com)")
	flag.Parse()

	if discoveryHost == "" {
		log.Fatal("Error: -idp flag is required\nUsage: mcp-resource-server -idp <hostname>")
	}

	discoveryURL = fmt.Sprintf("https://%s/.well-known/openid-configuration", discoveryHost)

	// Create the MCP server
	mcpServer := mcp.NewMCPServer()
	httpMCP := server.NewStreamableHTTPServer(mcpServer)

	// Wrap the MCP server with authentication middleware
	protectedMCPHandler := authMiddleware(httpMCP)

	// Register handlers
	http.HandleFunc("/config", configHandler)
	http.HandleFunc("/userinfo", userinfoHandler)
	http.HandleFunc("/.well-known/oauth-protected-resource", oauthProtectedResourceHandler)

	// protected endpoints
	http.Handle("/mcp", protectedMCPHandler)
	http.Handle("/protected", authMiddleware(http.HandlerFunc(protectedHandler)))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[ROOT] Request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		w.Write([]byte("OAuth Resource Server is running"))
		log.Printf("[ROOT] Health check response sent")
	})

	log.Println("========================================")
	log.Println("OAuth 2.0 Resource Server starting on :8080")
	log.Printf("Discovery URL: %s\n", discoveryURL)
	log.Println("\nDebug logging enabled for all HTTP handlers")
	log.Println("Watch for [AUTH], [CONFIG], [USERINFO], [PROTECTED], [ROOT] prefixes")
	log.Println("========================================")
	fmt.Println("\nEndpoints:")
	fmt.Println("  GET /           - Health check")
	fmt.Println("  GET /config     - View OpenID configuration")
	fmt.Println("  GET /userinfo   - Get user info with Bearer token")
	fmt.Println("  GET /.well-known/oauth-protected-resource - OAuth protected resource metadata")
	fmt.Println("  POST /mcp       - MCP server endpoint (requires Bearer token)")
	fmt.Println("  GET /protected  - Protected endpoint (requires Bearer token)")
	fmt.Println("\nExample usage:")
	fmt.Println("  # Get user info:")
	fmt.Println("  curl -H \"Authorization: Bearer <your-oauth-token>\" \\")
	fmt.Println("       http://localhost:8080/userinfo")
	fmt.Println("")
	fmt.Println("  # Access MCP endpoint:")
	fmt.Println("  curl -X POST -H \"Authorization: Bearer <your-oauth-token>\" \\")
	fmt.Println("       -H \"Content-Type: application/json\" \\")
	fmt.Println("       -d '{\"jsonrpc\":\"2.0\",\"method\":\"initialize\",\"params\":{},\"id\":1}' \\")
	fmt.Println("       http://localhost:8080/mcp")

	log.Fatal(http.ListenAndServe("localhost:8080", nil))
}
