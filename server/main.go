package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/mark3labs/mcp-go/server"
	"github.com/mostlygeek/mcp-demo/oauth"
	"github.com/sirupsen/logrus"
)

var discoveryHost string
var discoveryURL string

// authMiddleware wraps an http.Handler with OAuth authentication
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logrus.WithFields(logrus.Fields{
			"method": r.Method,
			"path":   r.URL.Path,
			"remote": r.RemoteAddr,
		}).Debug("[AUTH] Incoming request")
		logrus.WithField("headers", r.Header).Debug("[AUTH] Request headers")

		authHeader := r.Header.Get("Authorization")

		logrus.WithField("auth_header", authHeader).Debug("[AUTH] Authorization header")

		token := oauth.ExtractBearerToken(authHeader)
		logrus.WithField("has_token", token != "").Debug("[AUTH] Extracted token")

		validator := oauth.NewValidator(discoveryURL)

		if token == "" {
			logrus.Debug("[AUTH] No token provided, fetching OpenID configuration")
			config, err := validator.FetchOpenIDConfiguration()
			if err == nil {
				authHeader := fmt.Sprintf(`Bearer realm="%s", authorization_uri="%s"`,
					config.Issuer, config.AuthorizationEndpoint)
				w.Header().Set("WWW-Authenticate", authHeader)
				logrus.WithField("header", authHeader).Debug("[AUTH] Set WWW-Authenticate header")
			} else {
				logrus.WithError(err).Error("[AUTH] Failed to fetch OpenID config")
			}

			logrus.Info("[AUTH] Authentication failed - No token provided")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized"))
			return
		}

		logrus.Debug("[AUTH] Validating access token via userinfo endpoint")
		userInfo, err := validator.ValidateAccessToken(token)
		if err != nil {
			logrus.WithError(err).Info("[AUTH] Token validation failed")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized"))
			return
		}

		logrus.WithFields(logrus.Fields{
			"user": userInfo.Name,
			"sub":  userInfo.Sub,
		}).Info("[AUTH] Token validation successful")
		// Token is valid, pass the request to the next handler
		next.ServeHTTP(w, r)
	})
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	logrus.WithFields(logrus.Fields{
		"method": r.Method,
		"path":   r.URL.Path,
		"remote": r.RemoteAddr,
	}).Debug("[PROTECTED] Request received")
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("You got through to a protected endpoint!"))
	logrus.Debug("[PROTECTED] Response sent successfully")
}

func configHandler(w http.ResponseWriter, r *http.Request) {
	logrus.WithFields(logrus.Fields{
		"method": r.Method,
		"path":   r.URL.Path,
		"remote": r.RemoteAddr,
	}).Debug("[CONFIG] Request received")

	validator := oauth.NewValidator(discoveryURL)
	logrus.WithField("url", discoveryURL).Debug("[CONFIG] Fetching OpenID configuration")

	config, err := validator.FetchOpenIDConfiguration()
	if err != nil {
		logrus.WithError(err).Error("[CONFIG] Error fetching OpenID configuration")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf("Failed to fetch OpenID configuration: %v", err)))
		return
	}

	logrus.WithField("issuer", config.Issuer).Info("[CONFIG] Successfully fetched OpenID config")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
	logrus.Debug("[CONFIG] Response sent successfully")
}

func userinfoHandler(w http.ResponseWriter, r *http.Request) {
	logrus.WithFields(logrus.Fields{
		"method": r.Method,
		"path":   r.URL.Path,
		"remote": r.RemoteAddr,
	}).Debug("[USERINFO] Request received")

	authHeader := r.Header.Get("Authorization")
	token := oauth.ExtractBearerToken(authHeader)

	if token == "" {
		logrus.Info("[USERINFO] No token provided")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Unauthorized: Missing bearer token"))
		return
	}

	validator := oauth.NewValidator(discoveryURL)
	logrus.Debug("[USERINFO] Fetching user info for token")

	userInfo, err := validator.FetchUserInfo(token)
	if err != nil {
		logrus.WithError(err).Info("[USERINFO] Error fetching user info")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(fmt.Sprintf("Failed to fetch user info: %v", err)))
		return
	}

	logrus.WithField("sub", userInfo.Sub).Info("[USERINFO] Successfully fetched user info")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userInfo)
	logrus.Debug("[USERINFO] Response sent successfully")
}

func oauthProtectedResourceHandler(w http.ResponseWriter, r *http.Request) {
	logrus.WithFields(logrus.Fields{
		"method": r.Method,
		"path":   r.URL.Path,
		"remote": r.RemoteAddr,
	}).Debug("[OAUTH-PROTECTED-RESOURCE] Request received")

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
	logrus.Debug("[OAUTH-PROTECTED-RESOURCE] Response sent successfully")
}

func main() {
	// Configure logging based on LOG_LEVEL environment variable
	logLevel := strings.ToLower(os.Getenv("LOG_LEVEL"))
	switch logLevel {
	case "debug":
		logrus.SetLevel(logrus.DebugLevel)
	case "error":
		logrus.SetLevel(logrus.ErrorLevel)
	case "info", "":
		logrus.SetLevel(logrus.InfoLevel)
	default:
		logrus.SetLevel(logrus.InfoLevel)
		logrus.WithField("LOG_LEVEL", logLevel).Warn("Unknown LOG_LEVEL, defaulting to info")
	}

	// Set formatter for cleaner output
	logrus.SetFormatter(&logrus.TextFormatter{
		TimestampFormat: "2006-01-02 15:04:05",
		FullTimestamp:   false,
	})

	flag.StringVar(&discoveryHost, "idp", "", "OIDC provider hostname (e.g., auth.example.com)")
	flag.Parse()

	if discoveryHost == "" {
		logrus.Fatal("Error: -idp flag is required\nUsage: mcp-resource-server -idp <hostname>")
	}

	discoveryURL = fmt.Sprintf("https://%s/.well-known/openid-configuration", discoveryHost)

	// Create the MCP server
	mcpServer := NewMCPServer()
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
		logrus.WithFields(logrus.Fields{
			"method": r.Method,
			"path":   r.URL.Path,
			"remote": r.RemoteAddr,
		}).Debug("[ROOT] Health check request")
		w.Write([]byte("OAuth Resource Server is running"))
		logrus.Debug("[ROOT] Health check response sent")
	})

	fmt.Println("========================================")
	fmt.Println("OAuth 2.0 Resource Server starting on :8080")
	fmt.Printf("  idp: %s\n", discoveryURL)
	fmt.Printf("  log level: %s\n", logrus.GetLevel().String())
	fmt.Println("========================================")
	fmt.Println("\nEndpoints:")
	fmt.Println("  GET /           - Health check")
	fmt.Println("  GET /config     - View OpenID configuration")
	fmt.Println("  GET /userinfo   - Get user info with Bearer token")
	fmt.Println("  GET /.well-known/oauth-protected-resource - OAuth protected resource metadata")
	fmt.Println("  POST /mcp       - MCP server endpoint (requires Bearer token)")
	fmt.Println("  GET /protected  - Protected endpoint (requires Bearer token)")

	logrus.Fatal(http.ListenAndServe("localhost:8080", nil))
}
