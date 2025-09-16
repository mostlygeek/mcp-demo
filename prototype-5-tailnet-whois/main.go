package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"

	"tailscale.com/tsnet"
)

func main() {
	var (
		hostname = flag.String("hostname", "app-cap-testing", "Hostname on tailnet")
		dir      = flag.String("dir", "data", "Directory to store Tailscale state")
		debug    = flag.Bool("debug", false, "Enable debug logging")
	)
	flag.Parse()

	ts := &tsnet.Server{
		Hostname: *hostname,
		Dir:      *dir,
	}

	if *debug {
		ts.Logf = log.Printf
	}

	st, err := ts.Up(context.Background())
	if err != nil {
		log.Fatal(err.Error())
	}

	lc, err := ts.LocalClient()
	if err != nil {
		log.Fatalf("error getting local client: %s", err.Error())
	}

	ln, err := ts.Listen("tcp", ":80")

	if err != nil {
		log.Fatalf("error listening: %s", err.Error())
	}

	// start a webserver and use lc.WhoIs to get the client info

	fmt.Printf("listening at http://%s\n", strings.TrimSuffix(st.Self.DNSName, "."))
	httpServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			whois, err := lc.WhoIs(context.Background(), r.RemoteAddr)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, "Error: %s\n", err.Error())
				return
			}

			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			output := strings.Builder{}
			output.WriteString("WHOIS INFORMATION\n")
			output.WriteString("-----------------\n")
			output.WriteString(fmt.Sprintf("RemoteAddr: %s\n", r.RemoteAddr))

			// build output from whois info

			// Output Node Name
			if whois.Node != nil {
				output.WriteString(fmt.Sprintf("Node Name: %s\n", whois.Node.Name))
			}

			// Output UserProfile - all fields
			if whois.UserProfile != nil {
				output.WriteString("\nUser Profile:\n")
				output.WriteString(fmt.Sprintf("  ID: %s\n", whois.UserProfile.ID))
				output.WriteString(fmt.Sprintf("  LoginName: %s\n", whois.UserProfile.LoginName))
				output.WriteString(fmt.Sprintf("  DisplayName: %s\n", whois.UserProfile.DisplayName))
				output.WriteString(fmt.Sprintf("  ProfilePicURL: %s\n", whois.UserProfile.ProfilePicURL))
			}

			// Output CapMap - each item
			if len(whois.CapMap) > 0 {
				output.WriteString("\nCapabilities:\n")
				for capability, values := range whois.CapMap {
					output.WriteString(fmt.Sprintf("  %s: %v\n", capability, values))
				}
			}

			w.Write([]byte(output.String()))
		}),
	}
	httpServer.Serve(ln)
}
