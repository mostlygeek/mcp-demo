# Check if .env file exists
ifneq (,$(wildcard .env))
    include .env
    export $(shell sed 's/=.*//' .env)
else
    $(error .env file not found. Copy .env.example to .env and set your values)
endif

# tsidp is its own tsnet node. keep it's hostname as mcp-demo-idp as that
# is expected by the server.
tsidp:
	TAILSCALE_USE_WIP_CODE=1 go run ./tsidp -hostname mcp-demo-idp

# example: make server TAILNET_NAME=ts03932 LOG_LEVEL=debug
server:
	LOG_LEVEL=$(LOG_LEVEL) go run ./server -idp mcp-demo-idp.$(TAILNET_NAME).ts.net

# zero click login since with tsidp we call the auth endpoint and the redirect
# endpoints directly.
client-zero-click:
	LOG_LEVEL=$(LOG_LEVEL) go run ./client

# use the standard browser login flow
client-browser-use:
	LOG_LEVEL=$(LOG_LEVEL) go run ./client -browserLogin=true

.PHONY: tsidp server client-zero-click client-browser-use