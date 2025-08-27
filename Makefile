TAILNET_NAME = "your-tailnet-name"
LOG_LEVEL = "info"

tsidp:
	TAILSCALE_USE_WIP_CODE=1 go run ./tsidp -hostname idplocal

# example: make server TAILNET_NAME=ts03932 LOG_LEVEL=debug
server:
	LOG_LEVEL=$(LOG_LEVEL) go run ./server -idp idplocal.$(TAILNET_NAME).ts.net

client:
	LOG_LEVEL=$(LOG_LEVEL) go run ./client

.PHONY: tsidp server client
