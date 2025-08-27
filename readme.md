# What is this?

This repo is an answer to these question:

As a developer:

- how do I build an MCP with Oauth authentication?
- what is the most secure by default, easiest way to get my MCP server launched?

These are the components:

- an MCP server with required OAuth access token for `/mcp`.
- a CLI MCP client specifically to test the server
- tsidp - tailscale IDP

## Goal

- demonstration of an MCP server/client oauth flow with tsidp
- very minimal implementation to make it as accessible for learning as possible
- simple setup

## Todo:

- ▢ client that
  - ✅ performs a MCP tool call
  - ✅ performs a MCP resource fetch
  - supports DCR (dynamic client registration)
- ▢ vendor in tsidp
  - ▢ add support for DCR
- ▢ mcp server
  - ✅ supports Oauth2 access token authentication
  - ▢ supports [RFC9728 (April 2025)](https://www.rfc-editor.org/rfc/rfc9728.html) - OAuth 2.0 Protected Resource Metadata
    - 🙃 beyond SOTA LLM knowledge cutoff date
- ▢ reorganize repo into `/client`, `/server`, `/tsidp` subdirectories (all `main` package)
- ▢ add a Makefile to make it easy to run (`make client`, `make server`, `make tsidp`)
- ▢ ...
