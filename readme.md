# What is this?

This repo is an exploration of what the developer experience could be like building MCP servers on a tailnet. tsidp provides OAuth2 access tokens and user information about the tailescale authenticated user.

Demonstrated is a zero-click authentication flow where the client goes through these steps:

1. client makes request to server
2. server returns 401 Unauthorized with a `WWW-Authenticate` that redirects the clien to tsidp
3. client does a "zero-click" flow, as accessing tsidp on the tailnet does not require a client id or secret.
4. After successful authentication, the client makes an MCP tool and resource call.

## Running it:

1. copy the `.env.example` to `.env` and customize for your environment
2. run `make` pull in dependencies
3. run `make tsidp` to start the identity server. follow auth instructions.
4. in another terminal, run `make server`
5. finally, in another terminal, run `make client`
6. observe the output

## Goal

- demonstration of an MCP server/client oauth flow with tsidp
- very minimal implementation to make it as accessible for learning as possible
- simple setup

## Todo:

- ✅ mcp server
  - ✅ supports Oauth2 access token authentication
  - ✅ supports [RFC9728 (April 2025)](https://www.rfc-editor.org/rfc/rfc9728.html) - OAuth 2.0 Protected Resource Metadata
    - 🙃 beyond SOTA LLM knowledge cutoff date
  - ✅ merge the oauth/ and mcp/ packages into the server
  - ✅ accept `-listen` on cli, default to `localhost:8080`
  - ✅ change mcp resource to return user info
- ▢ client that
  - ✅ performs a MCP tool call
  - ✅ performs a MCP resource fetch
  - ✅ use mcp resource call to get user info
  - ▢ accept `-mcpURL` flag, default to `http://localhost:8080/mcp`
  - ▢ accept `-callbackURL` flag, default to `http://localhost:8085/oauth/callback`,
  - ▢ supports DCR (dynamic client registration)
  - ✅ change default flow to "zero click"
  - ✅ add a `-browserLogin` flag to use the browser login flow
- ▢ tsidp
  - ✅ vendor in tsidp
  - ▢ add support for DCR
- ✅ reorganize repo into `/client`, `/server`, `/tsidp` subdirectories (all `main` package)
- ✅ add a Makefile to make it easy to run (`make client`, `make server`, `make tsidp`)
- ▢ ...
