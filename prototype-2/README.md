# What is this

- For testing with an mcp client/server that only knows OAuth 2.1 and is entirely decoupled from tsidp.
- Good for testing OAuth flows are working with an Oauth IDP authorization server (tsidp in this case)

# How to use

## Running with Make

1. in root, copy `.env.example` to `.env`
1. `make tsidp` - to start the server
1. `make server` - in a separate terminal
1. `npx @modelcontextprotocol/inspector` - in another terminal window. It will open your browser
1. MCP Inspector Settings:
   - Transport type: Streamable HTTP
   - URL: http://localhost:9933
1. Click Connect

## Troubleshooting Notes

- MCP Inspector
  - will do CORS Preflight requests. IDP server is required to support OPTIONS and 204 responses.

## Running with Docker

### Build the Docker image

**Note:** The Docker build must be run from the project root directory (mcp-demo) because it needs access to go.mod and go.sum files.

```bash
# From the mcp-demo root directory
docker build -f prototype-2/server/Dockerfile -t mcp-server .
```

### Run the container

```bash
docker run -p 9933:9933 mcp-server
```

The MCP server will be available at `http://localhost:9933`. You can then use the MCP Inspector as described above to connect to it.
