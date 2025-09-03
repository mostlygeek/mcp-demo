# What is this

A local (stdin) mcpserver designed to work with an MCP compatible client like Claude Desktop to
query for information about your tailnet.

## Installation / Set up

### Step 1. Compile the binary

```
cd prototype-3
mkdir bin
go build -o bin/ts-api-mcpserver ./ts-api-mcpserver.go
```

### Step 2. Generate an Oauth client id and secret

1. Go to the web interface at [login.tailscale.com/admin/settings/oauth](https://login.tailscale.com/admin/settings/oauth). ([docs](https://tailscale.com/kb/1215/oauth-clients))
1. `Generate OAuth client...`
1. Choose All Read permission.

- **IMPORTANT** do not provide any WRITE permissions

1. Put the Client ID and Client Secret into Claude Desktop

### Step 3. Setup Claude Desktop

In `Claude Desktop > Settings > Developer > Edit Config`, this MCP server:

```
{
    "mcpServers": {
        "tailscale": {
            "command": "/path/to/prototype-3/bin/ts-api-mcpserver",
            "args": [],
            "env": {
                "TS_OAUTH_CLIENT_ID": "<your client id>",
                "TS_OAUTH_CLIENT_SECRET": "tskey-client-<some opaque string>"
            }
        }
    }
}
```

Things that must be set:

- `command` - full path to the golang binary you created in Step 1
- `TS_OAUTH_CLIENT_ID` - set to client ID from Tailscale web interface
- `TS_OAUTH_CLIENT_SECRET` - set to client secret from web interface

### Step 4. Start/Restart Claude Desktop

Use this prompt: `create a table of the devices and users in my tailnet`
