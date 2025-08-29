## Notes about funnel-tsidp

- tsidp's `/authorize` endpoint must be called on tailnet.
  - It will response with a 401 Unauthorized otherwise.
  - all other endpoints `/token`, `/userinfo`, `/clients` can be called over Funnel
- the mcp resource server (`mcpserver`) can be run anywhere
- the mcp client (`mcpclient`) has to be run in the (any?) tailnet as it will
- the `make tsidp-funnel`, the `/token` endpoint can be called by

### The Setup

1. **Funnel clients** are OIDC clients (like external web apps) that live **outside the tailnet** on the public internet
2. These clients are registered with the IDP and stored with a client ID, secret, and redirect URI
3. The IDP itself can be exposed via Tailscale Funnel to be accessible from the internet

### The Authorization Flow

When an external app wants to authenticate a Tailscale user:

1. **External app redirects user to the IDP's authorize endpoint**

   - The external app (on the public internet) redirects the user's browser to: `https://mcp-demo-idp-funnel.<tsname>.ts.net/authorize/funnel?client_id=xxx&redirect_uri=https://externalapp.com/callback`

2. **User's browser makes the request**

   - Even though the IDP is accessible via funnel, the user making this request is **inside the tailnet** (they're a Tailscale user trying to log in)
   - So this isn't a funnel request from the IDP's perspective - it's a regular tailnet request **!IMPORTANT!**
   - The path `/authorize/funnel` tells the IDP "this is for a funnel client"

3. **IDP validates and redirects back**

   - The IDP checks that the client_id matches a registered funnel client
   - Creates an auth code and redirects the user back to the external app with the code

4. **External app exchanges code for token**
   - Now the external app (via funnel) calls `/token` with the code and its client credentials
   - This IS a funnel request, and the `/token` endpoint allows it by validating the client credentials

### The Key Insight

The `/authorize/funnel` endpoint is accessed by **Tailscale users** (not via funnel) who are authorizing **external apps** (that will later access via funnel with calls to `/token`). It's the user-facing part of the OAuth flow, while the `/token` endpoint is the machine-to-machine part that actually uses funnel.
