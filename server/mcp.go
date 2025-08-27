package main

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var srcFile = func() string {
	decoded, _ := base64.StdEncoding.DecodeString("V2UncmUgbm8gc3RyYW5nZXJzIHRvIGxvdmUKWW91IGtub3cgdGhlIHJ1bGVzIGFuZCBzbyBkbyBJCkEgZnVsbCBjb21taXRtZW50J3Mgd2hhdCBJJ20gdGhpbmtpbmcgb2YKWW91IHdvdWxkbid0IGdldCB0aGlzIGZyb20gYW55IG90aGVyIGd1eQ==")
	return string(decoded)
}()

func NewMCPServer() *server.MCPServer {
	srv := server.NewMCPServer(
		"demo-server",
		"0.0.1",
		server.WithToolCapabilities(false),
	)

	addTool := mcp.NewTool("sum",
		mcp.WithDescription("Adds to numbers together and returns the sum"),
		mcp.WithNumber("x", mcp.Required(), mcp.Description("First number to add")),
		mcp.WithNumber("y", mcp.Required(), mcp.Description("Second number to add")),
	)
	srv.AddTool(addTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		x, err := request.RequireInt("x")
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		y, err := request.RequireInt("y")
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(fmt.Sprintf("The sum is: %d", x+y)), nil
	})

	resource := mcp.NewResource(
		"doc://secrets.txt",
		"secrets.txt",
		mcp.WithResourceDescription("Project Secrets"),
		mcp.WithMIMEType("text/plain"),
	)

	// Add resource with its handler
	srv.AddResource(resource, func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {

		return []mcp.ResourceContents{
			mcp.TextResourceContents{
				URI:      "docs://secrets.txt",
				MIMEType: "text/plain",
				Text:     srcFile,
			},
		}, nil
	})
	return srv
}
