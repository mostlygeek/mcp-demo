package main

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

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
		"user://who-am-i.txt",
		"who-am-i.txt",
		mcp.WithResourceDescription("Oauth user info from the access token"),
		mcp.WithMIMEType("text/plain"),
	)

	// Add resource with its handler
	srv.AddResource(resource, func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {

		return []mcp.ResourceContents{
			mcp.TextResourceContents{
				URI:      "user://who-am-i.txt",
				MIMEType: "text/plain",
				Text:     "to be filled in",
			},
		}, nil
	})
	return srv
}
