package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/casapps/casspeed/src/swagger"
)

const mcpProtocolVersion = "2026-07-28"

type mcpRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	Meta    map[string]any  `json:"_meta"`
}

type mcpToolCall struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

type mcpTool struct {
	Name            string          `json:"name"`
	Description     string          `json:"description"`
	InputSchema     map[string]any  `json:"inputSchema"`
	Annotations     map[string]bool `json:"annotations,omitempty"`
	Path            string          `json:"-"`
	Method          string          `json:"-"`
	OperatorOnly    bool            `json:"-"`
	BodyContentType string          `json:"-"`
}

type mcpOpenAPI struct {
	Paths map[string]map[string]json.RawMessage `json:"paths"`
}
type mcpOperation struct {
	OperationID  string           `json:"operationId"`
	Summary      string           `json:"summary"`
	Description  string           `json:"description"`
	Parameters   []map[string]any `json:"parameters"`
	RequestBody  map[string]any   `json:"requestBody"`
	Responses    map[string]any   `json:"responses"`
	MCPExcluded  bool             `json:"x-mcp-excluded"`
	OperatorOnly bool             `json:"x-operator-only"`
}

var mcpPathParam = regexp.MustCompile(`\{([^{}]+)\}`)
var mcpSafePathValue = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)

// handleMCP is mounted on the canonical endpoint and both direct aliases.
func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	s.auditMCP("mcp.request", "", "")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		s.mcpHTTPError(w, 405, "method_not_allowed", "MCP accepts POST only")
		return
	}
	if !s.mcpOriginAllowed(r) {
		s.mcpHTTPError(w, 403, "forbidden", "Origin is not allowed")
		return
	}
	const bearer = "Bearer "
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, bearer) || strings.TrimSpace(strings.TrimPrefix(auth, bearer)) == "" {
		s.auditMCP("mcp.auth.failure", "", "")
		w.Header().Set("WWW-Authenticate", "Bearer")
		s.mcpAuthError(w, nil)
		return
	}
	rawToken := strings.TrimPrefix(auth, bearer)
	token, _, valid := s.validateBearerToken(r.Context(), rawToken)
	if !valid || token.Scope == "agent" {
		s.auditMCP("mcp.auth.failure", "", "")
		w.Header().Set("WWW-Authenticate", "Bearer")
		s.mcpAuthError(w, nil)
		return
	}
	rawBody, bodyErr := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	var req mcpRequest
	if bodyErr != nil || json.Unmarshal(rawBody, &req) != nil {
		s.mcpHTTPError(w, 400, "bad_request", "Invalid JSON-RPC request")
		return
	}
	s.auditMCP("mcp.request", token.ID, req.Method)
	protocolHeader := r.Header.Get("MCP-Protocol-Version")
	if req.Method == "initialize" || (protocolHeader != "" && protocolHeader != mcpProtocolVersion) {
		w.Header().Set("MCP-Protocol-Version", mcpProtocolVersion)
		s.mcpRPCError(w, 400, req.ID, -32001, "Unsupported protocol version", map[string]any{"supported": []string{mcpProtocolVersion}})
		return
	}
	if protocolHeader != mcpProtocolVersion || req.JSONRPC != "2.0" || r.Header.Get("Mcp-Method") != req.Method || req.Meta["io.modelcontextprotocol/protocolVersion"] != mcpProtocolVersion {
		s.mcpRPCError(w, 400, req.ID, -32020, "HeaderMismatch", nil)
		return
	}
	var params map[string]any
	if len(req.Params) > 0 && string(req.Params) != "null" {
		if err := json.Unmarshal(req.Params, &params); err != nil {
			s.mcpRPCError(w, 400, req.ID, -32020, "HeaderMismatch", nil)
			return
		}
	}
	if req.Method == "tools/call" || req.Method == "resources/read" || req.Method == "prompts/get" {
		name, _ := params["name"].(string)
		if name == "" {
			name, _ = params["uri"].(string)
		}
		headerName, ok := decodeMCPName(r.Header.Get("Mcp-Name"))
		if !ok || name == "" || name != headerName {
			s.mcpRPCError(w, 400, req.ID, -32020, "HeaderMismatch", nil)
			return
		}
	}
	if req.Method != "tools/list" && req.Method != "tools/call" {
		s.mcpRPCError(w, 404, req.ID, -32601, "Method not found", nil)
		return
	}
	scope := token.Scope
	if scope == "" {
		scope = "global"
	}
	operator := strings.HasPrefix(token.TokenPrefix, "adm_") && scope == "global"
	tools, err := s.mcpToolsFor(r, scope, operator)
	if err != nil {
		s.mcpRPCError(w, 500, req.ID, -32603, "Unable to load API tools", nil)
		return
	}
	if req.Method == "tools/list" {
		s.mcpResult(w, req.ID, map[string]any{"tools": tools})
		return
	}
	var call mcpToolCall
	if err := json.Unmarshal(req.Params, &call); err != nil || call.Name == "" {
		s.mcpRPCError(w, 400, req.ID, -32602, "Invalid params", nil)
		return
	}
	for _, tool := range tools {
		if tool.Name == call.Name {
			result, failed := s.mcpDispatch(r, tool, call.Arguments)
			s.auditMCP("mcp.tool.call", token.ID, tool.Name)
			s.mcpResult(w, req.ID, map[string]any{"content": []any{map[string]any{"type": "text", "text": result}}, "isError": failed})
			return
		}
	}
	s.mcpRPCError(w, 404, req.ID, -32601, "Method not found", nil)
}

func (s *Server) mcpTools(r *http.Request) ([]mcpTool, error) {
	return s.mcpToolsFor(r, "global", false)
}

func (s *Server) mcpToolsFor(r *http.Request, scope string, operator bool) ([]mcpTool, error) {
	rec := httptest.NewRecorder()
	swagger.SpecHandlerWithRoutes(rec, r, s.openapiRouteInventory())
	var spec mcpOpenAPI
	if err := json.Unmarshal(rec.Body.Bytes(), &spec); err != nil {
		return nil, err
	}
	tools := make([]mcpTool, 0)
	for path, methods := range spec.Paths {
		if mcpRouteExcluded(path) {
			continue
		}
		adminPath := strings.Trim(s.Config.Server.AdminPath, "/")
		if adminPath == "" {
			adminPath = "administration"
		}
		operatorOnly := strings.HasPrefix(path, "/server/"+adminPath+"/")
		for method, raw := range methods {
			method = strings.ToUpper(method)
			if method != "GET" && method != "POST" && method != "PUT" && method != "PATCH" && method != "DELETE" {
				continue
			}
			var op mcpOperation
			if json.Unmarshal(raw, &op) != nil || op.OperationID == "" || op.MCPExcluded {
				continue
			}
			if (op.OperatorOnly || operatorOnly) && !operator {
				continue
			}
			if scope == "read" && method != "GET" {
				continue
			}
			if scope == "read-write" && (method == "DELETE" || op.OperatorOnly || operatorOnly) {
				continue
			}
			if scope != "read" && scope != "read-write" && scope != "global" {
				continue
			}
			resolvedPath := path
			if op.OperatorOnly && strings.Contains(resolvedPath, "{adminPath}") {
				adminPath := s.Config.Server.AdminPath
				if adminPath == "" {
					adminPath = "administration"
				}
				resolvedPath = strings.ReplaceAll(resolvedPath, "{adminPath}", adminPath)
			}
			props := map[string]any{}
			schema := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
			required := make([]string, 0, len(op.Parameters))
			for _, p := range op.Parameters {
				name, _ := p["name"].(string)
				if op.OperatorOnly && name == "adminPath" {
					continue
				}
				if name != "" {
					props[name] = p["schema"]
					if p["required"] == true {
						required = append(required, name)
					}
				}
			}
			for _, match := range mcpPathParam.FindAllStringSubmatch(resolvedPath, -1) {
				if _, exists := props[match[1]]; !exists {
					props[match[1]] = map[string]any{"type": "string"}
				}
				required = append(required, match[1])
			}
			bodyContentType := ""
			if content, ok := op.RequestBody["content"].(map[string]any); ok {
				for mediaType, value := range content {
					media, ok := value.(map[string]any)
					if !ok {
						continue
					}
					bodyContentType = mediaType
					if bodySchema, ok := media["schema"]; ok {
						props["body"] = bodySchema
					}
					break
				}
				if op.RequestBody["required"] == true {
					required = append(required, "body")
				}
			}
			if len(required) > 0 {
				schema["required"] = required
			}
			desc := op.Description
			if desc == "" {
				desc = op.Summary
			}
			ann := map[string]bool{}
			switch method {
			case "GET":
				ann["readOnlyHint"] = true
			case "DELETE":
				ann["destructiveHint"] = true
				ann["idempotentHint"] = true
			case "PUT":
				ann["idempotentHint"] = true
			default:
				ann["readOnlyHint"] = false
			}
			tools = append(tools, mcpTool{Name: op.OperationID, Description: desc, InputSchema: schema, Annotations: ann, Path: resolvedPath, Method: method, OperatorOnly: op.OperatorOnly || operatorOnly, BodyContentType: bodyContentType})
		}
	}
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
	return tools, nil
}

func mcpRouteExcluded(path string) bool {
	for _, segment := range []string{"/auth", "/tokens", "/passkey", "/mcp", "/metrics", "/debug", "/preferences", "/server/swagger", "/server/graphql", "/autodiscover"} {
		if strings.Contains(path, segment) {
			return true
		}
	}
	return strings.HasSuffix(path, "/sync/import") || strings.HasSuffix(path, "/security/recovery") || strings.Contains(path, "/security/recovery/")
}

func (s *Server) mcpHelp(r *http.Request) (string, string, []map[string]string, error) {
	tools, err := s.mcpTools(r)
	if err != nil {
		return "", "", nil, err
	}
	toolDocs := make([]map[string]string, 0, len(tools))
	var toolTable strings.Builder
	for _, tool := range tools {
		toolDocs = append(toolDocs, map[string]string{"name": tool.Name, "description": tool.Description})
		fmt.Fprintf(&toolTable, "| `%s` | %s |\n", tool.Name, strings.ReplaceAll(tool.Description, "|", "\\|"))
	}
	endpoint := absoluteRequestURL(r, "/api/v1/server/mcp")
	project := "CasSpeed lets an assistant work with speed-test data through the same REST operations. Start a test, read its result, and create an explicit share link only for a result you own. Anonymous results remain private to their originating session until shared. Shared results can be read and exported as PNG or SVG."
	if configured := strings.TrimSpace(s.Config.Server.Pages.Help.MCP); configured != "" {
		project += "\n\n" + configured
	}
	content := strings.Join([]string{
		"## What this is",
		"",
		"CasSpeed provides a remote MCP server over Streamable HTTP. API operations are exposed as tools; every request requires an API bearer token, and the API enforces the same ownership checks as REST.",
		"",
		"## Endpoint",
		"",
		"Canonical endpoint: `" + endpoint + "`  ",
		"Aliases: `" + absoluteRequestURL(r, "/api/mcp") + "` and `" + absoluteRequestURL(r, "/mcp") + "`",
		"",
		"## Authentication",
		"",
		"Send `Authorization: Bearer $MCP_TOKEN` using the same API token as REST. MCP has no separate token and no anonymous access. Keep the token secret and revoke it if exposed.",
		"",
		"Token scopes limit available tools: `read` permits GET operations, `read-write` excludes DELETE and administrative operations, and `global` permits the full set allowed to the token owner. Agent-scoped tokens are not accepted. Token creation accepts a `scope` and an optional RFC3339 `expires_at` value.",
		"",
		"## Connect a client",
		"",
		"Claude Code:",
		"",
		"```sh",
		"claude mcp add --transport http casspeed " + endpoint + " --header \"Authorization: Bearer $MCP_TOKEN\"",
		"```",
		"",
		"Generic client configuration:",
		"",
		"```json",
		"{\"mcpServers\":{\"casspeed\":{\"type\":\"http\",\"url\":\"" + endpoint + "\",\"headers\":{\"Authorization\":\"Bearer $MCP_TOKEN\"}}}}",
		"```",
		"",
		"Verify with `curl`:",
		"",
		"```sh",
		"curl -q -sS '" + endpoint + "' \\",
		"  -H \"Authorization: Bearer $MCP_TOKEN\" \\",
		"  -H 'Content-Type: application/json' \\",
		"  -H 'MCP-Protocol-Version: " + mcpProtocolVersion + "' \\",
		"  -H 'Mcp-Method: tools/list' \\",
		"  --data '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"" + mcpProtocolVersion + "\"}}'",
		"```",
		"",
		"## Tools",
		"",
		"| Tool | Description |",
		"|---|---|",
		strings.TrimSuffix(toolTable.String(), "\n"),
		"",
		"## Behavior and limits",
		"",
		"The endpoint accepts HTTP `POST` only, keeps no sessions, checks `Origin`, and uses the API's rate limits and ownership rules. It supports MCP revision `" + mcpProtocolVersion + "`; legacy `initialize` handshakes are rejected.",
		"",
		"## Troubleshooting",
		"",
		"| Status | Cause | Fix |",
		"|---|---|---|",
		"| `400` | Unsupported protocol revision or mismatched required header | Send the supported revision and match `Mcp-Method` to the JSON-RPC method |",
		"| `401` | Missing or invalid bearer token | Send a valid `Authorization: Bearer` token |",
		"| `403` | Request `Origin` does not match the server origin | Use the server's own origin |",
		"| `405` | Method other than `POST` | Use HTTP POST |",
		"",
		"## Project",
		"",
		project,
		"",
	}, "\n")
	return content, project, toolDocs, nil
}

func (s *Server) mcpDispatch(parent *http.Request, tool mcpTool, args map[string]any) (string, bool) {
	if args == nil {
		args = map[string]any{}
	}
	properties, _ := tool.InputSchema["properties"].(map[string]any)
	for key := range args {
		if _, ok := properties[key]; !ok {
			return `{"ok":false,"error":"INVALID_ARGUMENT","message":"Unknown tool argument"}`, true
		}
	}
	path := tool.Path
	for _, match := range mcpPathParam.FindAllStringSubmatch(tool.Path, -1) {
		value, ok := args[match[1]]
		if !ok {
			return `{"ok":false,"error":"INVALID_ARGUMENT","message":"Missing path parameter"}`, true
		}
		segment := fmt.Sprint(value)
		if !mcpSafePathValue.MatchString(segment) || segment == "." || segment == ".." {
			return `{"ok":false,"error":"INVALID_ARGUMENT","message":"Invalid path parameter"}`, true
		}
		path = strings.Replace(path, "{"+match[1]+"}", url.PathEscape(segment), 1)
	}
	query := url.Values{}
	for key, value := range args {
		if key != "body" && !strings.Contains(tool.Path, "{"+key+"}") {
			query.Set(key, fmt.Sprint(value))
		}
	}
	if q := query.Encode(); q != "" {
		path += "?" + q
	}
	var body io.Reader
	if value, ok := args["body"]; ok {
		if tool.BodyContentType == "application/octet-stream" {
			encoded, _ := value.(string)
			raw, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				return `{"ok":false,"error":"INVALID_ARGUMENT","message":"Binary body must be base64 encoded"}`, true
			}
			body = bytes.NewReader(raw)
		} else {
			raw, _ := json.Marshal(value)
			body = bytes.NewReader(raw)
		}
	}
	req := parent.Clone(parent.Context())
	req.Method = tool.Method
	req.URL, _ = url.Parse("/api/v1" + path)
	req.RequestURI = req.URL.RequestURI()
	if body == nil {
		req.Body = http.NoBody
	} else {
		req.Body = io.NopCloser(body)
	}
	req.Header = parent.Header.Clone()
	req.Header.Del("Cookie")
	if body != nil {
		contentType := tool.BodyContentType
		if contentType == "" {
			contentType = "application/json"
		}
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	s.Router.ServeHTTP(rec, req)
	result := strings.TrimSpace(rec.Body.String())
	contentType := strings.ToLower(rec.Header().Get("Content-Type"))
	if strings.HasPrefix(contentType, "application/octet-stream") || strings.HasPrefix(contentType, "image/png") {
		result = "base64:" + base64.StdEncoding.EncodeToString(rec.Body.Bytes())
	}
	if rec.Code < 200 || rec.Code >= 300 {
		var apiError map[string]any
		if json.Unmarshal(rec.Body.Bytes(), &apiError) != nil || apiError["ok"] != false || apiError["error"] == nil || apiError["message"] == nil {
			raw, _ := json.Marshal(map[string]any{"ok": false, "error": http.StatusText(rec.Code), "message": http.StatusText(rec.Code)})
			result = string(raw)
		}
	}
	if result == "" {
		result = fmt.Sprintf(`{"ok":%t}`, rec.Code >= 200 && rec.Code < 300)
	}
	return result, rec.Code < 200 || rec.Code >= 300
}

func (s *Server) auditMCP(event, tokenID, operation string) {
	if s.Logger == nil || s.Logger.Audit == nil {
		return
	}
	entry := map[string]any{"timestamp": time.Now().UTC().Format(time.RFC3339), "source": "mcp", "event": event}
	if tokenID != "" {
		entry["token_id"] = tokenID
	}
	if operation != "" {
		entry["operation"] = operation
	}
	raw, err := json.Marshal(entry)
	if err == nil {
		s.Logger.Audit.Printf("%s\n", raw)
	}
}

func (s *Server) mcpOriginAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	requestOrigin, err := url.Parse(absoluteRequestURL(r, ""))
	if err == nil && strings.EqualFold(u.Scheme, requestOrigin.Scheme) && strings.EqualFold(u.Host, requestOrigin.Host) {
		return true
	}
	allowed, wildcard := s.corsOriginAllowed(origin)
	return allowed && !wildcard
}
func decodeMCPName(value string) (string, bool) {
	if strings.HasPrefix(value, "=?base64?") && strings.HasSuffix(value, "?=") {
		decoded, err := base64.StdEncoding.DecodeString(value[len("=?base64?") : len(value)-2])
		return string(decoded), err == nil
	}
	for _, c := range value {
		if c > 127 {
			return "", false
		}
	}
	return value, value != ""
}
func (s *Server) mcpHTTPError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": code, "message": message})
}
func (s *Server) mcpAuthError(w http.ResponseWriter, raw json.RawMessage) {
	var request struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
	}
	if len(raw) > 0 && json.Unmarshal(raw, &request) == nil && request.JSONRPC == "2.0" {
		s.mcpRPCError(w, http.StatusUnauthorized, request.ID, -32000, "Unauthorized", nil)
		return
	}
	s.mcpHTTPError(w, http.StatusUnauthorized, "unauthorized", "A valid Bearer token is required")
}
func (s *Server) mcpRPCError(w http.ResponseWriter, status int, id json.RawMessage, code int, message string, data any) {
	rpcError := map[string]any{"code": code, "message": message}
	if data != nil {
		rpcError["data"] = data
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "error": rpcError})
}
func (s *Server) mcpResult(w http.ResponseWriter, id json.RawMessage, result any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}
