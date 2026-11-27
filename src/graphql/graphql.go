package graphql

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strings"

	"github.com/casapps/casspeed/src/common/i18n"
	graphqlgo "github.com/graph-gophers/graphql-go"
)

const maxGraphQLRequestBytes = 1 << 20

type graphQLRequest struct {
	Query         string         `json:"query"`
	OperationName string         `json:"operationName"`
	Variables     map[string]any `json:"variables"`
}

type queryHandler struct {
	schema *graphqlgo.Schema
	err    error
}

// NewQueryHandler constructs a validated GraphQL schema backed by live project services.
func NewQueryHandler(dependencies Dependencies) http.Handler {
	root := newResolvers(dependencies)
	schema, err := graphqlgo.ParseSchema(Schema, root,
		graphqlgo.MaxDepth(12),
		graphqlgo.MaxParallelism(8),
		graphqlgo.MaxQueryLength(maxGraphQLRequestBytes),
	)
	return &queryHandler{schema: schema, err: err}
}

// QueryHandler is an unconfigured compatibility handler. Applications should mount
// NewQueryHandler with their Store and health provider so resolvers have real data.
func QueryHandler(w http.ResponseWriter, r *http.Request) {
	NewQueryHandler(Dependencies{}).ServeHTTP(w, r)
}

func (h *queryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, POST")
		writeCanonicalError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GraphQL accepts GET and POST")
		return
	}
	if h.err != nil || h.schema == nil {
		writeCanonicalError(w, http.StatusInternalServerError, "SERVER_ERROR", "GraphQL schema is unavailable")
		return
	}
	request, err := readGraphQLRequest(w, r)
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			writeCanonicalError(w, http.StatusRequestEntityTooLarge, "REQUEST_TOO_LARGE", "GraphQL request is too large")
		} else {
			writeCanonicalError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid GraphQL request")
		}
		return
	}
	if request.Query == "" && r.Method == http.MethodGet {
		writeGraphQLResponse(w, map[string]any{"data": map[string]any{}, "extensions": map[string]any{"message": "Send a GraphQL query in the query parameter; mutations are not supported."}})
		return
	}
	ctx := contextWithRequest(r)
	response := h.schema.Exec(ctx, request.Query, request.OperationName, request.Variables)
	writeGraphQLResponse(w, response)
}

func readGraphQLRequest(w http.ResponseWriter, r *http.Request) (graphQLRequest, error) {
	if r.Method == http.MethodGet {
		query := r.URL.Query()
		variables, err := parseGraphQLVariables(query.Get("variables"))
		if err != nil {
			return graphQLRequest{}, err
		}
		return graphQLRequest{Query: query.Get("query"), OperationName: query.Get("operationName"), Variables: variables}, nil
	}
	if r.ContentLength > maxGraphQLRequestBytes {
		return graphQLRequest{}, &http.MaxBytesError{Limit: maxGraphQLRequestBytes}
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxGraphQLRequestBytes)
	decoder := json.NewDecoder(r.Body)
	var request graphQLRequest
	if err := decoder.Decode(&request); err != nil {
		return graphQLRequest{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return graphQLRequest{}, fmt.Errorf("multiple JSON values")
	}
	return request, nil
}

func parseGraphQLVariables(value string) (map[string]any, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	variables := make(map[string]any)
	if err := json.Unmarshal([]byte(value), &variables); err != nil {
		return nil, err
	}
	return variables, nil
}

func writeGraphQLResponse(w http.ResponseWriter, response any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(response)
}

func writeCanonicalError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": code, "message": message})
}

func contextWithRequest(r *http.Request) context.Context {
	return context.WithValue(r.Context(), requestContextKey{}, r)
}

// Handler serves the server-rendered GraphiQL shell and loads only local assets.
func Handler(w http.ResponseWriter, r *http.Request) {
	themeClass := GetThemeClass(DetectTheme(r))
	catalog := docsCatalog(r)
	prefix := docsPathPrefix(r, []string{"/server/docs/graphql", "/server/graphql", "/docs/graphql", "/graphql"})
	data := struct {
		Lang, Dir, ThemeClass, Prefix, Endpoint string
		Text                                    map[string]string
	}{catalog.Meta.Language, catalog.Meta.Direction, themeClass, prefix, prefix + "/api/v1/server/graphql", graphqlStandaloneText(catalog)}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := graphiQLPage.Execute(w, data); err != nil {
		http.Error(w, "Unable to render GraphiQL", http.StatusInternalServerError)
	}
}

func docsCatalog(r *http.Request) *i18n.Catalog {
	candidates := []string{r.URL.Query().Get("lang")}
	if cookie, err := r.Cookie("lang"); err == nil {
		candidates = append(candidates, cookie.Value)
	}
	for _, value := range strings.Split(r.Header.Get("Accept-Language"), ",") {
		candidates = append(candidates, strings.TrimSpace(strings.SplitN(value, ";", 2)[0]))
	}
	for _, candidate := range candidates {
		if i18n.IsSupportedTag(candidate) {
			if catalog, err := i18n.Resolve(candidate); err == nil {
				return catalog
			}
		}
	}
	catalog, _ := i18n.Resolve("en")
	return catalog
}

func docsPathPrefix(r *http.Request, suffixes []string) string {
	path := strings.TrimSuffix(r.URL.EscapedPath(), "/")
	for _, suffix := range suffixes {
		if strings.HasSuffix(path, suffix) {
			return strings.TrimSuffix(path, suffix)
		}
	}
	return ""
}

func graphqlStandaloneText(catalog *i18n.Catalog) map[string]string {
	keys := []string{"description", "title", "skip_content", "skip_navigation", "brand_home", "main_navigation", "home", "speed_test", "help", "about", "color_theme", "theme_dark", "theme_light", "theme_auto", "heading", "loading", "no_script", "endpoint", "footer_privacy"}
	values := make(map[string]string, len(keys))
	for _, key := range keys {
		values[key] = catalog.T("docs.graphql_standalone."+key, nil)
	}
	return values
}

var graphiQLPage = template.Must(template.New("graphiql").Parse(`<!doctype html>
<html lang="{{.Lang}}" dir="{{.Dir}}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="description" content="{{index .Text "description"}}"><title>{{index .Text "title"}} — CasSpeed</title><link rel="stylesheet" href="{{.Prefix}}/static/css/theme-dark.css"><link rel="stylesheet" href="{{.Prefix}}/static/css/theme-light.css"><link rel="stylesheet" href="{{.Prefix}}/static/css/style.css"><link rel="stylesheet" href="{{.Prefix}}/static/vendor/graphiql/graphiql.min.css"><link rel="stylesheet" href="{{.Prefix}}/static/css/graphiql-theme.css"><script src="{{.Prefix}}/static/js/theme.js" defer></script><script src="{{.Prefix}}/static/vendor/graphiql/react.production.min.js" defer></script><script src="{{.Prefix}}/static/vendor/graphiql/react-dom.production.min.js" defer></script><script src="{{.Prefix}}/static/vendor/graphiql/graphiql.min.js" defer></script><script src="{{.Prefix}}/static/js/docs-graphql.js" defer></script></head>
<body class="{{.ThemeClass}}"><a class="skip-link" href="#main-content">{{index .Text "skip_content"}}</a><a class="skip-link" href="#site-navigation">{{index .Text "skip_navigation"}}</a><header class="site-header"><a class="site-header__brand" href="{{.Prefix}}/" aria-label="{{index .Text "brand_home"}}">CasSpeed</a><nav id="site-navigation" aria-label="{{index .Text "main_navigation"}}"><a href="{{.Prefix}}/">{{index .Text "speed_test"}}</a><a href="{{.Prefix}}/server/help">{{index .Text "help"}}</a><a href="{{.Prefix}}/server/about">{{index .Text "about"}}</a></nav><div class="site-header__actions"><div class="theme-toggle" role="group" aria-label="{{index .Text "color_theme"}}"><button class="theme-toggle__btn" data-theme-btn="dark" aria-pressed="false" aria-label="{{index .Text "theme_dark"}}" type="button">◐</button><button class="theme-toggle__btn" data-theme-btn="light" aria-pressed="false" aria-label="{{index .Text "theme_light"}}" type="button">◑</button><button class="theme-toggle__btn" data-theme-btn="auto" aria-pressed="false" aria-label="{{index .Text "theme_auto"}}" type="button">◎</button></div></div></header>
<main id="main-content"><div class="container container-lg"><header class="page-header"><h1 class="page-title">{{index .Text "title"}}</h1><p class="page-lead">{{index .Text "description"}}</p></header><section class="section-card" aria-labelledby="graphql-explorer-heading"><h2 id="graphql-explorer-heading">{{index .Text "heading"}}</h2><div id="graphiql" class="graphiql-container" data-endpoint="{{.Endpoint}}">{{index .Text "loading"}}</div><noscript><p>{{index .Text "no_script"}} <a href="{{.Endpoint}}?query=%7Bhealth%7Bstatus%7D%7D">{{index .Text "endpoint"}}</a>.</p></noscript></section></div></main>
<footer class="site-footer"><a href="{{.Prefix}}/server/about">{{index .Text "about"}}</a> · <a href="{{.Prefix}}/server/privacy">{{index .Text "footer_privacy"}}</a> · <a href="{{.Prefix}}/server/help">{{index .Text "help"}}</a></footer></body></html>`))
