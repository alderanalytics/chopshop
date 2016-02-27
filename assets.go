package chopshop

import (
	"net/http"
	"os"
	"path"
	"strings"
)

// AssetHandler is a function that takes a path and either returns a response
// representing an asset or nil if the request cannot be fulfilled.
type AssetHandler func(path string) Response

// AssetResolver defines a sequence of AssetHandlers (called a resolution chain)
// applied in the given order to find an AssetHandler capable of fulfilling the
// request.
type AssetResolver struct {
	chain []AssetHandler
}

// NewAssetResolver constructs an AssetResolver with the given resolution chain.
func NewAssetResolver(chain ...AssetHandler) *AssetResolver {
	return &AssetResolver{chain: chain}
}

// PrependHandler prepends an AssetHandler to the resolution chain.
func (r *AssetResolver) PrependHandler(handler AssetHandler) {
	r.chain = append([]AssetHandler{handler}, r.chain...)
}

// AppendHandler appends an AssetHandler to the resolution chain.
func (r *AssetResolver) AppendHandler(handler AssetHandler) {
	r.chain = append(r.chain, handler)
}

// Chain replaces the resolution chain with the given argument sequence.
func (r *AssetResolver) Chain(chain ...AssetHandler) {
	r.chain = chain
}

// Resolve invokes the resolution chain in the given order, returning the first
// non-nil response from an AssetHandler. In the event that none of the
// AssetHandlers in the chain can fulfill the response, Resolve returns nil.
func (r *AssetResolver) Resolve(path string) Response {
	for _, resolver := range r.chain {
		if response := resolver(path); response != nil {
			return response
		}
	}
	return nil
}

// AssetResolverResponse returns a ContextHandlerFunc which attempts to return
// an response from an AssetResolver. If the AssetResolver cannot fulfill the
// request, BlankResponse(404) is returned.
func AssetResolverResponse(a *AssetResolver) ContextHandlerFunc {
	return func(ctx *RequestContext) Response {
		path := ctx.r.URL.Path
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}

		if response := a.Resolve(path); response != nil {
			return response
		}

		return BlankResponse(http.StatusNotFound)
	}
}

// LocalAssetHandler constructs an asset handler for serving assets from a local
// folder.
func LocalAssetHandler(rootpath string) AssetHandler {
	return func(lpath string) Response {
		if filename, err := resolveLocalFile(rootpath + path.Clean(lpath)); err == nil {
			return ResponseFunc(func(w http.ResponseWriter, r *http.Request) {
				http.ServeFile(w, r, filename)
			})
		}

		return nil
	}
}

func resolveLocalFile(filename string) (string, error) {
	stat, err := os.Stat(filename)
	if err != nil {
		return "", err
	}

	if stat.IsDir() {
		return resolveLocalFile(filename + "/index.html")
	}

	return filename, nil
}
