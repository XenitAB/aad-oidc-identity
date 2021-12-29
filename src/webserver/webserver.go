package webserver

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/xenitab/aad-oidc-identity/src/config"
	"github.com/xenitab/go-oidc-middleware/oidcgin"
	oidcoptions "github.com/xenitab/go-oidc-middleware/options"
)

type WebServer struct {
	server *http.Server
}

type publicKeyGetter interface {
	GetPublicKeySet() jwk.Set
}

func NewWebServer(cfg config.Config, internalIssuer string, httpClient *http.Client, key publicKeyGetter, providerHandlerFuncs map[string]gin.HandlerFunc) (*WebServer, error) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	oidcMiddleware := oidcgin.New(
		oidcoptions.WithIssuer(internalIssuer),
		oidcoptions.WithRequiredAudience(cfg.TokenAudience),
		oidcoptions.WithLazyLoadJwks(true),
		oidcoptions.WithHttpClient(httpClient),
	)

	internal := r.Group("/internal/", oidcMiddleware)
	external := r.Group("/external/")

	for provider, handler := range providerHandlerFuncs {
		internal.GET(fmt.Sprintf("/token/%s", provider), handler)
	}

	external.GET("/.well-known/openid-configuration", metadataHttpHandler(cfg.ExternalIssuer))
	external.GET("/jwks", jwksHttpHandler(key))

	addr := fmt.Sprintf("%s:%d", cfg.Address, cfg.Port)

	srv := &http.Server{
		Addr:    addr,
		Handler: r,
	}

	return &WebServer{
		server: srv,
	}, nil
}

func (srv *WebServer) ListenAndServe() error {
	return srv.server.ListenAndServe()
}

func (srv *WebServer) Shutdown(ctx context.Context) error {
	return srv.server.Shutdown(ctx)
}

type metadata struct {
	Issuer  string `json:"issuer"`
	JwksUri string `json:"jwks_uri"`

	// These are required by AWS or else the following error will occur:
	// <ErrorResponse>
	//   <Error>
	//     <Type>Sender</Type>
	//     <Code>InvalidIdentityToken</Code>
	//     <Message>Couldn't retrieve verification key from your identity provider,  please reference AssumeRoleWithWebIdentity documentation for requirements</Message>
	//   </Error>
	//   <RequestId>00000000-0000-0000-0000-000000000000</RequestId>
	// </ErrorResponse>
	ResponseTypesSupported           []string `json:"response_types_supported"`
	IdTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
}

func metadataHttpHandler(externalIssuer string) gin.HandlerFunc {
	return func(c *gin.Context) {
		data := metadata{
			Issuer:                           externalIssuer,
			JwksUri:                          fmt.Sprintf("%s/jwks", externalIssuer),
			ResponseTypesSupported:           []string{"id_token"},
			IdTokenSigningAlgValuesSupported: []string{"RS256"},
			SubjectTypesSupported:            []string{"public", "pairwise"},
		}

		c.JSON(http.StatusOK, data)
	}
}

func jwksHttpHandler(key publicKeyGetter) gin.HandlerFunc {
	return func(c *gin.Context) {
		pubKey := key.GetPublicKeySet()

		c.JSON(http.StatusOK, pubKey)
	}
}
