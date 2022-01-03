package webexternal

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	gorillaHandlers "github.com/gorilla/handlers"
	"github.com/lestrrat-go/jwx/jwk"
)

type WebExternal struct {
	server *http.Server
}

type publicKeyGetter interface {
	GetPublicKeySet() jwk.Set
}

func NewServer(setters ...Option) (*WebExternal, error) {
	opts, err := newOptions(setters...)
	if err != nil {
		return nil, fmt.Errorf("unable to get webexternal options: %w", err)
	}

	router := http.NewServeMux()
	router.HandleFunc("/.well-known/openid-configuration", metadataHandler(opts.issuer))
	router.HandleFunc("/jwks", jwksHandler(opts.key))

	addr := fmt.Sprintf("%s:%d", opts.address, opts.port)

	srv := &http.Server{
		Addr:    addr,
		Handler: gorillaHandlers.CombinedLoggingHandler(log.Writer(), router),
	}

	return &WebExternal{
		server: srv,
	}, nil
}

func (srv *WebExternal) ListenAndServe() error {
	return srv.server.ListenAndServe()
}

func (srv *WebExternal) Shutdown(ctx context.Context) error {
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

func metadataHandler(externalIssuer string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := metadata{
			Issuer:                           externalIssuer,
			JwksUri:                          fmt.Sprintf("%s/jwks", externalIssuer),
			ResponseTypesSupported:           []string{"id_token"},
			IdTokenSigningAlgValuesSupported: []string{"RS256"},
			SubjectTypesSupported:            []string{"public", "pairwise"},
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		json.NewEncoder(w).Encode(data)
	}
}

func jwksHandler(key publicKeyGetter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pubKey := key.GetPublicKeySet()

		w.Header().Set("Content-Type", "application/json")
		e := json.NewEncoder(w)
		e.SetIndent("", "  ")

		e.Encode(pubKey)
	}
}
