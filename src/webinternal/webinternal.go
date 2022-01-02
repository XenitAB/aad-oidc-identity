package webinternal

import (
	"context"
	"fmt"
	"log"
	"net/http"

	gorillaHandlers "github.com/gorilla/handlers"
	"github.com/xenitab/aad-oidc-identity/src/config"
	"github.com/xenitab/go-oidc-middleware/oidchttp"
	oidcoptions "github.com/xenitab/go-oidc-middleware/options"
)

type InternalWeb struct {
	server *http.Server
}

type TokenGetter interface {
	GetToken(ctx context.Context, issuer string, subject string) ([]byte, string, error)
}

func NewServer(cfg config.Config, internalIssuer string, httpClient *http.Client, providerTokenGetter map[string]TokenGetter) (*InternalWeb, error) {
	router := http.NewServeMux()

	for provider, t := range providerTokenGetter {
		router.HandleFunc(fmt.Sprintf("/token/%s", provider), tokenHandler(t, cfg.ExternalIssuer))
	}

	oidcHandler := oidchttp.New(router,
		oidcoptions.WithIssuer(internalIssuer),
		oidcoptions.WithRequiredAudience(cfg.TokenAudience),
		oidcoptions.WithLazyLoadJwks(true),
		oidcoptions.WithHttpClient(httpClient),
	)

	addr := fmt.Sprintf("%s:%d", cfg.Address, cfg.InternalPort)

	srv := &http.Server{
		Addr:    addr,
		Handler: gorillaHandlers.CombinedLoggingHandler(log.Writer(), oidcHandler),
	}

	return &InternalWeb{
		server: srv,
	}, nil
}

func (srv *InternalWeb) ListenAndServe() error {
	return srv.server.ListenAndServe()
}

func (srv *InternalWeb) Shutdown(ctx context.Context) error {
	return srv.server.Shutdown(ctx)
}

func tokenHandler(t TokenGetter, issuer string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		subject, err := getSubjectFromClaims(r)
		if err != nil {
			log.Printf("unable to get subject from claims: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		responseData, contentType, err := t.GetToken(r.Context(), issuer, subject)
		if err != nil {
			log.Printf("unable to get token from provider: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(http.StatusOK)
		w.Write(responseData)
	}
}

func getSubjectFromClaims(r *http.Request) (string, error) {
	claims, ok := r.Context().Value(oidcoptions.DefaultClaimsContextKeyName).(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("unable to find claims in context")
	}

	rawSub, ok := claims["sub"]
	if !ok {
		return "", fmt.Errorf("unable to find sub in claims")
	}

	sub, ok := rawSub.(string)
	if !ok {
		return "", fmt.Errorf("unable to typecast sub to string: %T", rawSub)
	}

	return sub, nil
}
