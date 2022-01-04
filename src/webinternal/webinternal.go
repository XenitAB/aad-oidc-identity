package webinternal

import (
	"context"
	"fmt"
	"log"
	"net/http"

	gorillaHandlers "github.com/gorilla/handlers"
	"github.com/xenitab/go-oidc-middleware/oidchttp"
	oidcoptions "github.com/xenitab/go-oidc-middleware/options"
)

type WebInternal struct {
	server *http.Server
}

type GetTokenFn func(ctx context.Context, issuer string, subject string) ([]byte, string, error)

func NewServer(setters ...Option) (*WebInternal, error) {
	opts, err := newOptions(setters...)
	if err != nil {
		return nil, fmt.Errorf("unable to get webinternal options: %w", err)
	}
	router := http.NewServeMux()

	for provider, getToken := range opts.getTokens {
		router.HandleFunc(fmt.Sprintf("/token/%s", provider), tokenHandler(getToken, opts.issuerExternal))
	}

	oidcHandler := oidchttp.New(router,
		oidcoptions.WithIssuer(opts.issuerInternal),
		oidcoptions.WithRequiredAudience(opts.audience),
		oidcoptions.WithLazyLoadJwks(true),
		oidcoptions.WithHttpClient(opts.httpClient),
	)

	addr := fmt.Sprintf("%s:%d", opts.address, opts.port)

	srv := &http.Server{
		Addr:    addr,
		Handler: gorillaHandlers.CombinedLoggingHandler(log.Writer(), oidcHandler),
	}

	return &WebInternal{
		server: srv,
	}, nil
}

func (srv *WebInternal) ListenAndServe() error {
	return srv.server.ListenAndServe()
}

func (srv *WebInternal) Shutdown(ctx context.Context) error {
	return srv.server.Shutdown(ctx)
}

func tokenHandler(getTokenFn GetTokenFn, issuer string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		subject, err := getSubjectFromClaims(r)
		if err != nil {
			log.Printf("unable to get subject from claims: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		responseData, contentType, err := getTokenFn(r.Context(), issuer, subject)
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
