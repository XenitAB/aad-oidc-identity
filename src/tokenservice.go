package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/xenitab/go-oidc-middleware/oidcgin"
	oidcoptions "github.com/xenitab/go-oidc-middleware/options"
)

type tokenService struct {
	server *http.Server
}

func NewTokenService(cfg config) (*tokenService, error) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	caCert, err := ioutil.ReadFile(cfg.CAPath)
	if err != nil {
		return nil, fmt.Errorf("unable to extract ca certificate: %w", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	token, err := ioutil.ReadFile(cfg.TokenPath)
	if err != nil {
		return nil, fmt.Errorf("unable to extract kubernetes service account token: %w", err)
	}

	transport := newAddHeaderTransport(&http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: caCertPool,
		},
	}, string(token))

	httpClient := &http.Client{
		Transport: transport,
	}

	oidcMiddleware := oidcgin.New(
		oidcoptions.WithIssuer(cfg.TokenIssuer),
		oidcoptions.WithRequiredAudience(cfg.TokenAudience),
		oidcoptions.WithLazyLoadJwks(true),
		oidcoptions.WithHttpClient(httpClient),
	)

	internal := r.Group("/internal/", oidcMiddleware)
	external := r.Group("/external/")

	internal.GET("/token", tokenHandler())

	external.GET("/foo", func(c *gin.Context) {
		c.String(200, "OK")
	})

	addr := fmt.Sprintf("%s:%d", cfg.Address, cfg.Port)

	srv := &http.Server{
		Addr:    addr,
		Handler: r,
	}

	return &tokenService{
		server: srv,
	}, nil
}

func tokenHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		claimsValue, found := c.Get("claims")
		if !found {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		claims, ok := claimsValue.(map[string]interface{})
		if !ok {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		c.JSON(http.StatusOK, claims)
	}
}

func newAddHeaderTransport(rt http.RoundTripper, token string) *addHeaderTransport {
	return &addHeaderTransport{
		rt:    rt,
		token: token,
	}
}

type addHeaderTransport struct {
	rt    http.RoundTripper
	token string
}

func (adt *addHeaderTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", adt.token))
	return adt.rt.RoundTrip(req)
}
