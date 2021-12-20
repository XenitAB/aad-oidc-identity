package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
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

	jwks, err := newJwksHandler()
	if err != nil {
		return nil, err
	}

	internal.GET("/token", internalTokenHttpHandler(jwks, cfg.ExternalIssuer, cfg.ExternalTenantID, cfg.ExternalClientID))
	external.GET("/.well-known/openid-configuration", metadataHttpHandler(cfg.ExternalIssuer))
	external.GET("/jwks", jwksHttpHandler(jwks))

	addr := fmt.Sprintf("%s:%d", cfg.Address, cfg.Port)

	srv := &http.Server{
		Addr:    addr,
		Handler: r,
	}

	return &tokenService{
		server: srv,
	}, nil
}

type metadata struct {
	Issuer  string `json:"issuer"`
	JwksUri string `json:"jwks_uri"`
}

func metadataHttpHandler(issuer string) gin.HandlerFunc {
	return func(c *gin.Context) {
		data := metadata{
			Issuer:  issuer,
			JwksUri: fmt.Sprintf("%s/jwks", issuer),
		}

		c.JSON(http.StatusOK, data)
	}
}

func jwksHttpHandler(jwks *jwksHandler) gin.HandlerFunc {
	return func(c *gin.Context) {
		pubKey := jwks.getPublicKeySet()

		c.JSON(http.StatusOK, pubKey)
	}
}

func newAccessToken(jwks *jwksHandler, issuer string, subject string) (string, error) {
	privKey := jwks.getPrivateKey()

	c := map[string]interface{}{
		jwt.IssuerKey:     issuer,
		jwt.AudienceKey:   "api://AzureADTokenExchange",
		jwt.SubjectKey:    subject,
		jwt.IssuedAtKey:   time.Now().Unix(),
		jwt.NotBeforeKey:  time.Now().Unix(),
		jwt.ExpirationKey: time.Now().Add(30 * time.Second).Unix(),
	}

	token := jwt.New()
	for k, v := range c {
		err := token.Set(k, v)
		if err != nil {
			return "", err
		}
	}

	h := map[string]interface{}{
		jws.KeyIDKey: privKey.KeyID(),
		// Microsoft error if not using 'JWT': {"error":"invalid_request","error_description":"AADSTS5002727: Invalid JWT header type specified, must be 'JWT' or 'http://openid.net/specs/jwt/1.0'.\r\nTrace ID: f9f80dd5-d257-4886-8031-fc52c5b11b00\r\nCorrelation ID: 61e463a9-7462-4e00-a0e3-f141b723a800\r\nTimestamp: 2021-12-20 21:21:25Z","error_codes":[5002727],"timestamp":"2021-12-20 21:21:25Z","trace_id":"f9f80dd5-d257-4886-8031-fc52c5b11b00","correlation_id":"61e463a9-7462-4e00-a0e3-f141b723a800"}
		jws.TypeKey: "JWT",
	}

	headers := jws.NewHeaders()
	for k, v := range h {
		err := headers.Set(k, v)
		if err != nil {
			return "", err
		}
	}

	// Error from Microsoft if not using 'RS256': {"error":"invalid_request","error_description":"AADSTS5002738: Invalid JWT token. 'ES384' is not a supported signature algorithm. Supported signing algorithms are: 'RS256, HS256'\r\nTrace ID: a798ea5f-df9a-4558-8618-21839c211600\r\nCorrelation ID: 81c2f6aa-de4a-464c-ae7c-a16511735188\r\nTimestamp: 2021-12-20 21:23:01Z","error_codes":[5002738],"timestamp":"2021-12-20 21:23:01Z","trace_id":"a798ea5f-df9a-4558-8618-21839c211600","correlation_id":"81c2f6aa-de4a-464c-ae7c-a16511735188","error_uri":"https://login.microsoftonline.com/error?code=5002738"}
	signedToken, err := jwt.Sign(token, jwa.RS256, privKey, jwt.WithHeaders(headers))
	if err != nil {
		return "", err
	}

	access := string(signedToken)

	return access, nil
}

type microsoftAccessTokenResponse struct {
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	AccessToken string `json:"access_token"`
}

// https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow#third-case-access-token-request-with-a-federated-credential
func getMicrosoftAccessToken(ctx context.Context, tenantId string, clientId string, internalToken string) (microsoftAccessTokenResponse, error) {
	data := url.Values{}
	data.Add("scope", "https://graph.microsoft.com/.default")
	data.Add("client_id", clientId)
	data.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	data.Add("client_assertion", internalToken)
	data.Add("grant_type", "client_credentials")

	remoteUrl, err := url.Parse(fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantId))
	if err != nil {
		return microsoftAccessTokenResponse{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, remoteUrl.String(), strings.NewReader(data.Encode()))
	if err != nil {
		return microsoftAccessTokenResponse{}, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return microsoftAccessTokenResponse{}, err
	}

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return microsoftAccessTokenResponse{}, err
	}

	log.Printf("Response code: %d", res.StatusCode)
	log.Printf("Response: %s", string(bodyBytes))

	defer res.Body.Close()

	var responseData microsoftAccessTokenResponse
	err = json.Unmarshal(bodyBytes, &responseData)
	if err != nil {
		return microsoftAccessTokenResponse{}, err
	}

	if responseData.AccessToken == "" {
		return microsoftAccessTokenResponse{}, fmt.Errorf("no access token in response")
	}

	return responseData, nil
}

func getSubjectFromClaims(c *gin.Context) (string, error) {
	claimsValue, ok := c.Get("claims")
	if !ok {
		return "", fmt.Errorf("unable to find claims in context")
	}

	claims, ok := claimsValue.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("unable to typecast claims to map[string]interface{}: %T", claimsValue)
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

func internalTokenHttpHandler(jwks *jwksHandler, issuer string, tenantId string, clientId string) gin.HandlerFunc {
	return func(c *gin.Context) {
		subject, err := getSubjectFromClaims(c)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		internalToken, err := newAccessToken(jwks, issuer, subject)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		msToken, err := getMicrosoftAccessToken(c.Request.Context(), tenantId, clientId, internalToken)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		c.JSON(http.StatusOK, msToken)
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
