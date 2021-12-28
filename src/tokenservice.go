package main

import (
	"context"
	"fmt"
	"net/http"
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
	kr     *kubeReader
}

func NewTokenService(cfg config, kr *kubeReader) (*tokenService, error) {
	ts := &tokenService{
		kr: kr,
	}

	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	httpClient := kr.getKubeHttpClient()

	issuer, err := kr.getKubeIssuer()
	if err != nil {
		return nil, err
	}

	oidcMiddleware := oidcgin.New(
		oidcoptions.WithIssuer(issuer),
		oidcoptions.WithRequiredAudience(cfg.TokenAudience),
		oidcoptions.WithLazyLoadJwks(true),
		oidcoptions.WithHttpClient(httpClient),
	)

	internal := r.Group("/internal/", oidcMiddleware)
	external := r.Group("/external/")

	rsaKey, err := kr.getCertificateFromSecret(context.Background(), "default", "aad-oidc-identity-jwks")
	if err != nil {
		return nil, err
	}

	jwks, err := newJwksHandler(rsaKey)
	if err != nil {
		return nil, err
	}

	internal.GET("/token/azure", ts.internalAzureTokenHttpHandler(jwks, cfg.ExternalIssuer))
	internal.GET("/token/aws", ts.internalAwsTokenHttpHandler(jwks, cfg.ExternalIssuer))
	internal.GET("/token/google", ts.internalGoogleTokenHttpHandler(jwks, cfg.ExternalIssuer))
	external.GET("/.well-known/openid-configuration", metadataHttpHandler(cfg.ExternalIssuer))
	external.GET("/jwks", jwksHttpHandler(jwks))

	addr := fmt.Sprintf("%s:%d", cfg.Address, cfg.Port)

	srv := &http.Server{
		Addr:    addr,
		Handler: r,
	}

	ts.server = srv

	return ts, nil
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

func metadataHttpHandler(issuer string) gin.HandlerFunc {
	return func(c *gin.Context) {
		data := metadata{
			Issuer:                           issuer,
			JwksUri:                          fmt.Sprintf("%s/jwks", issuer),
			ResponseTypesSupported:           []string{"id_token"},
			IdTokenSigningAlgValuesSupported: []string{"RS256"},
			SubjectTypesSupported:            []string{"public", "pairwise"},
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

func newAccessToken(jwks *jwksHandler, issuer string, subject string, aud string) (string, error) {
	privKey := jwks.getPrivateKey()

	c := map[string]interface{}{
		jwt.IssuerKey:     issuer,
		jwt.AudienceKey:   aud,
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

func getNamespaceAndServiceAccountFromSubject(sub string) (string, string, error) {
	// system:serviceaccount:namespace:serviceaccount
	comp := strings.SplitN(sub, ":", 4)
	namespace := comp[2]
	if namespace == "" {
		return "", "", fmt.Errorf("namespace is empty in subject: %s", sub)
	}

	serviceAccount := comp[3]
	if serviceAccount == "" {
		return "", "", fmt.Errorf("serviceAccount is empty in subject: %s", sub)
	}

	return namespace, serviceAccount, nil

}
