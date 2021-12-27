package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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

// "authorization_endpoint": "https://accounts.example.com/o/oauth2/v2/auth",
// "device_authorization_endpoint": "https://oauth2.exampleapis.com/device/code",
// "token_endpoint": "https://oauth2.exampleapis.com/token",
// "userinfo_endpoint": "https://openidconnect.exampleapis.com/v1/userinfo",
// "revocation_endpoint": "https://oauth2.exampleapis.com/revoke",

type metadata struct {
	Issuer                      string `json:"issuer"`
	JwksUri                     string `json:"jwks_uri"`
	AuthorizationEndpoint       string `json:"authorization_endpoint"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	TokenEndpoint               string `json:"token_endpoint"`
	UserinfoEndpoint            string `json:"userinfo_endpoint"`
	RevocationEndpoint          string `json:"revocation_endpoint"`
}

func metadataHttpHandler(issuer string) gin.HandlerFunc {
	return func(c *gin.Context) {
		data := metadata{
			Issuer:                      issuer,
			JwksUri:                     fmt.Sprintf("%s/jwks", issuer),
			AuthorizationEndpoint:       fmt.Sprintf("%s/fake/auth", issuer),
			TokenEndpoint:               fmt.Sprintf("%s/fake/token", issuer),
			UserinfoEndpoint:            fmt.Sprintf("%s/fake/userinfo", issuer),
			DeviceAuthorizationEndpoint: fmt.Sprintf("%s/fake/deviceauth", issuer),
			RevocationEndpoint:          fmt.Sprintf("%s/fake/revoke", issuer),
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

type microsoftAccessTokenResponse struct {
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	AccessToken string `json:"access_token"`
}

// https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow#third-case-access-token-request-with-a-federated-credential
func getMicrosoftAccessToken(ctx context.Context, azureData azureAnnotations, internalToken string) (microsoftAccessTokenResponse, error) {
	data := url.Values{}
	data.Add("scope", azureData.scope)
	data.Add("client_id", azureData.clientId)
	data.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	data.Add("client_assertion", internalToken)
	data.Add("grant_type", "client_credentials")

	remoteUrl, err := url.Parse(fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", azureData.tenantId))
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

// ?Action=AssumeRoleWithWebIdentity
// &DurationSeconds=3600
// &PolicyArns.member.1.arn=arn:aws:iam::123456789012:policy/webidentitydemopolicy1
// &PolicyArns.member.2.arn=arn:aws:iam::123456789012:policy/webidentitydemopolicy2
// &ProviderId=www.amazon.com
// &RoleSessionName=app1
// &RoleArn=arn:aws:iam::123456789012:role/FederatedWebIdentityRole
// &WebIdentityToken=Atza%7CIQEBLjAsAhRFiXuWpUXuRvQ9PZL3GMFcYevydwIUFAHZwXZXX
// XXXXXXJnrulxKDHwy87oGKPznh0D6bEQZTSCzyoCtL_8S07pLpr0zMbn6w1lfVZKNTBdDansFB
// mtGnIsIapjI6xKR02Yc_2bQ8LZbUXSGm6Ry6_BG7PrtLZtj_dfCTj92xNGed-CrKqjG7nPBjNI
// L016GGvuS5gSvPRUxWES3VYfm1wl7WTI7jn-Pcb6M-buCgHhFOzTQxod27L9CqnOLio7N3gZAG
// psp6n1-AJBOCJckcyXe2c6uD0srOJeZlKUm2eTDVMf8IehDVI0r1QOnTV6KzzAI3OY87Vd_cVMQ
// &Version=2011-06-15

// FIXME: Needs to be finished
// https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html
func getAwsAccessToken(ctx context.Context, awsData awsAnnotations, internalToken string) (microsoftAccessTokenResponse, error) {
	data := url.Values{}
	data.Add("action", "AssumeRoleWithWebIdentity")
	data.Add("DurationSeconds", "3600")
	data.Add("PolicyArns.member.1.arn", awsData.roleArn)
	data.Add("ProviderId", "www.amazon.com")
	data.Add("action", "AssumeRoleWithWebIdentity")
	data.Add("action", "AssumeRoleWithWebIdentity")
	data.Add("action", "AssumeRoleWithWebIdentity")
	data.Add("action", "AssumeRoleWithWebIdentity")
	data.Add("action", "AssumeRoleWithWebIdentity")
	data.Add("action", "AssumeRoleWithWebIdentity")

	remoteUrl, err := url.Parse(fmt.Sprintf("https://sts.amazonaws.com/?querySholdBeHere"))
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

func (ts *tokenService) internalAzureTokenHttpHandler(jwks *jwksHandler, issuer string) gin.HandlerFunc {
	return func(c *gin.Context) {
		subject, err := getSubjectFromClaims(c)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		internalToken, err := newAccessToken(jwks, issuer, subject, "api://AzureADTokenExchange")
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		namespace, serviceAccount, err := getNamespaceAndServiceAccountFromSubject(subject)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		reqData, err := ts.kr.getAzureAnnotations(c.Request.Context(), namespace, serviceAccount)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		msToken, err := getMicrosoftAccessToken(c.Request.Context(), reqData, internalToken)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		c.JSON(http.StatusOK, msToken)
	}
}

func (ts *tokenService) internalAwsTokenHttpHandler(jwks *jwksHandler, issuer string) gin.HandlerFunc {
	return func(c *gin.Context) {
		subject, err := getSubjectFromClaims(c)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		internalToken, err := newAccessToken(jwks, issuer, subject, "api://AWSTokenExchange")
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		namespace, serviceAccount, err := getNamespaceAndServiceAccountFromSubject(subject)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		reqData, err := ts.kr.getAwsAnnotations(c.Request.Context(), namespace, serviceAccount)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		msToken, err := getAwsAccessToken(c.Request.Context(), reqData, internalToken)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		c.JSON(http.StatusOK, msToken)
	}
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
