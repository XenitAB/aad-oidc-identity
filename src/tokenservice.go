package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
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

// https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow#third-case-access-token-request-with-a-federated-credential
func getMicrosoftAccessToken(ctx context.Context, azureData azureAnnotations, internalToken string) ([]byte, string, error) {
	data := url.Values{}
	data.Add("scope", azureData.scope)
	data.Add("client_id", azureData.clientId)
	data.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	data.Add("client_assertion", internalToken)
	data.Add("grant_type", "client_credentials")

	remoteUrl, err := url.Parse(fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", azureData.tenantId))
	if err != nil {
		return nil, "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, remoteUrl.String(), strings.NewReader(data.Encode()))
	if err != nil {
		return nil, "", err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, "", err
	}

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, "", err
	}

	defer res.Body.Close()

	if res.StatusCode != 200 {
		return nil, "", fmt.Errorf("received a non 200 status code: %d", res.StatusCode)
	}

	contentType := res.Header.Get("Content-Type")
	if contentType == "" {
		return nil, "", fmt.Errorf("content type header is empty")
	}

	return bodyBytes, contentType, nil
}

// https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html
func getAwsAccessToken(ctx context.Context, awsData awsAnnotations, internalToken string, subject string) ([]byte, string, error) {
	remoteUrl, err := url.Parse("https://sts.amazonaws.com/")
	if err != nil {
		return nil, "", err
	}

	query := url.Values{}
	query.Add("Action", "AssumeRoleWithWebIdentity")
	query.Add("DurationSeconds", "3600")
	query.Add("RoleSessionName", strings.ReplaceAll(subject, ":", "_"))
	query.Add("RoleArn", awsData.roleArn)
	query.Add("Version", "2011-06-15")
	query.Add("WebIdentityToken", internalToken)

	remoteUrl.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, remoteUrl.String(), nil)
	if err != nil {
		return nil, "", err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, "", err
	}

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, "", err
	}

	defer res.Body.Close()

	if res.StatusCode != 200 {
		return nil, "", fmt.Errorf("received a non 200 status code: %d", res.StatusCode)
	}

	contentType := res.Header.Get("Content-Type")
	if contentType == "" {
		return nil, "", fmt.Errorf("content type header is empty")
	}

	return bodyBytes, contentType, nil
}

// https://cloud.google.com/iam/docs/using-workload-identity-federation#authenticating_by_using_the_rest_api
func getGoogleAccessToken(ctx context.Context, googleData googleAnnotations, internalToken string, subject string, aud string) ([]byte, string, error) {
	stsReqBody := struct {
		Audience           string `json:"audience"`
		GrantType          string `json:"grantType"`
		RequestedTokenType string `json:"requestedTokenType"`
		Scope              string `json:"scope"`
		SubjectTokenType   string `json:"subjectTokenType"`
		SubjectToken       string `json:"subjectToken"`
	}{
		Audience:           strings.ReplaceAll(aud, "https://", "//"),
		GrantType:          "urn:ietf:params:oauth:grant-type:token-exchange",
		RequestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
		Scope:              googleData.scope,
		SubjectTokenType:   "urn:ietf:params:oauth:token-type:jwt",
		SubjectToken:       internalToken,
	}

	stsReqBodyJson, err := json.Marshal(stsReqBody)
	if err != nil {
		return nil, "", err
	}

	stsReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://sts.googleapis.com/v1/token", bytes.NewReader(stsReqBodyJson))
	if err != nil {
		return nil, "", err
	}

	stsReq.Header.Set("Content-Type", "text/json; charset=utf-8")

	stsRes, err := http.DefaultClient.Do(stsReq)
	if err != nil {
		return nil, "", err
	}

	stsBodyBytes, err := io.ReadAll(stsRes.Body)
	if err != nil {
		return nil, "", err
	}

	defer stsRes.Body.Close()

	if stsRes.StatusCode != 200 {
		return nil, "", fmt.Errorf("received a non 200 status code: %d", stsRes.StatusCode)
	}

	stsResBody := struct {
		AccessToken     string `json:"access_token"`
		IssuedTokenType string `json:"issued_token_type"`
		TokenType       string `json:"token_type"`
		ExpiresIn       int    `json:"expires_in"`
	}{}

	err = json.Unmarshal(stsBodyBytes, &stsResBody)
	if err != nil {
		return nil, "", err
	}

	remoteUrl, err := url.Parse(fmt.Sprintf("https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken", googleData.gsa))
	if err != nil {
		return nil, "", err
	}

	reqBody := struct {
		Scope []string `json:"scope"`
	}{
		Scope: []string{googleData.scope},
	}

	reqBodyJson, err := json.Marshal(reqBody)
	if err != nil {
		return nil, "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, remoteUrl.String(), bytes.NewReader(reqBodyJson))
	if err != nil {
		return nil, "", err
	}

	req.Header.Set("Content-Type", "text/json; charset=utf-8")
	req.Header.Set("Authorization", fmt.Sprintf("%s %s", stsResBody.TokenType, stsResBody.AccessToken))

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, "", err
	}

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, "", err
	}

	defer res.Body.Close()

	if res.StatusCode != 200 {
		return nil, "", fmt.Errorf("received a non 200 status code: %d", res.StatusCode)
	}

	contentType := res.Header.Get("Content-Type")
	if contentType == "" {
		return nil, "", fmt.Errorf("content type header is empty")
	}

	return bodyBytes, contentType, nil
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

		responseData, contentType, err := getMicrosoftAccessToken(c.Request.Context(), reqData, internalToken)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		c.Data(http.StatusOK, contentType, responseData)
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

		responseData, contentType, err := getAwsAccessToken(c.Request.Context(), reqData, internalToken, subject)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		c.Data(http.StatusOK, contentType, responseData)
	}
}

func (ts *tokenService) internalGoogleTokenHttpHandler(jwks *jwksHandler, issuer string) gin.HandlerFunc {
	return func(c *gin.Context) {
		subject, err := getSubjectFromClaims(c)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		namespace, serviceAccount, err := getNamespaceAndServiceAccountFromSubject(subject)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		reqData, err := ts.kr.getGoogleAnnotations(c.Request.Context(), namespace, serviceAccount)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		audience := fmt.Sprintf("https://iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/providers/%s", reqData.projectNumber, reqData.poolId, reqData.providerId)

		internalToken, err := newAccessToken(jwks, issuer, subject, audience)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		responseData, contentType, err := getGoogleAccessToken(c.Request.Context(), reqData, internalToken, subject, audience)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		c.Data(http.StatusOK, contentType, responseData)
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
