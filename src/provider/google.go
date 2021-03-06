package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	googleGSAAnnotationKey           = "aad-oidc-identity.xenit.io/gcp-service-account"
	googleProjectNumberAnnotationKey = "aad-oidc-identity.xenit.io/gcp-project-number"
	googlePoolIdAnnotationKey        = "aad-oidc-identity.xenit.io/gcp-pool-id"
	googleProviderIdAnnotationKey    = "aad-oidc-identity.xenit.io/gcp-provider-id"
	googleScopeAnnotationKey         = "aad-oidc-identity.xenit.io/gcp-scope"
)

type GoogleProvider struct {
	getServiceAccountInfo getServiceAccountInfoFn
	getPrivateKey         getPrivateKeyFn
	defaultProjectNumber  string
	defaultPoolId         string
	defaultProviderId     string
	defaultScope          string
}

func (p *GoogleProvider) validate() error {
	if p.defaultScope == "" {
		return fmt.Errorf("unabe to get google provider options: defaultScope is empty")
	}

	return nil
}

func NewGoogleProvider(setters ...Option) (*GoogleProvider, error) {
	opts, err := newOptions(setters...)
	if err != nil {
		return nil, fmt.Errorf("unable to get google provider options: %w", err)
	}

	p := &GoogleProvider{
		getServiceAccountInfo: opts.getServiceAccountInfo,
		getPrivateKey:         opts.getPrivateKey,
		defaultScope:          opts.googleDefaultScope,
		defaultProjectNumber:  opts.googleDefaultProjectNumber,
		defaultPoolId:         opts.googleDefaultPoolId,
		defaultProviderId:     opts.googleDefaultProviderId,
	}

	err = p.validate()
	if err != nil {
		return nil, err
	}

	return p, nil
}

type googleData struct {
	gsa           string
	projectNumber string
	poolId        string
	providerId    string
	scope         string
}

func (d *googleData) validate() error {
	if d.gsa == "" {
		return fmt.Errorf("google service account (gsa) is empty")
	}

	if d.projectNumber == "" {
		return fmt.Errorf("google projectNumber is empty")
	}

	if d.poolId == "" {
		return fmt.Errorf("google poolId is empty")
	}

	if d.providerId == "" {
		return fmt.Errorf("google providerId is empty")
	}

	if d.scope == "" {
		return fmt.Errorf("google scope is empty")
	}

	return nil
}

func (p *GoogleProvider) getProviderData(ctx context.Context, namespace string, name string) (googleData, error) {
	annotations, err := p.getServiceAccountInfo(ctx, namespace, name)
	if err != nil {
		return googleData{}, err
	}

	gsa, ok := annotations[googleGSAAnnotationKey]
	if !ok {
		return googleData{}, fmt.Errorf("could not find annotation (%s) on service account", googleGSAAnnotationKey)
	}

	projectNumber, ok := annotations[googleProjectNumberAnnotationKey]
	if !ok {
		projectNumber = p.defaultProjectNumber
	}

	poolId, ok := annotations[googlePoolIdAnnotationKey]
	if !ok {
		poolId = p.defaultPoolId
	}

	providerId, ok := annotations[googleProviderIdAnnotationKey]
	if !ok {
		poolId = p.defaultProviderId
	}

	scope, ok := annotations[googleScopeAnnotationKey]
	if !ok {
		poolId = p.defaultScope
	}

	data := googleData{
		gsa:           gsa,
		projectNumber: projectNumber,
		poolId:        poolId,
		providerId:    providerId,
		scope:         scope,
	}

	err = data.validate()
	if err != nil {
		return googleData{}, err
	}

	return data, nil
}

// https://cloud.google.com/iam/docs/using-workload-identity-federation#authenticating_by_using_the_rest_api
func (p *GoogleProvider) getAccessToken(ctx context.Context, googleData googleData, internalToken string, subject string, aud string) ([]byte, string, error) {
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
		return nil, "", fmt.Errorf("response code was %d: %s", res.StatusCode, string(bodyBytes))
	}

	contentType := res.Header.Get("Content-Type")
	if contentType == "" {
		return nil, "", fmt.Errorf("content type header is empty")
	}

	return bodyBytes, contentType, nil
}

func (p *GoogleProvider) GetToken(ctx context.Context, issuer string, subject string) ([]byte, string, error) {
	namespace, serviceAccount, err := getNamespaceAndServiceAccountFromSubject(subject)
	if err != nil {
		return nil, "", err
	}

	reqData, err := p.getProviderData(ctx, namespace, serviceAccount)
	if err != nil {
		return nil, "", err
	}

	audience := fmt.Sprintf("https://iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/providers/%s", reqData.projectNumber, reqData.poolId, reqData.providerId)

	internalToken, err := newAccessToken(p.getPrivateKey, issuer, subject, audience)
	if err != nil {
		return nil, "", err
	}

	return p.getAccessToken(ctx, reqData, internalToken, subject, audience)
}
