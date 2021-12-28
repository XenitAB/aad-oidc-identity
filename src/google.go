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

	"github.com/gin-gonic/gin"
)

type googleAnnotations struct {
	gsa           string
	projectNumber string
	poolId        string
	providerId    string
	scope         string
}

func (a *googleAnnotations) Validate() error {
	if a.gsa == "" {
		return fmt.Errorf("google service account (gsa) is empty")
	}

	if a.projectNumber == "" {
		return fmt.Errorf("google projectNumber is empty")
	}

	if a.poolId == "" {
		return fmt.Errorf("google poolId is empty")
	}

	if a.providerId == "" {
		return fmt.Errorf("google providerId is empty")
	}

	if a.scope == "" {
		return fmt.Errorf("google scope is empty")
	}

	return nil
}

func (k *kubeReader) getGoogleAnnotations(ctx context.Context, namespace string, name string) (googleAnnotations, error) {
	annotations, err := k.getServiceAccountAnnotations(ctx, namespace, name)
	if err != nil {
		return googleAnnotations{}, err
	}

	gsa, ok := annotations[googleGSAAnnotationKey]
	if !ok {
		return googleAnnotations{}, fmt.Errorf("could not find annotation (%s) on service account", googleGSAAnnotationKey)
	}

	projectNumber, ok := annotations[googleProjectNumberAnnotationKey]
	if !ok {
		projectNumber = k.defaultGoogleProjectNumber
	}

	poolId, ok := annotations[googlePoolIdAnnotationKey]
	if !ok {
		poolId = k.defaultGooglePoolId
	}

	providerId, ok := annotations[googleProviderIdAnnotationKey]
	if !ok {
		poolId = k.defaultGoogleProviderId
	}

	scope, ok := annotations[googleScopeAnnotationKey]
	if !ok {
		poolId = googleDefaultScope
	}

	ga := googleAnnotations{
		gsa:           gsa,
		projectNumber: projectNumber,
		poolId:        poolId,
		providerId:    providerId,
		scope:         scope,
	}

	err = ga.Validate()
	if err != nil {
		return googleAnnotations{}, err
	}

	return ga, nil
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
