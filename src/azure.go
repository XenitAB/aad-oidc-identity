package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	azureClientIdAnnotationKey = "aad-oidc-identity.xenit.io/client-id"
	azureTenantIdAnnotationKey = "aad-oidc-identity.xenit.io/tenant-id"
	azureScopeAnnotationKey    = "aad-oidc-identity.xenit.io/scope"
)

type getDataFn func(ctx context.Context, namespace string, name string) (map[string]string, error)

type azureProvider struct {
	getData         getDataFn
	defaultTenantId string
	defaultScope    string
}

func (p *azureProvider) Validate() error {
	if p.getData == nil {
		return fmt.Errorf("azureProvider getData is nil")
	}

	if p.defaultTenantId == "" {
		return fmt.Errorf("azureProvider defaultTenantId is empty")
	}

	if p.defaultScope == "" {
		return fmt.Errorf("azureProvider defaultScope is empty")
	}

	return nil
}

func newAzureProvider(getData getDataFn, tenantId string) (*azureProvider, error) {
	p := &azureProvider{
		getData:         getData,
		defaultTenantId: tenantId,
		defaultScope:    "https://management.core.windows.net/.default",
	}

	err := p.Validate()
	if err != nil {
		return nil, err
	}

	return p, nil
}

type azureData struct {
	clientId string
	tenantId string
	scope    string
}

func (d *azureData) Validate() error {
	if d.clientId == "" {
		return fmt.Errorf("azure clientId is empty")
	}

	if d.tenantId == "" {
		return fmt.Errorf("azure tenantId is empty")
	}

	if d.scope == "" {
		return fmt.Errorf("azure scope is empty")
	}

	return nil
}

func (p *azureProvider) getProviderData(ctx context.Context, namespace string, name string) (azureData, error) {
	annotations, err := p.getData(ctx, namespace, name)
	if err != nil {
		return azureData{}, err
	}

	clientId, ok := annotations[azureClientIdAnnotationKey]
	if !ok {
		return azureData{}, fmt.Errorf("could not find annotation (%s) on service account", azureClientIdAnnotationKey)
	}

	tenantId, ok := annotations[azureTenantIdAnnotationKey]
	if !ok {
		tenantId = p.defaultTenantId
	}

	scope, ok := annotations[azureScopeAnnotationKey]
	if !ok {
		scope = p.defaultScope
	}

	data := azureData{
		clientId: clientId,
		tenantId: tenantId,
		scope:    scope,
	}

	err = data.Validate()
	if err != nil {
		return azureData{}, err
	}

	return data, nil
}

// https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow#third-case-access-token-request-with-a-federated-credential
func (p *azureProvider) getAccessToken(ctx context.Context, azureData azureData, internalToken string) ([]byte, string, error) {
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

func (p *azureProvider) httpHandler(jwks *jwksHandler, issuer string) gin.HandlerFunc {
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

		reqData, err := p.getProviderData(c.Request.Context(), namespace, serviceAccount)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		responseData, contentType, err := p.getAccessToken(c.Request.Context(), reqData, internalToken)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		c.Data(http.StatusOK, contentType, responseData)
	}
}
