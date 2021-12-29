package provider

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

type AzureProvider struct {
	data            dataGetter
	key             privateKeyGetter
	defaultTenantId string
	defaultScope    string
}

func (p *AzureProvider) validate() error {
	if p.data == nil {
		return fmt.Errorf("azureProvider data is nil")
	}

	if p.key == nil {
		return fmt.Errorf("azureProvider key is nil")
	}

	if p.defaultTenantId == "" {
		return fmt.Errorf("azureProvider defaultTenantId is empty")
	}

	if p.defaultScope == "" {
		return fmt.Errorf("azureProvider defaultScope is empty")
	}

	return nil
}

func NewAzureProvider(data dataGetter, key privateKeyGetter, tenantId string) (*AzureProvider, error) {
	p := &AzureProvider{
		data:            data,
		key:             key,
		defaultTenantId: tenantId,
		defaultScope:    "https://management.core.windows.net/.default",
	}

	err := p.validate()
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

func (d *azureData) validate() error {
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

func (p *AzureProvider) getProviderData(ctx context.Context, namespace string, name string) (azureData, error) {
	annotations, err := p.data.GetData(ctx, namespace, name)
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

	err = data.validate()
	if err != nil {
		return azureData{}, err
	}

	return data, nil
}

// https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow#third-case-access-token-request-with-a-federated-credential
func (p *AzureProvider) getAccessToken(ctx context.Context, azureData azureData, internalToken string) ([]byte, string, error) {
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

func (p *AzureProvider) NewHandlerFunc(issuer string) gin.HandlerFunc {
	return func(c *gin.Context) {
		subject, err := getSubjectFromClaims(c)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		internalToken, err := newAccessToken(p.key, issuer, subject, "api://AzureADTokenExchange")
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
