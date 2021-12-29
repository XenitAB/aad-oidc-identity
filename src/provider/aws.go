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
	awsRoleArnAnnotationKey = "aad-oidc-identity.xenit.io/role-arn"
)

type AwsProvider struct {
	data dataGetter
	key  privateKeyGetter
}

func (p *AwsProvider) validate() error {
	if p.data == nil {
		return fmt.Errorf("awsProvider data is nil")
	}

	if p.key == nil {
		return fmt.Errorf("awsProvider key is nil")
	}

	return nil
}

func NewAwsProvider(data dataGetter, key privateKeyGetter) (*AwsProvider, error) {
	p := &AwsProvider{
		data: data,
		key:  key,
	}

	err := p.validate()
	if err != nil {
		return nil, err
	}

	return p, nil
}

type awsData struct {
	roleArn string
}

func (a *awsData) validate() error {
	if a.roleArn == "" {
		return fmt.Errorf("aws roleArn is empty")
	}
	return nil
}

func (p *AwsProvider) getProviderData(ctx context.Context, namespace string, name string) (awsData, error) {
	annotations, err := p.data.GetData(ctx, namespace, name)
	if err != nil {
		return awsData{}, err
	}

	roleArn, ok := annotations[awsRoleArnAnnotationKey]
	if !ok {
		return awsData{}, fmt.Errorf("could not find annotation (%s) on service account", awsRoleArnAnnotationKey)
	}

	data := awsData{
		roleArn: roleArn,
	}

	err = data.validate()
	if err != nil {
		return awsData{}, err
	}

	return data, nil
}

// https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html
func (p *AwsProvider) getAccessToken(ctx context.Context, awsData awsData, internalToken string, subject string) ([]byte, string, error) {
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
		return nil, "", fmt.Errorf("response code was %d: %s", res.StatusCode, string(bodyBytes))
	}

	contentType := res.Header.Get("Content-Type")
	if contentType == "" {
		return nil, "", fmt.Errorf("content type header is empty")
	}

	return bodyBytes, contentType, nil
}

func (p *AwsProvider) NewHandlerFunc(issuer string) gin.HandlerFunc {
	return func(c *gin.Context) {
		subject, err := getSubjectFromClaims(c)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		internalToken, err := newAccessToken(p.key, issuer, subject, "api://AWSTokenExchange")
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

		responseData, contentType, err := p.getAccessToken(c.Request.Context(), reqData, internalToken, subject)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		c.Data(http.StatusOK, contentType, responseData)
	}
}
