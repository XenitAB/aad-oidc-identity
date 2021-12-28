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

type awsAnnotations struct {
	roleArn string
}

func (k *kubeReader) getAwsAnnotations(ctx context.Context, namespace string, name string) (awsAnnotations, error) {
	annotations, err := k.getServiceAccountAnnotations(ctx, namespace, name)
	if err != nil {
		return awsAnnotations{}, err
	}

	roleArn, ok := annotations[awsRoleArnAnnotationKey]
	if !ok {
		return awsAnnotations{}, fmt.Errorf("could not find annotation (%s) on service account", awsRoleArnAnnotationKey)
	}

	return awsAnnotations{
		roleArn: roleArn,
	}, nil
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
