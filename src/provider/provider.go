package provider

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
)

// FIXME: Better name
type privateKeyGetter interface {
	GetPrivateKey() jwk.Key
}

// FIXME: Better name
type dataGetter interface {
	GetData(ctx context.Context, namespace string, name string) (map[string]string, error)
}

func newAccessToken(key privateKeyGetter, issuer string, subject string, aud string) (string, error) {
	privKey := key.GetPrivateKey()

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
