package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	azureClientIdAnnotationKey       = "aad-oidc-identity.xenit.io/client-id"
	azureTenantIdAnnotationKey       = "aad-oidc-identity.xenit.io/tenant-id"
	azureScopeAnnotationKey          = "aad-oidc-identity.xenit.io/scope"
	azureDefaultScope                = "https://management.core.windows.net/.default"
	awsRoleArnAnnotationKey          = "aad-oidc-identity.xenit.io/role-arn"
	googleGSAAnnotationKey           = "aad-oidc-identity.xenit.io/gcp-service-account"
	googleProjectNumberAnnotationKey = "aad-oidc-identity.xenit.io/gcp-project-number"
	googlePoolIdAnnotationKey        = "aad-oidc-identity.xenit.io/gcp-pool-id"
	googleProviderIdAnnotationKey    = "aad-oidc-identity.xenit.io/gcp-provider-id"
	googleScopeAnnotationKey         = "aad-oidc-identity.xenit.io/gcp-scope"
	googleDefaultScope               = "https://www.googleapis.com/auth/cloud-platform"
)

type kubeReader struct {
	kubeClient           kubernetes.Interface
	kubeConfig           *rest.Config
	httpClient           *http.Client
	defaultAzureTenantId string

	// FIXME: Add config for these
	defaultGoogleProjectNumber string
	defaultGooglePoolId        string
	defaultGoogleProviderId    string
}

func newKubeReader(cfg config, kubeConfigPath string) (*kubeReader, error) {
	config, err := getKubeConfig(kubeConfigPath)
	if err != nil {
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	httpClient, err := newHttpClient(config)
	if err != nil {
		return nil, err
	}

	return &kubeReader{
		kubeClient:           clientset,
		kubeConfig:           config,
		httpClient:           httpClient,
		defaultAzureTenantId: cfg.DefaultTenantID,
	}, nil
}

func (k *kubeReader) getKubeIssuer() (string, error) {
	baseReqUrl := strings.TrimSuffix(k.kubeConfig.Host, "/")
	reqUrl := fmt.Sprintf("%s/.well-known/openid-configuration", baseReqUrl)
	req, err := http.NewRequest(http.MethodGet, reqUrl, nil)
	if err != nil {
		return "", err
	}

	res, err := k.httpClient.Do(req)
	if err != nil {
		return "", err
	}

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	defer res.Body.Close()

	var data struct {
		Issuer string `json:"issuer"`
	}

	err = json.Unmarshal(bodyBytes, &data)
	if err != nil {
		return "", err
	}

	return data.Issuer, nil
}

func (k *kubeReader) getKubeHttpClient() *http.Client {
	return k.httpClient
}

func newHttpClient(restConfig *rest.Config) (*http.Client, error) {
	caCert, err := ioutil.ReadFile(restConfig.TLSClientConfig.CAFile)
	if err != nil {
		return nil, fmt.Errorf("unable to extract ca certificate: %w", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	token, err := ioutil.ReadFile(restConfig.BearerTokenFile)
	if err != nil {
		return nil, fmt.Errorf("unable to extract kubernetes service account token: %w", err)
	}

	tlsClientConfig := &tls.Config{
		RootCAs: caCertPool,
	}

	transport := newAddHeaderTransport(&http.Transport{
		TLSClientConfig: tlsClientConfig,
	}, string(token))

	httpClient := &http.Client{
		Transport: transport,
	}

	return httpClient, nil
}

func (k *kubeReader) getCertificateFromSecret(ctx context.Context, namespace string, name string) (*rsa.PrivateKey, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	secret, err := k.kubeClient.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	certBytes, ok := secret.Data["tls.crt"]
	if !ok {
		return nil, fmt.Errorf("unable to extract 'tls.crt' from secret %s/%s", namespace, name)
	}

	keyBytes, ok := secret.Data["tls.key"]
	if !ok {
		return nil, fmt.Errorf("unable to extract 'tls.key' from secret %s/%s", namespace, name)
	}

	keyPem, _ := pem.Decode(keyBytes)
	if keyPem == nil {
		return nil, fmt.Errorf("unable to pem decode private key")
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(keyPem.Bytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(keyPem.Bytes); err != nil {
			return nil, fmt.Errorf("unable to parse private key")
		}
	}

	privateKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("unable to typecast to private key")

	}

	certPem, _ := pem.Decode(certBytes)
	if certPem == nil {
		return nil, fmt.Errorf("unable to pem decode public key")
	}

	parsedCert, err := x509.ParsePKIXPublicKey(certPem.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse RSA public key: %w", err)
	}

	publicKey, ok := parsedCert.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unable to typecast to public key")
	}

	privateKey.PublicKey = *publicKey

	return privateKey, nil
}

func (k *kubeReader) getServiceAccountAnnotations(ctx context.Context, namespace string, name string) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	sa, err := k.kubeClient.CoreV1().ServiceAccounts(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	return sa.Annotations, nil
}

type azureAnnotations struct {
	clientId string
	tenantId string
	scope    string
}

func (k *kubeReader) getAzureAnnotations(ctx context.Context, namespace string, name string) (azureAnnotations, error) {
	annotations, err := k.getServiceAccountAnnotations(ctx, namespace, name)
	if err != nil {
		return azureAnnotations{}, err
	}

	clientId, ok := annotations[azureClientIdAnnotationKey]
	if !ok {
		return azureAnnotations{}, fmt.Errorf("could not find annotation (%s) on service account", azureClientIdAnnotationKey)
	}

	tenantId, ok := annotations[azureTenantIdAnnotationKey]
	if !ok {
		tenantId = k.defaultAzureTenantId
	}

	scope, ok := annotations[azureScopeAnnotationKey]
	if !ok {
		scope = azureDefaultScope
	}

	return azureAnnotations{
		clientId: clientId,
		tenantId: tenantId,
		scope:    scope,
	}, nil
}

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

func getKubeConfig(kubeConfigPath string) (*rest.Config, error) {
	if kubeConfigPath != "" {
		return clientcmd.BuildConfigFromFlags("", kubeConfigPath)

	}
	return rest.InClusterConfig()
}

func newAddHeaderTransport(rt http.RoundTripper, token string) *addHeaderTransport {
	return &addHeaderTransport{
		rt:    rt,
		token: token,
	}
}

type addHeaderTransport struct {
	rt    http.RoundTripper
	token string
}

func (adt *addHeaderTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", adt.token))
	return adt.rt.RoundTrip(req)
}
