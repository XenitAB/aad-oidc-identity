package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
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
	clientIdAnnotationKey = "aad-oidc-identity.xenit.io/client-id"
	tenantIdAnnotationKey = "aad-oidc-identity.xenit.io/tenant-id"
	scopeAnnotationKey    = "aad-oidc-identity.xenit.io/scope"
	defaultScope          = "https://management.core.windows.net/.default"
)

type kubeReader struct {
	kubeClient      kubernetes.Interface
	kubeConfig      *rest.Config
	httpClient      *http.Client
	defaultTenantId string
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
		kubeClient:      clientset,
		kubeConfig:      config,
		httpClient:      httpClient,
		defaultTenantId: cfg.DefaultTenantID,
	}, nil
}

func (k *kubeReader) getIssuer() (string, error) {
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

func (k *kubeReader) getHttpClient() *http.Client {
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

type requestData struct {
	clientId string
	tenantId string
	scope    string
}

func (k *kubeReader) getClientIDFromServiceAccount(ctx context.Context, namespace string, name string) (requestData, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	sa, err := k.kubeClient.CoreV1().ServiceAccounts(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return requestData{}, err
	}

	clientId, ok := sa.Annotations[clientIdAnnotationKey]
	if !ok {
		return requestData{}, fmt.Errorf("could not find annotation (%s) on service account", clientIdAnnotationKey)
	}

	tenantId, ok := sa.Annotations[tenantIdAnnotationKey]
	if !ok {
		tenantId = k.defaultTenantId
	}

	scope, ok := sa.Annotations[scopeAnnotationKey]
	if !ok {
		scope = defaultScope
	}

	return requestData{
		clientId: clientId,
		tenantId: tenantId,
		scope:    scope,
	}, nil
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
