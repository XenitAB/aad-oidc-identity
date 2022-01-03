package key

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"sync"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
)

type KeyHandler struct {
	sync.RWMutex
	privateKeys []jwk.Key
	publicKeys  []jwk.Key
}

func NewHandler(setters ...Option) (*KeyHandler, error) {
	opts, err := newOptions(setters...)
	if err != nil {
		return nil, fmt.Errorf("unable to get key options: %w", err)
	}

	h := &KeyHandler{
		privateKeys: []jwk.Key{},
		publicKeys:  []jwk.Key{},
	}

	err = h.addJwkFromRsa(opts.rsaKey)
	if err != nil {
		return nil, err
	}

	return h, nil
}

func (h *KeyHandler) addJwkFromRsa(rsaKey *rsa.PrivateKey) error {
	key, err := jwk.New(rsaKey)
	if err != nil {
		return err
	}

	if _, ok := key.(jwk.RSAPrivateKey); !ok {
		return fmt.Errorf("expected jwk.RSAPrivateKey, got %T", key)
	}

	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return err
	}

	keyID := fmt.Sprintf("%x", thumbprint)
	err = key.Set(jwk.KeyIDKey, keyID)
	if err != nil {
		return err
	}

	pubKey, err := jwk.New(rsaKey.PublicKey)
	if err != nil {
		return err
	}

	if _, ok := pubKey.(jwk.RSAPublicKey); !ok {
		return fmt.Errorf("expected jwk.RSAPublicKey, got %T", key)
	}

	err = pubKey.Set(jwk.KeyIDKey, keyID)
	if err != nil {
		return err
	}

	// Error from Microsoft if not using 'RS256': {"error":"invalid_request","error_description":"AADSTS5002738: Invalid JWT token. 'ES384' is not a supported signature algorithm. Supported signing algorithms are: 'RS256, HS256'\r\nTrace ID: a798ea5f-df9a-4558-8618-21839c211600\r\nCorrelation ID: 81c2f6aa-de4a-464c-ae7c-a16511735188\r\nTimestamp: 2021-12-20 21:23:01Z","error_codes":[5002738],"timestamp":"2021-12-20 21:23:01Z","trace_id":"a798ea5f-df9a-4558-8618-21839c211600","correlation_id":"81c2f6aa-de4a-464c-ae7c-a16511735188","error_uri":"https://login.microsoftonline.com/error?code=5002738"}
	err = pubKey.Set(jwk.AlgorithmKey, jwa.RS256)
	if err != nil {
		return err
	}

	// Error from Microsoft: {"error":"invalid_client","error_description":"AADSTS700027: Client assertion contains an invalid signature. [Reason - The key was not found., Please visit the Azure Portal, Graph Explorer or directly use MS Graph to see configured keys for app Id '911f001c-650d-4b8e-97ac-e3a88ec20df9'. Review the documentation at https://docs.microsoft.com/en-us/graph/deployments to determine the corresponding service endpoint and https://docs.microsoft.com/en-us/graph/api/application-get?view=graph-rest-1.0&tabs=http to build a query request URL, such as 'https://graph.microsoft.com/beta/applications/911f001c-650d-4b8e-97ac-e3a88ec20df9'].\r\nTrace ID: 69614a63-47ba-4e4d-83ee-9ade62ff1600\r\nCorrelation ID: ae66f807-0e16-448b-b0f8-6a5d6e6bd334\r\nTimestamp: 2021-12-20 21:39:20Z","error_codes":[700027],"timestamp":"2021-12-20 21:39:20Z","trace_id":"69614a63-47ba-4e4d-83ee-9ade62ff1600","correlation_id":"ae66f807-0e16-448b-b0f8-6a5d6e6bd334","error_uri":"https://login.microsoftonline.com/error?code=700027"}
	err = pubKey.Set(jwk.KeyUsageKey, "sig")
	if err != nil {
		return err
	}

	h.Lock()

	h.privateKeys = append(h.privateKeys, key)
	h.publicKeys = append(h.publicKeys, pubKey)

	h.Unlock()

	return nil
}

func (h *KeyHandler) GetPrivateKey() jwk.Key {
	h.RLock()

	lastKeyIndex := len(h.privateKeys) - 1
	privKey := h.privateKeys[lastKeyIndex]

	h.RUnlock()

	return privKey
}

func (h *KeyHandler) GetPublicKeySet() jwk.Set {
	keySet := jwk.NewSet()

	h.RLock()

	for i := range h.publicKeys {
		keySet.Add(h.publicKeys[i])
	}

	h.RUnlock()

	return keySet
}
