# aad-oidc-identity
Proof of concept to see if it's possible to provide Azure tokens to PODs in a more secure manner than aad-pod-identity


## Testing

```shell
kubectl apply -f test/client-deployment.yaml
kubectl exec -it client /bin/sh
TOKEN=$(cat /var/run/secrets/tokens/oidc-token)
curl -v -H "Authorization: Bearer ${TOKEN}" -k http://aad-oidc-identity/internal/token
```

## Add custom federated identity

```shell
az rest --method POST --uri 'https://graph.microsoft.com/beta/applications/${APP_OBJECT_ID}/federatedIdentityCredentials' --body '{"name":"Testing","issuer":"${EXTERNAL_ISSUER}","subject":"system:serviceaccount:default:default","description":"Testing","audiences":["api://AzureADTokenExchange"]}' 
```