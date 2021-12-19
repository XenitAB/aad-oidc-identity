# aad-oidc-identity
Proof of concept to see if it's possible to provide Azure tokens to PODs in a more secure manner than aad-pod-identity


## Testing

```shell
kubectl apply -f test/client-deployment.yaml
kubectl exec -it client /bin/sh
TOKEN=$(cat /var/run/secrets/tokens/oidc-token)
curl -v -H "Authorization: Bearer ${TOKEN}" -k http://aad-oidc-identity/internal/token
```