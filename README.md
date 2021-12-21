# aad-oidc-identity
**PLEASE NOTE**: This is a pre-alpha proof of concept. The name is just a placeholder for something meaningful in the future and borrowed from [aad-pod-identity](https://github.com/Azure/aad-pod-identity).

This proof of concept aims to showcase the new federated identity credentials in Azure AD working together with Service Account Token Volume Projection and Service Account Issuer Discovery in Kubernetes to create a secure way for applications to get Azure AD tokens, kind of like [IRSA](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html).

## POC TODO

- [x] Initial project setup
- [x] Service Account Issuer Discovery with go-oidc-middleware
- [x] External endpoint for OIDC Metadata (`/external/.well-known/openid-configuration`)
- [x] External endpoint for JWKs (`/external/jwks`)
- [x] Request Azure AD access tokens using federated identity credentials with JWT created with JWK
- [x] Internal endpoint for token switching from Kubernetes JWT to Azure AD JWT (`/internal/token`)
- [x] Create a small overview diagram
- [x] Document the flow to showcase the functionality
- [ ] Add support for Client ID discovery through annotation
- [ ] Add support for Tenant ID discovery through annotation (?)
- [ ] Add support to request different scopes

## Overview

### High level diagram

![overview](assets/overview.png)

### Flow

1. Azure AD app is created and [federated identity credentials](https://docs.microsoft.com/en-us/graph/api/resources/federatedidentitycredentials-overview?view=graph-rest-beta) is configured
   ```bash
   AZ_APP_OBJECT_ID=$(az ad app show --id 00000000-0000-0000-0000-000000000000 --output tsv --query objectId)
   az rest --method POST --uri 'https://graph.microsoft.com/beta/applications/${AZ_APP_OBJECT_ID}/federatedIdentityCredentials' --body '{"name":"AKSCluster","issuer":"https://aks-oidc.domain.com/external","subject":"system:serviceaccount:team1:team1","description":"AKS Cluster authentication with aad-oidc-identity","audiences":["api://AzureADTokenExchange"]}' 
   ```
2. Service account is created with an annotation for the client id
   ```yaml
   apiVersion: v1
   kind: ServiceAccount
   metadata:
     annotations:
       aad-oidc-identity.xenit.io/client-id: 00000000-0000-0000-0000-000000000000
     namespace: team1
     name: team1
   ```
3. A pod is created using the service account and [Service Account Token Volume Projection](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#service-account-token-volume-projection)
   ```yaml
   apiVersion: v1
   kind: Pod
   metadata:
     name: app
     namespace: team1
   spec:
     serviceAccountName: team1
     containers:
       - image: nginx:alpine
         name: app
         volumeMounts:
           - mountPath: /var/run/secrets/tokens
             name: oidc-token
     volumes:
       - name: oidc-token
         projected:
           sources:
             - serviceAccountToken:
                 path: oidc-token
                 expirationSeconds: 7200
                 audience: aad-oidc-identity
   ```
4. The pod (app) requests a token from aad-oidc-identity
   ```bash
   TOKEN=$(cat /var/run/secrets/tokens/oidc-token)
   curl -H "Authorization: Bearer ${TOKEN}" -k http://aad-oidc-identity/internal/token
   ```

   *Note: future iterations may include what scopes are requested here.*
5. aad-oidc-identity receives the request and validates the token using [Service Account Issuer Discovery](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#service-account-issuer-discovery)
6. *NOT IMPLEMENTED YET:* Get Client ID (and Tenant ID if available - maybe even *scopes* if not included in the request) through the Kubernetes API from the Service Account
7. aad-oidc-identity creates a JWT (with the sub `system:serviceaccount:team1:team1`) and signs it with its own JWK
8. aad-oidc-identity sends the new JWT using the [Client Credentials Grant Flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow#third-case-access-token-request-with-a-federated-credential) to Azure AD
9. Azure AD goes out to the OIDC Discovery Endpoint (metadata) based on the configured `issuer`, `https://aks-oidc.domain.com/external/.well-known/openid-configuration`, and grabs the `jwks_uri` from the JSON response
10. Azure AD goes out to the `jwks_uri`, `https://aks-oidc.domain.com/external/jwks`, and downloads the public key(s)
11. Azure AD validates the token based on the downloaded public key(s) and if valid issues an Azure AD access token
12. aad-oidc-identity receives the Azure AD access token and responds with it to the pod (app)
13. The pod now has an Azure AD access token that it can use for whatever tasks needed 

## Development
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