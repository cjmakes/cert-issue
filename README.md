# Cert Issuer
This is a service that issues users temporary ssh certificates to access
servers.

# Deploying
Set some env vars:

|---------------------|-------------------------------------------------------|
| Setting             | Notes                                                 |
|---------------------|-------------------------------------------------------|
| HTTP_ADDR           | Address for the server to listen on                   |
| HTTP_PORT           | Port for the server to listen on                      |
| GITHUB_ORG          | Org to check against                                  |
| GITHUB_TEAM         | Team to check against                                 |
| GITHUB_TOKEN        | Token to access github APIs                           |
| PRIVATE_KEY         | Private Keyh to issue certificates with               |
| PUBLIC_KEY          | Public key match the private key                      |
| CERT_DURATION_HOURS | How long certificates should be valid for in hours    |
|---------------------|-------------------------------------------------------|
