<!-- SPDX-License-Identifier: Apache-2.0 -->

# Auth-Lib

## Overview
Library used to get and validate tokens for Tazama.

## Installation

A personal access token is required to install this repository. For more information read the following.
https://docs.github.com/en/packages/learn-github-packages/about-permissions-for-github-packages#about-scopes-and-permissions-for-package-registries

Thereafter you can run 
  > npm install @tazama-lf/auth-lib

## Usage

When Retrieving a token - Please note, the Auth-Service already does this. 

```
// Initialize the service
import { validateTokenAndClaims } from '@tazama-lf/auth-lib';
export const authService: AuthenticationService = new AuthenticationService();

// Get Token
const token = await authService.getToken(username, password);
```

Validating the token received against roles provided.
```
// Validate Roles
import { validateTokenAndClaims } from '@tazama-lf/auth-lib';
const validated = validateTokenAndClaims(token, ["POST_V1_EVALUATE_ISO20022_PAIN_001_001_11"]);
```

##### Environment variables

| Variable | Purpose | Example
| ------ | ------ | ------ |
| `AUTH_URL` | Base URL where KeyCloak is hosted | `https://keycloak.example.com:8080`
| `KEYCLOAK_REALM` | KeyCloak Realm for Tazama | `tazama`
| `CLIENT_ID` | KeyCloak defined client for auth-lib | `auth-lib-client`
| `CLIENT_SECRET` | The secret of the KeyCloak client | `someClientGeneratedSecret123`
| `CERT_PATH_PRIVATE` | The pem file path for signing Tazama tokens | `/path/to/private-key.pem`
| `CERT_PATH_PUBLIC` | The pem file path for validating Tazama tokens | `/path/to/public-key.pem`