<!-- SPDX-License-Identifier: Apache-2.0 -->

# Auth-Lib

## Overview
Library used to get and validate tokens for Tazama.

## Installation

A personal access token is required to install this repository. For more information read the following.
https://docs.github.com/en/packages/learn-github-packages/about-permissions-for-github-packages#about-scopes-and-permissions-for-package-registries

Make sure you've got an .npmrc file in the root of your project, specifying where the @tazama-lf repo is. 
```
@tazama-lf:registry=https://npm.pkg.github.com
```

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

## Description

This TypeScript project involves authentication and token management using Keycloak and JSON Web Tokens (JWT). The main components include interfaces, services, and utility functions to handle tokens.

### src/services/authenticationFactory.ts
This file contains the `AuthenticationService` class which acts as a factory for creating instances of authentication services. It abstracts the creation logic and provides a unified interface for obtaining authentication services.

[src/services/authenticationFactory.ts]()

### src/services/keycloakService.ts
This file contains the KeycloakService class which implements the `IAuthenticationService` interface. It handles authentication with Keycloak and token generation. The main methods include:

 - `getToken`: Authenticates with Keycloak using a username and password to get a Keycloak token and then generates a TazamaToken.
 - `generateTazamaToken`: Decodes the Keycloak token and maps the associated claims to create a TazamaToken.
 - `mapTazamaRoles`: Extracts and maps the claims from the decoded Keycloak JWT token.

[src/services/keycloakService.ts]()

### src/services/jwtService.ts
This file contains utility functions for signing and verifying JWT tokens using private and public PEM files. The main functions include:

 - `signToken`: Signs a TazamaToken using a private PEM file with the RS256 algorithm.
 - `verifyToken`: Verifies a signed JWT token using a public PEM file and returns the decoded payload if verification is successful.

[src/services/jwtService.ts]()

### src/services/tazamaService.ts
This file contains utility functions for validating tokens and their claims. The main function includes:

 - `validateTokenAndClaims`: Validates a given token and checks if it contains the required claims.

[src/services/tazamaService.ts]()

### src/interfaces/iTazamaToken.ts
This file defines the TazamaToken interface which outlines the structure of a token. It includes properties like `exp` (expiration time), `sid` (session ID), `iss` (issuer), `tokenString`, `clientId`, and `claims` (an array of strings representing the token's claims). It also defines the ClaimValidationResult type.

[src/interfaces/iTazamaToken.ts]()

### src/interfaces/iKeycloakAuthToken.ts
This file defines the `KeycloakAuthToken` interface which outlines the structure of a Keycloak authentication token. It includes properties like `accessToken`, `tokenType`, and `refreshToken`.

[src/interfaces/iKeycloakAuthToken.ts]()

### src/interfaces/iAuthenticationService.ts
This file defines the `IAuthenticationService` interface which outlines the contract for an authentication service. It specifies methods like `getToken` and `generateTazamaToken`.

[src/interfaces/iAuthenticationService.ts]()

### src/index.ts
This file exports the main components of the library, including the `AuthenticationService` and `validateTokenAndClaims` function, as well as the `TazamaToken` type.

[src/interfaces/index.ts]()
