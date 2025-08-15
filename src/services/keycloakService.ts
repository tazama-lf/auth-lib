import jwt from 'jsonwebtoken';
import { authConfig } from '../interfaces/iAuthConfig';
import { type IAuthenticationService } from '../interfaces/iAuthenticationService';
import { type KeycloakJwtToken } from '../interfaces/iKeycloackJwtToken';
import { type KeycloakAuthToken } from '../interfaces/iKeycloakAuthToken';
import { type TazamaToken } from '../interfaces/iTazamaToken';
import { signToken } from './jwtService';

// Extended keycloak token interface to support tenant ID fields
interface KeycloakJwtTokenWithTenant extends KeycloakJwtToken {
  tenantId?: string;
  TENANT_ID?: string;
}

export class KeycloakService implements IAuthenticationService {
  realm: string;
  baseUrl: string;

  constructor() {
    this.realm = authConfig.keycloakRealm;
    this.baseUrl = authConfig.authURL;
  }

  /**
   * Authenticates with the provided username and password via KeyCloak to get a KeyCloak token
   * Generates a TazamaToken from the KeyCloak Token with added claims
   *
   * @param {string} username - The username for authentication.
   * @param {string} password - The password for authentication.
   * @returns {Promise<string>} - A promise that resolves to a signed JWT token.
  */
  async getToken(username: string, password: string): Promise<string> {
    const form = new URLSearchParams();
    form.append('client_id', authConfig.clientID);
    form.append('client_secret', authConfig.clientSecret);
    form.append('username', username);
    form.append('password', password);
    form.append('grant_type', 'password');

    const myHeaders = new Headers();
    myHeaders.append('Content-Type', 'application/x-www-form-urlencoded');

    const res = await fetch(`${this.baseUrl}/realms/${this.realm}/protocol/openid-connect/token`, {
      method: 'POST',
      body: form,
      headers: myHeaders,
      redirect: 'follow',
    });
    const resBody = JSON.parse(await res.text());
    const token: KeycloakAuthToken = {
      accessToken: resBody.access_token,
      tokenType: resBody.token_type,
      refreshToken: resBody.refresh_token,
    };

    return signToken(await this.generateTazamaToken(token));
  }

  /**
   * Decodes the given Keycloak authentication token and maps out the associated claims.
   *
   * @param {KeycloakAuthToken} authToken - The Keycloak authentication token to decode.
   * @returns {Promise<TazamaToken>} - A promise that resolves to a TazamaToken object containing the mapped claims.
  */
  async generateTazamaToken(authToken: KeycloakAuthToken): Promise<TazamaToken> {
    const decodedToken = jwt.decode(authToken.accessToken) as KeycloakJwtTokenWithTenant;

    if (!decodedToken || typeof decodedToken === 'string') {
      throw new Error(`Token is in the wrong format, received ${typeof decodedToken}`);
    }

    if (!decodedToken.sub || !decodedToken.iss || !decodedToken.exp) {
      throw new Error(`Token is missing required properties: sub: ${decodedToken.sub}, iss: ${decodedToken.iss}, exp: ${decodedToken.exp}`);
    }

    return {
      clientId: decodedToken.sub,
      iss: decodedToken.iss,
      sid: decodedToken.sid,
      exp: decodedToken.exp,
      tokenString: authToken.accessToken,
      tenantId: decodedToken.tenantId || decodedToken.TENANT_ID || 'DEFAULT', // Support both tenantId and TENANT_ID for backward compatibility
      claims: this.mapTazamaRoles(decodedToken),
    };
  }

  /**
   * Extracts and maps the claims from the decoded Keycloak JWT token.
   *
   * @param {KeycloakJwtToken} decodedToken - The decoded JWT token from Keycloak.
   * @returns {string[]} - An array of privileges extracted from the decoded token.
  */
  mapTazamaRoles(decodedToken: KeycloakJwtToken): string[] {
    const roles: string[] = [];

    for (const res in decodedToken.resource_access) {
      for (const role of decodedToken.resource_access[res].roles) {
        roles.push(role);
      }
    }

    if (decodedToken.realm_access) {
      for (const role of decodedToken.realm_access.roles) {
        roles.push(role);
      }
    }

    return roles;
  }
}
