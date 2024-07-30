import jwt from 'jsonwebtoken';
import { authConfig } from '../interfaces/iAuthConfig';
import { type IAuthenticationService } from '../interfaces/iAuthenticationService';
import { type KeycloakJwtToken } from '../interfaces/iKeycloackJwtToken';
import { type KeycloakAuthToken } from '../interfaces/iKeycloakAuthToken';
import { type TazamaToken } from '../interfaces/iTazamaToken';
import { signToken } from './jwtService';

export class KeycloakService implements IAuthenticationService {
  realm: string;
  baseUrl: string;

  constructor() {
    this.realm = authConfig.keycloakRealm;
    this.baseUrl = authConfig.authURL;
  }

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

  async generateTazamaToken(authToken: KeycloakAuthToken): Promise<TazamaToken> {
    const decodedToken = jwt.decode(authToken.accessToken);

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
      claims: this.mapTazamaRoles(decodedToken),
    };
  }

  mapTazamaRoles(decodedToken: KeycloakJwtToken): string[] {
    if (!decodedToken.realm_access) {
      throw new Error('No Roles configured for user');
    }

    return decodedToken.realm_access.roles;
  }
}
