import type { IAuthenticationService } from '../interfaces/iAuthenticationService';
import { KeycloakService } from './keycloakService';

export class AuthenticationService implements IAuthenticationService {
  private readonly authService: IAuthenticationService;

  constructor() {
    this.authService = new KeycloakService();
  }

  /**
   * Authenticates with the provided username and password via given authService
   * Generates a TazamaToken string embedded with claims pulled from the custom service
   *
   * @param {string} username - The username for authentication.
   * @param {string} password - The password for authentication.
   * @returns {Promise<string>} - A promise that resolves to a signed JWT token.
   */
  async getToken(username: string, password: string): Promise<string> {
    return await this.authService.getToken(username, password);
  }
}
