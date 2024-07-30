import { type IAuthenticationService } from '../interfaces/iAuthenticationService';
import { KeycloakService } from './keycloakService';

export class AuthenticationService implements IAuthenticationService {
  private readonly authService: IAuthenticationService;

  constructor() {
    this.authService = new KeycloakService();
  }

  async getToken(username: string, password: string): Promise<string> {
    return await this.authService.getToken(username, password);
  }
}
