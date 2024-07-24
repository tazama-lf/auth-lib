import { IAuthenticationService } from "../interfaces/iAuthenticationService";
import { KeycloakService } from "./keycloakService";

export class AuthenticationService implements IAuthenticationService {
  authService: IAuthenticationService;

  constructor() {
    this.authService = new KeycloakService();
  }

  async getToken() {
    return await this.authService.getToken();
  }
}
