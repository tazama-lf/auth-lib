import { IAuthenticationService } from "../interfaces/iAuthenticationService";
import { KeycloakService } from "./keycloakService";

export class AuthenticationService implements IAuthenticationService {
  private authService: IAuthenticationService;

  constructor() {
    this.authService = new KeycloakService();
  }

  async getToken(username: string, password: string) {
    return await this.authService.getToken(username, password);
  }
}
