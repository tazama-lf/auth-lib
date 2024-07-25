import { KeycloakAuthToken } from "./iKeycloakAuthToken";
import { TazamaToken } from "./iTazamaToken";

export interface IAuthenticationService {
  getToken: (username: string, password: string) => Promise<string>;
  generateTazamaToken?: (KeycloakAuthToken: KeycloakAuthToken) => Promise<TazamaToken>
}
