import { KeycloakAuthToken } from "./iKeycloakAuthToken";
import { TazamaToken } from "./iTazamaToken";

export interface IAuthenticationService {
  getToken: () => Promise<TazamaToken>;
  generateTazamaToken?: (KeycloakAuthToken: KeycloakAuthToken) => Promise<TazamaToken>
}
