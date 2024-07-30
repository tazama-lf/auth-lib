import { type JwtPayload } from 'jsonwebtoken';

export interface KeycloakJwtToken extends JwtPayload {
  realm_access?: {
    roles: string[];
  };
}
