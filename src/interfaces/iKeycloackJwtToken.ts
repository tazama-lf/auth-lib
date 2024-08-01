import { type JwtPayload } from 'jsonwebtoken';

export interface KeycloakJwtToken extends JwtPayload {
  resource_access?: Record<string, { roles: string[] }>;
  realm_access?: {
    roles: string[];
  };
}
