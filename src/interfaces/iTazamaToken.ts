import type jwt from 'jsonwebtoken';

interface TazamaToken extends jwt.JwtPayload {
  claims: string[];
  clientId: string;
  exp: number;
  iss: string;
  sid: string;
  tokenString: string;
}

type ClaimValidationResult = Record<string, boolean>;

export type { ClaimValidationResult, TazamaToken };

