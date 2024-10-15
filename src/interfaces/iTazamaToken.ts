export interface TazamaToken {
  exp: number;
  sid: string;
  iss: string;
  tokenString: string;
  clientId: string;
  claims: string[];
}

export type ClaimValidationResult = Record<string, boolean>;
