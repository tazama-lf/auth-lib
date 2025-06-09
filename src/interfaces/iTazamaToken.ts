interface TazamaToken {
  exp: number;
  sid: string;
  iss: string;
  tokenString: string;
  clientId: string;
  claims: string[];
}

type ClaimValidationResult = Record<string, boolean>;

export type { ClaimValidationResult, TazamaToken };
