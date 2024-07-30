import { type ClaimValidationResult } from '../interfaces/iTazamaToken';
import { verifyToken } from './jwtService';

export function validateTokenAndClaims(token: string, claimList: string[]): ClaimValidationResult {
  const decodedToken = verifyToken(token);
  const claimResult: ClaimValidationResult = {};

  if (!decodedToken || typeof decodedToken === 'string') {
    claimList.forEach((claim) => (claimResult[claim] = false));
    return claimResult;
  }

  const claimsFromToken = decodedToken.claims;
  claimList.forEach((claim) => {
    claimResult[claim] = claimsFromToken.includes(claim);
  });

  return claimResult;
}
