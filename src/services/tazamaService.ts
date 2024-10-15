import { type ClaimValidationResult } from '../interfaces/iTazamaToken';
import { verifyToken } from './jwtService';

/**
 * Validates a JWT token and checks if any of the supplied claims are present in the decoded token.
 * 
 * @param {string} token - The JWT token to be validated.
 * @param {string[]} claimList - An array of claims  to check against the decoded token.
 * @returns {ClaimValidationResult} - Returns key value pair of every claim provided in string:boolean format,
 * true if the claim is found in the token, otherwise false.
*/
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
