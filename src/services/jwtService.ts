import fs from 'fs';
import jwt, { TokenExpiredError } from 'jsonwebtoken';
import { authLibConfig } from '../interfaces/iAuthLibConfig';
import { type TazamaToken } from '../interfaces/iTazamaToken';

/**
 * Signs the token using a private PEM file (RS256).
 *
 * @param {Token} token - The token to be signed.
 * @returns {string} - The signed JWT token.
 */
export function signToken(token: TazamaToken): string {
  let privateKey;
  try {
    privateKey = fs.readFileSync(authLibConfig.certPathPrivate);
  } catch (error) {
    throw new Error('Missing or Corrupted Private Key');
  }

  const signedToken = jwt.sign(token, privateKey, {
    algorithm: 'RS256',
  });
  return signedToken;
}

/**
 * Verifies the JWT token using a public PEM file.
 *
 * @param {string} signedToken - The signed JWT token to be verified.
 * @returns {string | jwt.JwtPayload | undefined} - The decoded payload if verification is successful, otherwise undefined.
 */
export function verifyToken(signedToken: string): string | jwt.JwtPayload | undefined {
  const publicKey = fs.readFileSync(authLibConfig.certPathPublic);

  try {
    const verifyRes = jwt.verify(signedToken, publicKey);
    return verifyRes;
  } catch (error) {
    if (error instanceof TokenExpiredError) {
      throw new Error('401 Unauthorized - token expired');
    } else {
      const err = error as Error;
      throw new Error(`401 Unauthorized - ${err.message}`);
    }
  }
}
