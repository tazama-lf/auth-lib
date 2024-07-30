import fs from 'fs';
import jwt, { TokenExpiredError } from 'jsonwebtoken';
import { authConfig } from '../interfaces/iAuthConfig';
import { type TazamaToken } from '../interfaces/iTazamaToken';

export function signToken(token: TazamaToken): string {
  let privateKey;
  try {
    privateKey = fs.readFileSync(authConfig.certPathPrivate);
  } catch (error) {
    throw new Error('Missing or Corrupted Private Key');
  }

  const signedToken = jwt.sign(token, privateKey, {
    algorithm: 'RS256',
  });
  return signedToken;
}

export function verifyToken(signedToken: string): string | jwt.JwtPayload | undefined {
  const publicKey = fs.readFileSync(authConfig.certPathPublic);

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
