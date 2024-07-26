import fs from "fs";
import jwt, { JwtPayload, TokenExpiredError } from "jsonwebtoken";
import { TazamaToken } from "../interfaces/iTazamaToken";
import { authConfig } from "../interfaces/iAuthConfig";

export function signToken(token: TazamaToken): string | Error | any {
  let privateKey;
  try {
    privateKey = fs.readFileSync(authConfig.certPath);
  } catch (error) {
    return error;
  }

  const signedToken = jwt.sign(token, privateKey, {
    algorithm: "RS256",
  });
  return signedToken;
}

export function verifyToken(signedToken: string) {
  const publicKey = fs.readFileSync(`./publickey.crt`);

  try {
    const verifyRes = jwt.verify(signedToken, publicKey);
    return verifyRes;
  } catch (error) {
    if (error instanceof TokenExpiredError) {
      console.error("401 Unauthorized - token expired");
    } else console.error("401 Unauthorized", error);
  }
}
