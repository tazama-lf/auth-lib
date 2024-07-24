import fs from "fs";
import jwt from "jsonwebtoken";
import { TazamaToken } from "../interfaces/iTazamaToken";
import { authConfig } from "../interfaces/iAuthConfig";

export function signToken(token: TazamaToken) : string | Error | any { 
    let privateKey;
    try {
        privateKey = fs.readFileSync(authConfig.certPath);
    } catch (error) {
        return error;    
    }

    const signedToken = jwt.sign(token, privateKey, { algorithm: 'RS256', expiresIn: '4s' });
    return signedToken;
}