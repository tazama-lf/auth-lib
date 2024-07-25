import { verifyToken } from "./jwtService";

export function validateToken(token: string) {
  const decodedToken = verifyToken(token);
}
