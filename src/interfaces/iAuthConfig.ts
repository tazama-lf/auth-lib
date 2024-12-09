import { config as dotenv } from 'dotenv';
import path from 'path';

// Load .env file into process.env if it exists. This is convenient for running locally.
dotenv({
  path: path.resolve(__dirname, '../.env'),
});

interface IAuthConfig {
  authURL: string;
  keycloakRealm: string;
  certPathPrivate: string;
  certPathPublic: string;
  clientSecret: string;
  clientID: string;
}

export const authConfig: IAuthConfig = {
  authURL: process.env.AUTH_URL!,
  keycloakRealm: process.env.KEYCLOAK_REALM!,
  certPathPrivate: process.env.CERT_PATH_PRIVATE!,
  certPathPublic: process.env.CERT_PATH_PUBLIC!,
  clientSecret: process.env.CLIENT_SECRET!,
  clientID: process.env.CLIENT_ID!,
};
