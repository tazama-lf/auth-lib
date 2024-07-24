import { config as dotenv } from "dotenv";
import path from "path";

// Load .env file into process.env if it exists. This is convenient for running locally.
dotenv({
  path: path.resolve(__dirname, "../.env"),
});

interface IAuthConfig {
  authURL: string;
  keycloakRealm: string;
  certPath: string;
}

export const authConfig: IAuthConfig = {
  authURL: process.env.AUTH_URL as string,
  keycloakRealm: process.env.KEYCLOAK_REALM as string,
  certPath: process.env.CERT_PATH as string
};
