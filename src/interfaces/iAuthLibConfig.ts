import { config as dotenv } from 'dotenv';
import path from 'node:path';

// Load .env file into process.env if it exists. This is convenient for running locally.
dotenv({
  path: path.resolve(__dirname, '../.env'),
});

interface IAuthLibConfig {
  certPathPrivate: string;
  certPathPublic: string;
}

const authLibConfig: IAuthLibConfig = {
  certPathPrivate: process.env.CERT_PATH_PRIVATE!,
  certPathPublic: process.env.CERT_PATH_PUBLIC!,
};

export { authLibConfig, type IAuthLibConfig };
