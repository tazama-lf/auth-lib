import type { ClaimValidationResult, TazamaToken } from './interfaces/iTazamaToken';
import * as AuthProviderConfig from './services/providerHelper';
import * as JwtService from './services/jwtService';
import { TazamaAuthentication, type TazamaAuthProvider } from './services/tazamaAuthentication';
import { validateTokenAndClaims } from './services/tazamaService';
import { extractTenant } from './services/tenantService';

// Providers
export { AuthProviderConfig, JwtService, TazamaAuthentication };
export type { TazamaAuthProvider, TazamaToken };

// Clients
export { validateTokenAndClaims, extractTenant };
export type { ClaimValidationResult };
