import type { ClaimValidationResult, TazamaToken } from './interfaces/iTazamaToken';
import * as AuthProviderConfig from './services/providerHelper';
import * as JwtService from './services/jwtService';
import { TazamaAuthentication, type TazamaAuthProvider } from './services/tazamaAuthentication';
import { validateTokenAndClaims } from './services/tazamaService';
import {
  validateAndExtractTenant,
  validateTokenAndExtractTenant,
  type TenantValidationResult,
  type TenantValidationOptions,
} from './services/tenantService';

// Providers
export { AuthProviderConfig, JwtService, TazamaAuthentication };
export type { TazamaAuthProvider, TazamaToken };

// Clients
export { validateTokenAndClaims, validateAndExtractTenant, validateTokenAndExtractTenant };
export type { ClaimValidationResult, TenantValidationResult, TenantValidationOptions };
