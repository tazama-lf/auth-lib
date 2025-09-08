import type { TazamaToken } from '../interfaces/iTazamaToken';
import { verifyToken } from './jwtService';

/**
 * Extracts tenant information from an authorization header or returns a default tenant.
 *
 * @param authenticated - Whether the request is authenticated
 * @param authorizationHeader - Optional authorization header containing the JWT token
 * @returns An object containing success status and optional tenantId
 *
 * @example
 * ```typescript
 * // For authenticated request with valid header
 * const result = extractTenant(true, "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...");
 * // Returns: { success: true, tenantId: "tenant123" }
 *
 * // For unauthenticated request
 * const result = extractTenant(false);
 * // Returns: { success: true, tenantId: "DEFAULT" }
 *
 * // For authenticated request without header
 * const result = extractTenant(true);
 * // Returns: { success: false }
 * ```
 *
 * @remarks
 * - If authenticated is false, returns success with 'DEFAULT' as tenantId
 * - If authenticated is true but no authorization header is provided, returns failure
 * - If authenticated is true and header is provided, extracts and verifies the JWT token
 * - Expects authorization header in format "Bearer <token>"
 */
export const extractTenant = (authenticated: boolean, authorizationHeader?: string): { success: boolean; tenantId?: string } => {
  if (authenticated) {
    if (!authorizationHeader) return { success: false };
    const token = authorizationHeader?.split(' ')[1];
    const decodedToken = verifyToken(token) as TazamaToken;
    return {
      success: true,
      tenantId: decodedToken.tenantId,
    };
  }
  return { success: true, tenantId: 'DEFAULT' };
};
