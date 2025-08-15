import { verifyToken } from './jwtService';
import type { TazamaToken } from '../interfaces/iTazamaToken';

export interface TenantValidationResult {
  success: boolean;
  tenantId?: string;
  error?: string;
  statusCode?: number;
}

export interface TenantValidationOptions {
  authenticated: boolean;
  defaultTenantId?: string;
  tenantIdHeader?: string;
}

// Extended token interface to support legacy TENANT_ID field for backward compatibility
interface TazamaTokenWithLegacy extends TazamaToken {
  TENANT_ID?: string;
}

/**
 * Extracts tenant ID from a TazamaToken, supporting both tenantId and TENANT_ID for backward compatibility
 * @param token - The decoded TazamaToken
 * @returns The extracted tenant ID or undefined if not found
 */
function extractTenantId(token: TazamaToken): string | undefined {
  const tokenWithLegacy = token as TazamaTokenWithLegacy;
  return token.tenantId || tokenWithLegacy.TENANT_ID;
}

/**
 * Validates and extracts tenant ID from JWT token or headers
 * @param authorizationHeader - The authorization header value (Bearer token)
 * @param options - Configuration options for tenant validation
 * @returns TenantValidationResult containing success status, tenantId, and error information
 */
export function validateAndExtractTenant(
  authorizationHeader?: string,
  options: TenantValidationOptions = { authenticated: true },
): TenantValidationResult {
  const { authenticated, defaultTenantId = 'DEFAULT', tenantIdHeader } = options;

  try {
    if (authenticated) {
      // Authenticated mode - extract from JWT token
      if (!authorizationHeader?.startsWith('Bearer ')) {
        return {
          success: false,
          error: 'Missing or invalid authorization header',
          statusCode: 401,
        };
      }

      const token = authorizationHeader.substring('Bearer '.length);

      try {
        const decodedToken = verifyToken(token);

        if (!decodedToken || typeof decodedToken === 'string') {
          return {
            success: false,
            error: 'Invalid JWT token',
            statusCode: 401,
          };
        }

        const tazamaToken = decodedToken;

        // Check for tenantId in the token (support both tenantId and TENANT_ID for backward compatibility)
        const tenantId = extractTenantId(tazamaToken);

        if (!tenantId || tenantId.trim() === '') {
          return {
            success: false,
            error: 'TENANT_ID attribute is required and cannot be blank',
            statusCode: 403,
          };
        }

        return {
          success: true,
          tenantId: tenantId.trim(),
        };
      } catch (jwtError) {
        const errorMessage = jwtError instanceof Error ? jwtError.message : String(jwtError);
        return {
          success: false,
          error: `Failed to decode JWT token: ${errorMessage}`,
          statusCode: 401,
        };
      }
    } else {
      // Unauthenticated mode - check for tenant ID in header or use default
      if (tenantIdHeader && tenantIdHeader.trim() !== '') {
        return {
          success: true,
          tenantId: tenantIdHeader.trim(),
        };
      } else {
        return {
          success: true,
          tenantId: defaultTenantId,
        };
      }
    }
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return {
      success: false,
      error: `Error in tenant validation: ${errorMessage}`,
      statusCode: 500,
    };
  }
}

/**
 * Validates a JWT token and extracts tenant ID
 * @param token - The JWT token string (without Bearer prefix)
 * @returns TenantValidationResult containing success status, tenantId, and error information
 */
export function validateTokenAndExtractTenant(token: string): TenantValidationResult {
  try {
    const decodedToken = verifyToken(token);

    if (!decodedToken || typeof decodedToken === 'string') {
      return {
        success: false,
        error: 'Invalid JWT token',
        statusCode: 401,
      };
    }

    const tazamaToken = decodedToken;

    // Check for tenantId in the token (support both tenantId and TENANT_ID for backward compatibility)
    const tenantId = extractTenantId(tazamaToken);

    if (!tenantId || tenantId.trim() === '') {
      return {
        success: false,
        error: 'TENANT_ID attribute is required and cannot be blank',
        statusCode: 403,
      };
    }

    return {
      success: true,
      tenantId: tenantId.trim(),
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return {
      success: false,
      error: `Failed to validate token and extract tenant: ${errorMessage}`,
      statusCode: 401,
    };
  }
}
