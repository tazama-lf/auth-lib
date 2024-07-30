import jwt, { JwtPayload } from 'jsonwebtoken';
import { AuthenticationService, validateTokenAndClaims } from '../../src';
import { authConfig } from '../../src/interfaces/iAuthConfig';

const mockKeycloakAuthToken = {
  access_token:
    'eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJacDJINEtReVBFUW9oMWQwRTVSZzdnaThBeUQzeGVLNWpPSjdTX3BBYkpFIn0.eyJleHAiOjE3MjIyNTU4ODMsImlhdCI6MTcyMjI1NTU4MywianRpIjoiYzZiZDc5NjQtZDRlZS00OWQ5LWFlYzktZTA3NWU1N2E2OTAxIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy90YXphbWEiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiM2U1ZjQ5MjYtYjVjMi00YjQ2LTk0OTItNjQwYzg1YTcwZDM5IiwidHlwIjoiQmVhcmVyIiwiYXpwIjoiYXV0aC1saWItY2xpZW50Iiwic2Vzc2lvbl9zdGF0ZSI6IjIxNTdiNjNhLTFjZWQtNDQ0Mi04YjNiLTMyZjg2OTFkYTdkNSIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiLyoiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIlBPU1RfVjFfRVZBTFVBVEVfSVNPMjAwMjJfUEFJTl8wMDFfMDAxXzExIiwiUE9TVF9WMV9FVkFMVUFURV9JU08yMDAyMl9QQUNTXzAwOF8wMDFfMTAiLCJQT1NUX1YxX0VWQUxVQVRFX0lTTzIwMDIyX1BBQ1NfMDAyXzAwMV8xMiIsImRlZmF1bHQtcm9sZXMtdGF6YW1hIiwib2ZmbGluZV9hY2Nlc3MiLCJQT1NUX1YxX0VWQUxVQVRFX0lTTzIwMDIyX1BBSU5fMDEzXzAwMV8wOSIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwic2lkIjoiMjE1N2I2M2EtMWNlZC00NDQyLThiM2ItMzJmODY5MWRhN2Q1IiwiZW1haWxfdmVyaWZpZWQiOnRydWUsInByZWZlcnJlZF91c2VybmFtZSI6InRhemFtYS11c2VyIiwiZW1haWwiOiJ0YXphbWEtdXNlckBleGFtcGxlLmNvbSJ9.V5r6U2pS80OeSVNKbXZzHyli2GD3oITki5FaQbTV8DtGm9SF8tE2E-8KvZ5I0mtH5m9VCmFNuaR_8ODol_obGiRG1R-1J_hajxEI_BgBybFByxOX5HQPUnr4xTZrHqtzbBk1tv711SrYuqJHhrslxCG1dE3CI32JXF-HhDoXTGllrkpWKiRfe9hrbQg52-X06buBeCcRT6FU860tq-NciXB73RkyBpKhRGaImt53xZyLb_lpz-ZOkD63euOvAUEJNQQdHG-VauHov6VixUAmLmps5havozh3998sX6vhtSnBnRQXfonLJowh6I4R2ibhkAYrJeokf_MBHqUwmv8I2g',
  refresh_token: 'TEST_REFRESH_TOKEN',
  token_type: 'Bearer',
  scope: 'TEST',
};

describe('App Services', () => {
  beforeEach(() => {
    authConfig.certPathPrivate = './private-key.pem';
    authConfig.certPathPublic = './public-key.pem';
    jest.spyOn(global, 'fetch').mockImplementation(() => Promise.resolve(new Response(JSON.stringify(mockKeycloakAuthToken))));
    jest.spyOn(jwt, 'verify').mockImplementation((x) => jwt.decode(x));
  });

  it('should handle getToken from AuthenticationService - happy path', async () => {
    const authService = new AuthenticationService();

    const authServiceSpy = jest.spyOn(authService, 'getToken');
    const token = await authService.getToken('testUser', 'testPassword');

    expect(authServiceSpy).toHaveBeenCalledTimes(1);
    expect(token).toBeDefined();
  });

  it('should handle getToken from AuthenticationService - no realm access', async () => {
    const mockKeycloakAuthTokenNoResourceAccess = {
      access_token:
        'eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3MjIyNTU4ODMsImlhdCI6MTcyMjI1NTU4MywianRpIjoiYzZiZDc5NjQtZDRlZS00OWQ5LWFlYzktZTA3NWU1N2E2OTAxIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy90YXphbWEiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiM2U1ZjQ5MjYtYjVjMi00YjQ2LTk0OTItNjQwYzg1YTcwZDM5IiwidHlwIjoiQmVhcmVyIiwiYXpwIjoiYXV0aC1saWItY2xpZW50Iiwic2Vzc2lvbl9zdGF0ZSI6IjIxNTdiNjNhLTFjZWQtNDQ0Mi04YjNiLTMyZjg2OTFkYTdkNSIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiLyoiXSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwic2lkIjoiMjE1N2I2M2EtMWNlZC00NDQyLThiM2ItMzJmODY5MWRhN2Q1IiwiZW1haWxfdmVyaWZpZWQiOnRydWUsInByZWZlcnJlZF91c2VybmFtZSI6InRhemFtYS11c2VyIiwiZW1haWwiOiJ0YXphbWEtdXNlckBleGFtcGxlLmNvbSJ9.pc2XBV060J-omkqji0ZzFPZCB5bA0yZh98p0IalNB6o',
      refresh_token: 'TEST_REFRESH_TOKEN',
      token_type: 'Bearer',
      scope: 'TEST',
    };

    jest
      .spyOn(global, 'fetch')
      .mockImplementationOnce(() => Promise.resolve(new Response(JSON.stringify(mockKeycloakAuthTokenNoResourceAccess))));

    const authService = new AuthenticationService();

    const authServiceSpy = jest.spyOn(authService, 'getToken');
    try {
      await authService.getToken('testUser', 'testPassword');
      throw new Error('UNREACHABLE');
    } catch (err) {
      expect(err).toEqual(new Error('No Roles configured for user'));
    }

    expect(authServiceSpy).toHaveBeenCalledTimes(1);
  });

  it('should handle getToken from AuthenticationService - bad cert', async () => {
    authConfig.certPathPrivate = '';

    const authService = new AuthenticationService();

    const authServiceSpy = jest.spyOn(authService, 'getToken');
    try {
      await authService.getToken('testUser', 'testPassword');
      throw new Error('UNREACHABLE');
    } catch (err) {
      expect(err).toEqual(new Error('Missing or Corrupted Private Key'));
    }

    expect(authServiceSpy).toHaveBeenCalledTimes(1);
  });

  it('should handle getToken from AuthenticationService - bad decode', async () => {
    jest.spyOn(jwt, 'decode').mockImplementation((x) => 'somestring');

    const authService = new AuthenticationService();

    const authServiceSpy = jest.spyOn(authService, 'getToken');
    try {
      await authService.getToken('testUser', 'testPassword');
      throw new Error('UNREACHABLE');
    } catch (err) {
      expect(err).toEqual(new Error('Token is in the wrong format, received string'));
    }

    expect(authServiceSpy).toHaveBeenCalledTimes(1);
  });

  it('should handle getToken from AuthenticationService - missing jwt properties', async () => {
    jest.spyOn(jwt, 'decode').mockImplementationOnce((x) => {
      return {
        sub: undefined,
        iss: undefined,
        exp: undefined,
      } as JwtPayload;
    });

    const authService = new AuthenticationService();

    const authServiceSpy = jest.spyOn(authService, 'getToken');
    try {
      await authService.getToken('testUser', 'testPassword');
      throw new Error('UNREACHABLE');
    } catch (err) {
      expect(err).toEqual(new Error('Token is missing required properties: sub: undefined, iss: undefined, exp: undefined'));
    }

    expect(authServiceSpy).toHaveBeenCalledTimes(1);

    jest.spyOn(jwt, 'decode').mockRestore();
  });

  it('should handle validateToken from TazamaService - happy path', async () => {
    const authService = new AuthenticationService();

    const token = await authService.getToken('tazama-user', 'password');

    const claims = ['default-roles-tazama', 'admin-panel'];

    const checkedClaims = validateTokenAndClaims(token, claims);

    expect(checkedClaims['default-roles-tazama']).toBeTruthy();
    expect(checkedClaims['admin-panel']).toBeFalsy();
  });

  it('should handle validateToken from TazamaService - wrong type', async () => {
    const authService = new AuthenticationService();

    const token = await authService.getToken('tazama-user', 'password');

    const claims = ['default-roles-tazama', 'admin-panel'];

    jest.spyOn(jwt, 'verify').mockImplementationOnce((x) => 'somestring');

    const checkedClaims = validateTokenAndClaims(token, claims);

    expect(checkedClaims['default-roles-tazama']).toBeFalsy();
    expect(checkedClaims['admin-panel']).toBeFalsy();
  });

  it('should handle validateToken from TazamaService - expired/invalid signature', async () => {
    const authService = new AuthenticationService();

    const token = await authService.getToken('tazama-user', 'password');

    const claims = ['default-roles-tazama', 'admin-panel'];

    jest.spyOn(jwt, 'verify').mockRestore();

    try {
      validateTokenAndClaims(token, claims);
      throw new Error('UNREACHABLE');
    } catch (err) {
      expect(err).toEqual(new Error('401 Unauthorized - token expired'));
    }
  });

  it('should handle validateToken from TazamaService - error', async () => {
    const authService = new AuthenticationService();

    const token = await authService.getToken('tazama-user', 'password');

    const claims = ['default-roles-tazama', 'admin-panel'];

    jest.spyOn(jwt, 'verify').mockImplementationOnce(() => {
      throw new Error('Test Error');
    });

    try {
      validateTokenAndClaims(token, claims);
      throw new Error('UNREACHABLE');
    } catch (err) {
      expect(err).toEqual(new Error('401 Unauthorized - Test Error'));
    }
  });
});
