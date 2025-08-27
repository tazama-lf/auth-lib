import jwt, { JwtPayload, TokenExpiredError } from 'jsonwebtoken';
import { TazamaAuthentication, TazamaAuthProvider, TazamaToken, validateTokenAndClaims } from '../../src';
import { authLibConfig } from '../../src/interfaces/iAuthLibConfig';
import { signToken } from '../../src/services/jwtService';
import * as ProviderHelper from '../../src/services/providerHelper';
import { validateAndExtractTenant, validateTokenAndExtractTenant } from '../../src/services/tenantService';

const mockAuthToken = {
  access_token:
    'eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJacDJINEtReVBFUW9oMWQwRTVSZzdnaThBeUQzeGVLNWpPSjdTX3BBYkpFIn0.eyJleHAiOjE3MjIyNTU4ODMsImlhdCI6MTcyMjI1NTU4MywianRpIjoiYzZiZDc5NjQtZDRlZS00OWQ5LWFlYzktZTA3NWU1N2E2OTAxIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy90YXphbWEiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiM2U1ZjQ5MjYtYjVjMi00YjQ2LTk0OTItNjQwYzg1YTcwZDM5IiwidHlwIjoiQmVhcmVyIiwiYXpwIjoiYXV0aC1saWItY2xpZW50Iiwic2Vzc2lvbl9zdGF0ZSI6IjIxNTdiNjNhLTFjZWQtNDQ0Mi04YjNiLTMyZjg2OTFkYTdkNSIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiLyoiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIlBPU1RfVjFfRVZBTFVBVEVfSVNPMjAwMjJfUEFJTl8wMDFfMDAxXzExIiwiUE9TVF9WMV9FVkFMVUFURV9JU08yMDAyMl9QQUNTXzAwOF8wMDFfMTAiLCJQT1NUX1YxX0VWQUxVQVRFX0lTTzIwMDIyX1BBQ1NfMDAyXzAwMV8xMiIsImRlZmF1bHQtcm9sZXMtdGF6YW1hIiwib2ZmbGluZV9hY2Nlc3MiLCJQT1NUX1YxX0VWQUxVQVRFX0lTTzIwMDIyX1BBSU5fMDEzXzAwMV8wOSIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwic2lkIjoiMjE1N2I2M2EtMWNlZC00NDQyLThiM2ItMzJmODY5MWRhN2Q1IiwiZW1haWxfdmVyaWZpZWQiOnRydWUsInByZWZlcnJlZF91c2VybmFtZSI6InRhemFtYS11c2VyIiwiZW1haWwiOiJ0YXphbWEtdXNlckBleGFtcGxlLmNvbSJ9.V5r6U2pS80OeSVNKbXZzHyli2GD3oITki5FaQbTV8DtGm9SF8tE2E-8KvZ5I0mtH5m9VCmFNuaR_8ODol_obGiRG1R-1J_hajxEI_BgBybFByxOX5HQPUnr4xTZrHqtzbBk1tv711SrYuqJHhrslxCG1dE3CI32JXF-HhDoXTGllrkpWKiRfe9hrbQg52-X06buBeCcRT6FU860tq-NciXB73RkyBpKhRGaImt53xZyLb_lpz-ZOkD63euOvAUEJNQQdHG-VauHov6VixUAmLmps5havozh3998sX6vhtSnBnRQXfonLJowh6I4R2ibhkAYrJeokf_MBHqUwmv8I2g',
  refresh_token: 'TEST_REFRESH_TOKEN',
  token_type: 'Bearer',
  scope: 'TEST',
};

describe('Tazama Providers', () => {
  it('should be able to create provider from TestProvider with one argument [string]', async () => {
    class TestProvider implements TazamaAuthProvider<[string]> {
      async getToken(testArg: string): Promise<string> {
        const simulatedjwtSign = (payload: string): string => {
          const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
          const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
          const testSignature = Buffer.from('test-signature').toString('base64url');

          return `${header}.${encodedPayload}.${testSignature}`;
        };
        return simulatedjwtSign(testArg);
      }
    }

    const provider = new TestProvider();

    const providerSpy = jest.spyOn(provider, 'getToken');
    const token = await provider.getToken('testCredential');

    expect(providerSpy).toHaveBeenCalledTimes(1);
    expect(token).toBeDefined();
  });

  it('should be able to create provider from TestProvider with two arguments [string, string]', async () => {
    class TestProvider implements TazamaAuthProvider<[string, string]> {
      async getToken(testArg1: string, testArg2: string): Promise<string> {
        const simulatedjwtSign = (payload: string): string => {
          const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
          const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
          const testSignature = Buffer.from('test-signature').toString('base64url');

          return `${header}.${encodedPayload}.${testSignature}`;
        };
        return simulatedjwtSign(`${testArg1}${testArg2}`);
      }
    }

    const provider = new TestProvider();

    const providerSpy = jest.spyOn(provider, 'getToken');
    const token = await provider.getToken('testUser', 'testPass');

    expect(providerSpy).toHaveBeenCalledTimes(1);
    expect(token).toBeDefined();
  });

  it('should be able to create provider from TestProvider with two arguments [string, number]', async () => {
    class TestProvider implements TazamaAuthProvider<[string, number]> {
      async getToken(testStrArg: string, testNumArg: number): Promise<string> {
        const simulatedjwtSign = (payload: string): string => {
          const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
          const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
          const testSignature = Buffer.from('test-signature').toString('base64url');

          return `${header}.${encodedPayload}.${testSignature}`;
        };
        return simulatedjwtSign(`${testStrArg}${testNumArg}`);
      }
    }

    const provider = new TestProvider();

    const providerSpy = jest.spyOn(provider, 'getToken');
    const token = await provider.getToken('testUser', 12345);

    expect(providerSpy).toHaveBeenCalledTimes(1);
    expect(token).toBeDefined();
  });
});

describe('App Services', () => {
  class TestProvider implements TazamaAuthProvider<[string]> {
    async getToken(testArg: string): Promise<string> {
      // simulate jwt sign
      const simulatedjwtSign = (payload: string): string => {
        const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
        const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
        const testSignature = Buffer.from('test-signature').toString('base64url');

        return `${header}.${encodedPayload}.${testSignature}`;
      };

      return simulatedjwtSign(testArg);
    }
  }

  beforeEach(() => {
    authLibConfig.certPathPrivate = './private-key.pem';
    authLibConfig.certPathPublic = './public-key.pem';
    jest.spyOn(global, 'fetch').mockImplementation(() => Promise.resolve(new Response(JSON.stringify(mockAuthToken))));
    jest.spyOn(jwt, 'verify').mockImplementation((x) => jwt.decode(x));
  });

  it('should handle TazamaAuthentication creation - no config provided', async () => {
    const authService = new TazamaAuthentication();

    const authServiceConfigSpy = jest.spyOn(authService, 'getConfigured');

    const configured = authService.getConfigured();

    expect(authServiceConfigSpy).toHaveReturnedWith([]);
    expect(configured).toEqual([]);
  });

  it('should handle TazamaAuthentication creation - config provided', async () => {
    const providerConfig = ['test'];

    const authService = new TazamaAuthentication(providerConfig);

    const authServiceConfigSpy = jest.spyOn(authService, 'getConfigured');

    const configured = authService.getConfigured();

    expect(authServiceConfigSpy).toHaveReturnedWith(providerConfig);
    expect(configured).toEqual(providerConfig);
  });

  it('should handle TazamaAuthentication creation - no config provided', async () => {
    const authService = new TazamaAuthentication();

    const authServiceConfigSpy = jest.spyOn(authService, 'getConfigured');
    const authServiceInitSpy = jest.spyOn(authService, 'init');

    try {
      await authService.init();
      throw new Error('UNREACHABLE');
    } catch (err) {
      expect(err).toEqual(new Error('No Provider Config'));
    }

    const configured = authService.getConfigured();

    expect(authServiceInitSpy).toHaveBeenCalledTimes(1);
    expect(authServiceConfigSpy).toHaveBeenCalledTimes(1);
    expect(configured).toEqual([]);
  });

  it('should handle TazamaAuthentication creation - provider configured twice', async () => {
    const providerConfig = ['test'];

    const authService = new TazamaAuthentication(providerConfig);

    const authServiceConfigSpy = jest.spyOn(authService, 'getConfigured');

    const isConfiguredTwice = authService.configureProvider('test');
    const configured = authService.getConfigured();

    expect(authServiceConfigSpy).toHaveReturnedWith(providerConfig);
    expect(configured).toEqual(providerConfig);
    expect(isConfiguredTwice).toEqual(false);
  });

  it('should contain configured and registered provider if valid provider passed to TazamaAuthentication constructor', async () => {
    const testProviderName = 'testProvider';

    const authService = new TazamaAuthentication([testProviderName]);
    const authServiceGetConfigSpy = jest.spyOn(authService, 'getConfigured');
    const authServiceGetRegisterSpy = jest.spyOn(authService, 'getRegistered');
    const authServiceGetInstanceSpy = jest.spyOn(authService, 'getInstances');

    const registerSpy = jest.spyOn(authService, 'registerProvider').mockImplementation((x: string) => {
      const provider = TestProvider.prototype;
      authService.providerRegistry.set(x, provider.constructor);
      return Promise.resolve(true);
    });

    let configured;
    let registered;
    let instances;

    try {
      authService.configureProvider(testProviderName);
      await authService.registerProvider(testProviderName);

      configured = authService.getConfigured();
      registered = authService.getRegistered();
      instances = authService.getInstances();
    } catch (err) {
      // Unreachable
      expect(true).toEqual(false);
    }

    expect(registerSpy).toHaveBeenCalledTimes(1);

    expect(authServiceGetConfigSpy).toHaveReturnedWith([testProviderName]);
    expect(configured).toEqual([testProviderName]);

    expect(authServiceGetRegisterSpy).toHaveReturnedWith([testProviderName]);
    expect(registered).toEqual([testProviderName]);

    expect(authServiceGetInstanceSpy).toHaveReturnedWith([] as string[]);
    expect(instances).toEqual([]);
  });

  it('should handle instantiateProvider given valid provider', async () => {
    const testProviderName = 'testProvider';

    const authService = new TazamaAuthentication([testProviderName]);
    const authServiceGetConfigSpy = jest.spyOn(authService, 'getConfigured');
    const authServiceGetRegisterSpy = jest.spyOn(authService, 'getRegistered');
    const authServiceGetInstanceSpy = jest.spyOn(authService, 'getInstances');

    const registerSpy = jest.spyOn(authService, 'registerProvider').mockImplementation((x: string) => {
      const provider = TestProvider.prototype;
      authService.providerRegistry.set(x, provider.constructor);
      return Promise.resolve(true);
    });

    const authServiceInstanceSpy = jest.spyOn(authService, 'instantiateProvider');

    let configured;
    let registered;
    let instances;
    let isInstantiated;

    try {
      authService.configureProvider(testProviderName);
      await authService.registerProvider(testProviderName);
      isInstantiated = authService.instantiateProvider(testProviderName);

      configured = authService.getConfigured();
      registered = authService.getRegistered();
      instances = authService.getInstances();
    } catch (err) {
      // Unreachable
      expect(true).toEqual(false);
    }

    expect(registerSpy).toHaveBeenCalledTimes(1);

    expect(isInstantiated).toEqual(true);

    expect(authServiceGetConfigSpy).toHaveReturnedWith([testProviderName]);
    expect(configured).toEqual([testProviderName]);

    expect(authServiceGetRegisterSpy).toHaveReturnedWith([testProviderName]);
    expect(registered).toEqual([testProviderName]);

    expect(authServiceGetInstanceSpy).toHaveReturnedWith([testProviderName]);
    expect(instances).toEqual([testProviderName]);

    expect(authServiceInstanceSpy).toHaveBeenCalledTimes(1);
  });

  it('should handle instantiateProvider given valid provider - instantiated twice', async () => {
    const testProviderName = 'testProvider';

    const authService = new TazamaAuthentication([testProviderName]);
    const authServiceGetConfigSpy = jest.spyOn(authService, 'getConfigured');
    const authServiceGetRegisterSpy = jest.spyOn(authService, 'getRegistered');
    const authServiceGetInstanceSpy = jest.spyOn(authService, 'getInstances');

    const registerSpy = jest.spyOn(authService, 'registerProvider').mockImplementation((x: string) => {
      const provider = TestProvider.prototype;
      authService.providerRegistry.set(x, provider.constructor);
      return Promise.resolve(true);
    });

    const authServiceInstanceSpy = jest.spyOn(authService, 'instantiateProvider');

    let configured;
    let registered;
    let instances;
    let isInstantiatedFirstTime;
    let isInstantiatedSecondTime;

    try {
      authService.configureProvider(testProviderName);
      await authService.registerProvider(testProviderName);

      isInstantiatedFirstTime = authService.instantiateProvider(testProviderName);
      isInstantiatedSecondTime = authService.instantiateProvider(testProviderName);

      configured = authService.getConfigured();
      registered = authService.getRegistered();
      instances = authService.getInstances();
    } catch (err) {
      // Unreachable
      expect(true).toEqual(false);
    }

    expect(registerSpy).toHaveBeenCalledTimes(1);

    expect(authServiceGetConfigSpy).toHaveReturnedWith([testProviderName]);
    expect(configured).toEqual([testProviderName]);

    expect(authServiceGetRegisterSpy).toHaveReturnedWith([testProviderName]);
    expect(registered).toEqual([testProviderName]);

    expect(authServiceGetInstanceSpy).toHaveReturnedWith([testProviderName]);
    expect(instances).toEqual([testProviderName]);

    expect(authServiceInstanceSpy).toHaveBeenCalledTimes(2);

    expect(isInstantiatedFirstTime).toEqual(true);
    expect(isInstantiatedSecondTime).toEqual(false);
  });

  it('should handle instantiateProvider given invalid provider constructor', async () => {
    const testProviderName = 'testProvider';

    const authService = new TazamaAuthentication([testProviderName]);
    const authServiceGetConfigSpy = jest.spyOn(authService, 'getConfigured');
    const authServiceGetRegisterSpy = jest.spyOn(authService, 'getRegistered');
    const authServiceGetInstanceSpy = jest.spyOn(authService, 'getInstances');

    const registerSpy = jest.spyOn(authService, 'registerProvider').mockImplementation((x: string) => {
      authService.providerRegistry.set(x, {});
      return Promise.resolve(true);
    });

    const authServiceInstanceSpy = jest.spyOn(authService, 'instantiateProvider');

    let configured;
    let registered;
    let instances;

    try {
      authService.configureProvider(testProviderName);
      await authService.registerProvider(testProviderName);

      authService.instantiateProvider(testProviderName);
      throw new Error('UNREACHABLE');
    } catch (err) {
      // Unreachable
      expect(err).toEqual(new TypeError('providerConstructor is not a constructor'));
    }

    configured = authService.getConfigured();
    registered = authService.getRegistered();
    instances = authService.getInstances();

    expect(registerSpy).toHaveBeenCalledTimes(1);

    expect(authServiceGetConfigSpy).toHaveReturnedWith([testProviderName]);
    expect(configured).toEqual([testProviderName]);

    expect(authServiceGetRegisterSpy).toHaveReturnedWith([testProviderName]);
    expect(registered).toEqual([testProviderName]);

    expect(authServiceGetInstanceSpy).toHaveReturnedWith([]);
    expect(instances).toEqual([]);

    expect(authServiceInstanceSpy).toHaveBeenCalledTimes(1);
  });

  it('should handle instantiateProvider - no registered provider', async () => {
    const testProviderName = 'test';

    const authService = new TazamaAuthentication([testProviderName]);

    const authServiceInstanceSpy = jest.spyOn(authService, 'instantiateProvider');

    const isProviderInstatiated = authService.instantiateProvider(testProviderName);

    expect(authServiceInstanceSpy).toHaveBeenCalledTimes(1);
    expect(isProviderInstatiated).toEqual(false);
  });

  it('should handle getToken from active and valid provider', async () => {
    const testProviderName = 'testProvider';

    const authService = new TazamaAuthentication([testProviderName]);

    const registerSpy = jest.spyOn(authService, 'registerProvider').mockImplementation((x: string) => {
      const provider = TestProvider.prototype;
      authService.providerRegistry.set(x, provider.constructor);
      return Promise.resolve(true);
    });

    const authServiceInstanceSpy = jest.spyOn(authService, 'instantiateProvider');
    const authServiceGetTokeneSpy = jest.spyOn(authService, 'getToken');

    let token;
    try {
      authService.configureProvider(testProviderName);
      await authService.registerProvider(testProviderName);

      authService.instantiateProvider(testProviderName);
      token = await authService.getToken('testCredential');
    } catch (err) {
      // Unreachable
      expect(true).toEqual(false);
    }

    expect(registerSpy).toHaveBeenCalledTimes(1);
    expect(authServiceInstanceSpy).toHaveBeenCalledTimes(1);
    expect(authServiceGetTokeneSpy).toHaveBeenCalledTimes(1);
    expect(token).toContain('ey');
  });

  it('should handle setActive with bad provider', async () => {
    const testProviderName = 'testProvider';

    const authService = new TazamaAuthentication([testProviderName]);

    const registerSpy = jest.spyOn(authService, 'registerProvider').mockImplementation((x: string) => {
      const provider = TestProvider.prototype;
      authService.providerRegistry.set(x, provider.constructor);
      return Promise.resolve(true);
    });

    const authServiceInstanceSpy = jest.spyOn(authService, 'instantiateProvider');

    try {
      authService.configureProvider(testProviderName);
      await authService.registerProvider(testProviderName);

      authService.instantiateProvider(testProviderName);
      authService.setActive('wrong');
    } catch (err) {
      // Unreachable
      expect(true).toEqual(false);
    }

    expect(registerSpy).toHaveBeenCalledTimes(1);
    expect(authServiceInstanceSpy).toHaveBeenCalledTimes(1);
  });

  it('should handle init with bad provider registration', async () => {
    const testProviderName = 'testProvider';

    const authService = new TazamaAuthentication([testProviderName]);

    const registerSpy = jest.spyOn(authService, 'registerProvider').mockResolvedValueOnce(false);

    try {
      await authService.init();
    } catch (err) {
      // Unreachable
      expect(true).toEqual(false);
    }

    expect(registerSpy).toHaveBeenCalledTimes(1);
  });

  it('should handle instantiateProvider valid test provider', async () => {
    const testProviderName = 'testProvider';

    const authService = new TazamaAuthentication([testProviderName]);

    const dynamicImportSpy = jest.spyOn(ProviderHelper, 'dynamicPackageImport').mockImplementationOnce((_: string) => {
      return Promise.resolve({
        register: () => TestProvider.prototype,
      });
    });

    const registerProviderSpy = jest.spyOn(authService, 'registerProvider');

    let registeredProviders;
    let activeProvider;

    try {
      await authService.init();
      registeredProviders = authService.getRegistered();
      activeProvider = authService.getActive();
    } catch (err) {
      // Unreachable
      expect(true).toEqual(false);
    }

    expect(registerProviderSpy).toHaveBeenCalledTimes(1);
    expect(dynamicImportSpy).toHaveBeenCalledTimes(1);
    expect(registeredProviders).toEqual([testProviderName]);
    expect(activeProvider).toEqual(testProviderName);
  });

  it('should handle instantiateProvider invalid test provider', async () => {
    const testProviderName = 'testProvider';

    const authService = new TazamaAuthentication([testProviderName]);

    const dynamicImportSpy = jest.spyOn(ProviderHelper, 'dynamicPackageImport').mockImplementationOnce((_: string) => {
      return Promise.resolve({
        bad: () => undefined,
      });
    });

    const registerProviderSpy = jest.spyOn(authService, 'registerProvider');

    let registeredProviders;
    let activeProvider;

    try {
      await authService.init();
      registeredProviders = authService.getRegistered();
      activeProvider = authService.getActive();
    } catch (err) {
      // Unreachable
      expect(true).toEqual(false);
    }

    expect(registerProviderSpy).toHaveBeenCalledTimes(1);
    expect(dynamicImportSpy).toHaveBeenCalledTimes(1);
    expect(registeredProviders).toEqual([]);
    expect(activeProvider).toEqual(undefined);
  });

  it('should handle instantiateProvider unable to load test provider', async () => {
    const testProviderName = 'testProvider';

    const authService = new TazamaAuthentication([testProviderName]);

    const dynamicImportSpy = jest
      .spyOn(ProviderHelper, 'dynamicPackageImport')
      .mockRejectedValueOnce((_: string) => new Error('Test Failure'));

    const registerProviderSpy = jest.spyOn(authService, 'registerProvider');

    let registeredProviders;

    try {
      await authService.init();
      registeredProviders = authService.getRegistered();
    } catch (err) {
      // Unreachable
      expect(true).toEqual(false);
    }

    expect(registerProviderSpy).toHaveBeenCalledTimes(1);
    expect(dynamicImportSpy).toHaveBeenCalledTimes(1);
    expect(registeredProviders).toEqual([]);
  });

  it('should handle getToken with no active provider', async () => {
    const testProviderName = 'testProvider';

    const authService = new TazamaAuthentication([testProviderName]);

    const registerSpy = jest.spyOn(authService, 'registerProvider').mockImplementation((x: string) => {
      const provider = TestProvider.prototype;
      authService.providerRegistry.set(x, provider.constructor);
      return Promise.resolve(true);
    });

    const authServiceInstanceSpy = jest.spyOn(authService, 'instantiateProvider');
    const authServiceGetTokeneSpy = jest.spyOn(authService, 'getToken');

    let token;
    try {
      authService.configureProvider(testProviderName);
      await authService.registerProvider(testProviderName);

      token = await authService.getToken('testCredential');
    } catch (err) {
      // Unreachable
      expect(true).toEqual(false);
    }

    expect(registerSpy).toHaveBeenCalledTimes(1);
    expect(authServiceInstanceSpy).toHaveBeenCalledTimes(0);
    expect(authServiceGetTokeneSpy).toHaveBeenCalledTimes(1);
    expect(token).toEqual('');
  });

  it('should handle signToken from jwtService - happy', async () => {
    const testToken: TazamaToken = {
      claims: [],
      clientId: '1234',
      exp: 0,
      iss: 'aaaa',
      sid: '1234',
      tokenString: 'eyyyyy',
      tenantId: 'tenant1234',
    };

    const signedToken = signToken(testToken);
    expect(signedToken).toContain('ey');
  });

  it('should handle signToken from jwtService - bad cert', async () => {
    authLibConfig.certPathPrivate = '';

    const testToken: TazamaToken = {
      claims: [],
      clientId: '1234',
      exp: 0,
      iss: 'aaaa',
      sid: '1234',
      tokenString: 'eyyyyy',
      tenantId: 'tenant1234',
    };

    try {
      signToken(testToken);
      throw new Error('UNREACHABLE');
    } catch (err) {
      expect(err).toEqual(new Error('Missing or Corrupted Private Key'));
    }
  });

  it('should handle validateToken from TazamaService - happy path', async () => {
    const verifiedResult = {
      clientId: 'abcdefgh-0000-4154-0000-ijklmnopqrst',
      iss: 'http://testProvider:80/authenticate',
      sid: 'somevalue',
      exp: 1749089681,
      tokenString: 'ey123456',
      claims: ['default-roles-tazama'],
      iat: 1749059681,
    };

    jest.spyOn(jwt, 'verify').mockImplementationOnce((_) => verifiedResult);

    const claims = ['default-roles-tazama', 'admin-panel'];

    const checkedClaims = validateTokenAndClaims('testToken', claims);

    expect(checkedClaims['default-roles-tazama']).toBeTruthy();
    expect(checkedClaims['admin-panel']).toBeFalsy();
  });

  it('should handle validateToken from TazamaService - wrong type', async () => {
    const authService = new TestProvider();

    const token = await authService.getToken('testCredentials');

    const claims = ['default-roles-tazama', 'admin-panel'];

    jest.spyOn(jwt, 'verify').mockImplementationOnce((x) => 'somestring');

    const checkedClaims = validateTokenAndClaims(token, claims);

    expect(checkedClaims['default-roles-tazama']).toBeFalsy();
    expect(checkedClaims['admin-panel']).toBeFalsy();
  });

  it('should handle validateToken from TazamaService - expired token', async () => {
    const expiredReslult = {
      name: 'TokenExpiredError',
      message: 'jwt expired',
      expiredAt: new Date('1970-01-01T00:00:00.000Z'),
    };

    jest.spyOn(jwt, 'verify').mockImplementationOnce(() => {
      throw new TokenExpiredError(expiredReslult.message, expiredReslult.expiredAt);
    });

    const claims = ['default-roles-tazama', 'admin-panel'];

    try {
      validateTokenAndClaims('testToken', claims);
      throw new Error('UNREACHABLE');
    } catch (err) {
      expect(err).toEqual(new Error('401 Unauthorized - token expired'));
    }
  });

  it('should handle validateToken from TazamaService - error', async () => {
    const authService = new TestProvider();

    const token = await authService.getToken('testCredentials');

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

  it('should list dependencies from providerHelper', async () => {
    const dependencies = await ProviderHelper.listAvailableProviders();

    expect(dependencies).toBeDefined();
  });

  it('should list dependencies from providerHelper - error', async () => {
    jest.spyOn(JSON, 'parse').mockImplementationOnce(() => {
      throw new Error('test');
    });
    let dependencies: string[];

    try {
      dependencies = await ProviderHelper.listAvailableProviders();

      expect(dependencies).toEqual([]);
    } catch (err) {
      // unreachable
      expect(true).toEqual(false);
    }
  });
});

describe('Tenant Service', () => {
  // Mock the verifyToken function for tenant service tests
  const originalVerifyToken = require('../../src/services/jwtService').verifyToken;

  beforeEach(() => {
    // Reset any existing mocks for tenant service tests
    jest.clearAllMocks();
  });

  afterEach(() => {
    // Restore original function
    jest.restoreAllMocks();
  });

  describe('validateAndExtractTenant', () => {
    it('should extract tenant ID from valid JWT token with tenantId field', () => {
      // Mock verifyToken to return a valid TazamaToken with tenantId
      jest.spyOn(require('../../src/services/jwtService'), 'verifyToken').mockReturnValue({
        sub: 'test-user',
        iss: 'test-issuer',
        exp: Math.floor(Date.now() / 1000) + 3600,
        sid: 'test-session',
        tokenString: 'test-token',
        clientId: 'test-client',
        tenantId: 'test-tenant',
        claims: ['test-claim'],
      });

      const result = validateAndExtractTenant('Bearer valid-token', { authenticated: true });

      expect(result.success).toBe(true);
      expect(result.tenantId).toBe('test-tenant');
      expect(result.error).toBeUndefined();
    });

    it('should return error when authorization header is missing', () => {
      const result = validateAndExtractTenant(undefined, { authenticated: true });

      expect(result.success).toBe(false);
      expect(result.error).toBe('Missing or invalid authorization header');
      expect(result.statusCode).toBe(401);
    });

    it('should return error when authorization header does not start with Bearer', () => {
      const result = validateAndExtractTenant('Invalid header', { authenticated: true });

      expect(result.success).toBe(false);
      expect(result.error).toBe('Missing or invalid authorization header');
      expect(result.statusCode).toBe(401);
    });

    it('should return error when JWT token is invalid', () => {
      // Mock verifyToken to throw an error
      jest.spyOn(require('../../src/services/jwtService'), 'verifyToken').mockImplementation(() => {
        throw new Error('jwt malformed');
      });

      const result = validateAndExtractTenant('Bearer invalid-token', { authenticated: true });

      expect(result.success).toBe(false);
      expect(result.error).toContain('Failed to decode JWT token');
      expect(result.statusCode).toBe(401);
    });

    it('should return error when verifyToken returns string', () => {
      // Mock verifyToken to return a string (invalid case)
      jest.spyOn(require('../../src/services/jwtService'), 'verifyToken').mockReturnValue('invalid-string-response');

      const result = validateAndExtractTenant('Bearer token-returning-string', { authenticated: true });

      expect(result.success).toBe(false);
      expect(result.error).toBe('Invalid JWT token');
      expect(result.statusCode).toBe(401);
    });

    it('should return error when tenant ID is missing from token', () => {
      // Mock verifyToken to return a token without tenantId
      jest.spyOn(require('../../src/services/jwtService'), 'verifyToken').mockReturnValue({
        sub: 'test-user',
        iss: 'test-issuer',
        exp: Math.floor(Date.now() / 1000) + 3600,
        sid: 'test-session',
        tokenString: 'test-token',
        clientId: 'test-client',
        claims: ['test-claim'],
        // No tenantId
      });

      const result = validateAndExtractTenant('Bearer token-without-tenant', { authenticated: true });

      expect(result.success).toBe(false);
      expect(result.error).toBe('TENANT_ID attribute is required and cannot be blank');
      expect(result.statusCode).toBe(403);
    });

    it('should return error when tenant ID is empty string', () => {
      // Mock verifyToken to return a token with empty tenantId
      jest.spyOn(require('../../src/services/jwtService'), 'verifyToken').mockReturnValue({
        sub: 'test-user',
        iss: 'test-issuer',
        exp: Math.floor(Date.now() / 1000) + 3600,
        sid: 'test-session',
        tokenString: 'test-token',
        clientId: 'test-client',
        tenantId: '   ', // Empty/whitespace only
        claims: ['test-claim'],
      });

      const result = validateAndExtractTenant('Bearer token-with-empty-tenant', { authenticated: true });

      expect(result.success).toBe(false);
      expect(result.error).toBe('TENANT_ID attribute is required and cannot be blank');
      expect(result.statusCode).toBe(403);
    });

    it('should extract tenant ID from legacy TENANT_ID field', () => {
      // Mock verifyToken to return a token with legacy TENANT_ID field
      jest.spyOn(require('../../src/services/jwtService'), 'verifyToken').mockReturnValue({
        sub: 'test-user',
        iss: 'test-issuer',
        exp: Math.floor(Date.now() / 1000) + 3600,
        sid: 'test-session',
        tokenString: 'test-token',
        clientId: 'test-client',
        TENANT_ID: 'legacy-tenant', // Legacy field
        claims: ['test-claim'],
      });

      const result = validateAndExtractTenant('Bearer legacy-token', { authenticated: true });

      expect(result.success).toBe(true);
      expect(result.tenantId).toBe('legacy-tenant');
    });

    it('should use tenant ID from header in unauthenticated mode', () => {
      const result = validateAndExtractTenant(undefined, {
        authenticated: false,
        tenantIdHeader: 'header-tenant',
      });

      expect(result.success).toBe(true);
      expect(result.tenantId).toBe('header-tenant');
    });

    it('should use default tenant ID in unauthenticated mode when header is empty', () => {
      const result = validateAndExtractTenant(undefined, {
        authenticated: false,
        defaultTenantId: 'custom-default',
      });

      expect(result.success).toBe(true);
      expect(result.tenantId).toBe('custom-default');
    });

    it('should use DEFAULT tenant when no header and no custom default in unauthenticated mode', () => {
      const result = validateAndExtractTenant(undefined, { authenticated: false });

      expect(result.success).toBe(true);
      expect(result.tenantId).toBe('DEFAULT');
    });

    it('should trim whitespace from tenant ID', () => {
      // Mock verifyToken to return a token with whitespace around tenantId
      jest.spyOn(require('../../src/services/jwtService'), 'verifyToken').mockReturnValue({
        sub: 'test-user',
        iss: 'test-issuer',
        exp: Math.floor(Date.now() / 1000) + 3600,
        sid: 'test-session',
        tokenString: 'test-token',
        clientId: 'test-client',
        tenantId: '  spaced-tenant  ',
        claims: ['test-claim'],
      });

      const result = validateAndExtractTenant('Bearer spaced-token', { authenticated: true });

      expect(result.success).toBe(true);
      expect(result.tenantId).toBe('spaced-tenant');
    });

    it('should handle unexpected errors in tenant validation', () => {
      // Mock verifyToken to throw a non-Error object to test error handling
      jest.spyOn(require('../../src/services/jwtService'), 'verifyToken').mockImplementation(() => {
        throw 'String error'; // Non-Error object
      });

      const result = validateAndExtractTenant('Bearer error-token', { authenticated: true });

      expect(result.success).toBe(false);
      expect(result.error).toBe('Failed to decode JWT token: String error');
      expect(result.statusCode).toBe(401);
    });
  });

  describe('validateTokenAndExtractTenant', () => {
    it('should extract tenant ID from valid JWT token', () => {
      // Mock verifyToken to return a valid TazamaToken
      jest.spyOn(require('../../src/services/jwtService'), 'verifyToken').mockReturnValue({
        sub: 'test-user',
        iss: 'test-issuer',
        exp: Math.floor(Date.now() / 1000) + 3600,
        sid: 'test-session',
        tokenString: 'test-token',
        clientId: 'test-client',
        tenantId: 'direct-tenant',
        claims: ['test-claim'],
      });

      const result = validateTokenAndExtractTenant('valid-token');

      expect(result.success).toBe(true);
      expect(result.tenantId).toBe('direct-tenant');
      expect(result.error).toBeUndefined();
    });

    it('should return error when token is invalid', () => {
      // Mock verifyToken to throw an error
      jest.spyOn(require('../../src/services/jwtService'), 'verifyToken').mockImplementation(() => {
        throw new Error('jwt malformed');
      });

      const result = validateTokenAndExtractTenant('invalid-token');

      expect(result.success).toBe(false);
      expect(result.error).toContain('Failed to validate token and extract tenant');
      expect(result.statusCode).toBe(401);
    });

    it('should return error when tenant ID is missing from token', () => {
      // Mock verifyToken to return a token without tenantId
      jest.spyOn(require('../../src/services/jwtService'), 'verifyToken').mockReturnValue({
        sub: 'test-user',
        iss: 'test-issuer',
        exp: Math.floor(Date.now() / 1000) + 3600,
        sid: 'test-session',
        tokenString: 'test-token',
        clientId: 'test-client',
        claims: ['test-claim'],
        // No tenantId
      });

      const result = validateTokenAndExtractTenant('token-without-tenant');

      expect(result.success).toBe(false);
      expect(result.error).toBe('TENANT_ID attribute is required and cannot be blank');
      expect(result.statusCode).toBe(403);
    });

    it('should support legacy TENANT_ID field', () => {
      // Mock verifyToken to return a token with legacy TENANT_ID
      jest.spyOn(require('../../src/services/jwtService'), 'verifyToken').mockReturnValue({
        sub: 'test-user',
        iss: 'test-issuer',
        exp: Math.floor(Date.now() / 1000) + 3600,
        sid: 'test-session',
        tokenString: 'test-token',
        clientId: 'test-client',
        TENANT_ID: 'legacy-direct-tenant',
        claims: ['test-claim'],
      });

      const result = validateTokenAndExtractTenant('legacy-token');

      expect(result.success).toBe(true);
      expect(result.tenantId).toBe('legacy-direct-tenant');
    });

    it('should trim whitespace from extracted tenant ID', () => {
      // Mock verifyToken to return a token with whitespace
      jest.spyOn(require('../../src/services/jwtService'), 'verifyToken').mockReturnValue({
        sub: 'test-user',
        iss: 'test-issuer',
        exp: Math.floor(Date.now() / 1000) + 3600,
        sid: 'test-session',
        tokenString: 'test-token',
        clientId: 'test-client',
        tenantId: '  direct-spaced-tenant  ',
        claims: ['test-claim'],
      });

      const result = validateTokenAndExtractTenant('spaced-token');

      expect(result.success).toBe(true);
      expect(result.tenantId).toBe('direct-spaced-tenant');
    });

    it('should handle unexpected errors in validateTokenAndExtractTenant', () => {
      // Mock verifyToken to throw a non-Error object to test error handling
      jest.spyOn(require('../../src/services/jwtService'), 'verifyToken').mockImplementation(() => {
        throw 42; // Non-Error object (number)
      });

      const result = validateTokenAndExtractTenant('error-token');

      expect(result.success).toBe(false);
      expect(result.error).toBe('Failed to validate token and extract tenant: 42');
      expect(result.statusCode).toBe(401);
    });
  });
});
