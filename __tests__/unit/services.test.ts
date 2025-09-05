import jwt, { JwtPayload, TokenExpiredError } from 'jsonwebtoken';
import { TazamaAuthentication, TazamaAuthProvider, TazamaToken, validateTokenAndClaims } from '../../src';
import { authLibConfig } from '../../src/interfaces/iAuthLibConfig';
import { signToken } from '../../src/services/jwtService';
import * as ProviderHelper from '../../src/services/providerHelper';
import { extractTenant } from '../../src/services/tenantService';

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
  beforeEach(() => {
    // Reset any existing mocks for tenant service tests
    jest.clearAllMocks();
  });

  afterEach(() => {
    // Restore original function
    jest.restoreAllMocks();
  });

  describe('extractTenant', () => {
    it('should extract tenant ID from valid JWT token in authenticated mode', () => {
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

      const result = extractTenant(true, 'Bearer valid-token');

      expect(result.success).toBe(true);
      expect(result.tenantId).toBe('test-tenant');
    });

    it('should return failure when authenticated but no authorization header is provided', () => {
      const result = extractTenant(true);

      expect(result.success).toBe(false);
      expect(result.tenantId).toBeUndefined();
    });

    it('should return failure when authenticated but authorization header is undefined', () => {
      const result = extractTenant(true, undefined);

      expect(result.success).toBe(false);
      expect(result.tenantId).toBeUndefined();
    });

    it('should return DEFAULT tenant when not authenticated', () => {
      const result = extractTenant(false);

      expect(result.success).toBe(true);
      expect(result.tenantId).toBe('DEFAULT');
    });

    it('should return DEFAULT tenant when not authenticated even with header provided', () => {
      const result = extractTenant(false, 'Bearer some-token');

      expect(result.success).toBe(true);
      expect(result.tenantId).toBe('DEFAULT');
    });

    it('should extract tenant ID from token with proper Bearer format', () => {
      // Mock verifyToken to return a valid TazamaToken
      jest.spyOn(require('../../src/services/jwtService'), 'verifyToken').mockReturnValue({
        sub: 'test-user',
        iss: 'test-issuer',
        exp: Math.floor(Date.now() / 1000) + 3600,
        sid: 'test-session',
        tokenString: 'test-token',
        clientId: 'test-client',
        tenantId: 'bearer-tenant',
        claims: ['test-claim'],
      });

      const result = extractTenant(true, 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...');

      expect(result.success).toBe(true);
      expect(result.tenantId).toBe('bearer-tenant');
    });

    it('should handle verifyToken returning token with different tenant ID', () => {
      // Mock verifyToken to return a token with a specific tenant ID
      jest.spyOn(require('../../src/services/jwtService'), 'verifyToken').mockReturnValue({
        sub: 'user123',
        iss: 'auth-service',
        exp: Math.floor(Date.now() / 1000) + 7200,
        sid: 'session123',
        tokenString: 'jwt-token-string',
        clientId: 'client123',
        tenantId: 'tenant123',
        claims: ['admin', 'user'],
      });

      const result = extractTenant(true, 'Bearer mock-jwt-token');

      expect(result.success).toBe(true);
      expect(result.tenantId).toBe('tenant123');
    });

    it('should handle verifyToken being called with correct token from authorization header', () => {
      const verifyTokenSpy = jest.spyOn(require('../../src/services/jwtService'), 'verifyToken').mockReturnValue({
        sub: 'test-user',
        iss: 'test-issuer',
        exp: Math.floor(Date.now() / 1000) + 3600,
        sid: 'test-session',
        tokenString: 'test-token',
        clientId: 'test-client',
        tenantId: 'spy-tenant',
        claims: ['test-claim'],
      });

      const authHeader = 'Bearer mock-token-string';
      extractTenant(true, authHeader);

      expect(verifyTokenSpy).toHaveBeenCalledWith('mock-token-string');
    });

    it('should work with different authorization header formats', () => {
      jest.spyOn(require('../../src/services/jwtService'), 'verifyToken').mockReturnValue({
        sub: 'test-user',
        iss: 'test-issuer',
        exp: Math.floor(Date.now() / 1000) + 3600,
        sid: 'test-session',
        tokenString: 'test-token',
        clientId: 'test-client',
        tenantId: 'format-tenant',
        claims: ['test-claim'],
      });

      // Test with different spacing
      const result1 = extractTenant(true, 'Bearer token123');
      expect(result1.success).toBe(true);
      expect(result1.tenantId).toBe('format-tenant');

      // Test with multiple spaces (should split correctly)
      const result2 = extractTenant(true, 'Bearer  token-with-spaces');
      expect(result2.success).toBe(true);
      expect(result2.tenantId).toBe('format-tenant');
    });

    it('should handle the case when verifyToken throws an error', () => {
      // Mock verifyToken to throw an error
      jest.spyOn(require('../../src/services/jwtService'), 'verifyToken').mockImplementation(() => {
        throw new Error('Invalid token');
      });

      // The current implementation doesn't handle errors from verifyToken
      // This test documents the current behavior
      expect(() => {
        extractTenant(true, 'Bearer invalid-token');
      }).toThrow('Invalid token');
    });

    it('should handle edge cases with authorization header splitting', () => {
      jest.spyOn(require('../../src/services/jwtService'), 'verifyToken').mockReturnValue({
        sub: 'test-user',
        iss: 'test-issuer',
        exp: Math.floor(Date.now() / 1000) + 3600,
        sid: 'test-session',
        tokenString: 'test-token',
        clientId: 'test-client',
        tenantId: 'split-tenant',
        claims: ['test-claim'],
      });

      // Test with only "Bearer" (no token part)
      const result1 = extractTenant(true, 'Bearer');
      expect(result1.success).toBe(true);
      expect(result1.tenantId).toBe('split-tenant');

      // Test with empty string after Bearer
      const result2 = extractTenant(true, 'Bearer ');
      expect(result2.success).toBe(true);
      expect(result2.tenantId).toBe('split-tenant');
    });
  });
});
