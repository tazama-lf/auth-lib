import type { ProviderConstructor, TazamaAuthProvider } from '../interfaces/iTazamaProvider';
import { dynamicPackageImport } from './providerHelper';

class TazamaAuthentication {
  readonly providerConfig = new Set<string>();
  readonly providerRegistry = new Map<string, unknown>();
  readonly providerInstances = new Map<string, TazamaAuthProvider>();
  private activeInstance: undefined | string;

  constructor(providerList?: string[]) {
    if (providerList) {
      providerList.forEach((provider) => {
        this.configureProvider(provider);
      });
    }
  }

  /**
   * Stores provider config to be registered at the init step
   *
   * @param {string} providerName name of provider to store configuration of
   * @returns {boolean} returns success outcome
   */
  configureProvider(providerName: string): boolean {
    if (this.providerConfig.has(providerName)) {
      return false;
    }

    this.providerConfig.add(providerName);
    return true;
  }

  /**
   * Register providers using stored configuration from the constructor or the configureProvider(providerName) method
   * Then instantiate each provider on the list
   *
   * Note: Only the last provider instantiated will be active in current implementation
   *
   * @throws on empty provider config
   * @async
   * @returns {Promise<void>}
   */
  async init(): Promise<void> {
    if (this.providerConfig.size === 0) {
      throw new Error('No Provider Config');
    }
    for (const provider of this.providerConfig) {
      if (await this.registerProvider(provider)) {
        this.instantiateProvider(provider);
      }
    }
  }

  /**
   * Registering a provider involves importing the package and invoking the register method from the imported package
   *
   * @async
   * @param {string} providerName name of provider to register
   * @returns {Promise<boolean>} returns success outcome
   */
  async registerProvider(providerName: string): Promise<boolean> {
    let providerModule;
    try {
      providerModule = (await dynamicPackageImport(providerName)) as { register: () => ProviderConstructor };
    } catch (err) {
      // Provider could not be loaded
      return false;
    }

    if (typeof providerModule.register !== 'function') {
      // Validation failure
      return false;
    }

    const providerClass = providerModule.register();

    this.providerRegistry.set(providerName, providerClass.constructor);
    return true;
  }

  /**
   * Invoking the constructor of a registered provider to instantiate it
   * Sets the provider as the active provider
   *
   * @param {string} providerName name of provider to instantiate
   * @returns {boolean} returns success outcome
   */
  instantiateProvider(providerName: string): boolean {
    const providerConstructor = this.providerRegistry.get(providerName);

    if (!providerConstructor) {
      return false;
    }
    if (this.providerInstances.has(providerName)) {
      return false;
    }

    const instance = new (providerConstructor as ProviderConstructor)();
    this.providerInstances.set(providerName, instance);
    this.setActive(providerName);
    return true;
  }

  /**
   * Returns list of providers with stored configuration
   *
   * @returns {string[]}
   */
  getConfigured(): string[] {
    return Array.from(this.providerConfig.keys());
  }

  /**
   * Returns list of providers that have been imported and able to be instantiated
   *
   * @returns {string[]}
   */
  getRegistered(): string[] {
    return Array.from(this.providerRegistry.keys());
  }

  /**
   * Returns list of providers that have been instantiated
   *
   * @returns {string[]}
   */
  getInstances(): string[] {
    return Array.from(this.providerInstances.keys());
  }

  /**
   * Set an instantiated provider as the active provider to use getToken on
   *
   * @param {string} providerName name of instantiated provider
   * @returns {boolean} returns success outcome
   */
  setActive(providerName: string): boolean {
    if (!this.providerInstances.has(providerName)) {
      return false;
    }

    this.activeInstance = providerName;
    return true;
  }

  /**
   * Gets the active and instantiated provider
   *
   * @returns {string} providerName name of active and instantiated provider
   */
  getActive(): string | undefined {
    if (!this.activeInstance) {
      return undefined;
    }

    return this.activeInstance;
  }

  /**
   * Calls getToken function for the active instantiated provider
   *
   * @async
   * @param {...unknown[]} args params dependent on active provider implementation
   * @see [signToken](..\services\jwtService.ts)
   * @see [TazamaToken](..\interfaces\iTazamaToken.ts)
   * @returns {Promise<string>} token string from a jwtService.signToken(TazamaToken)
   */
  async getToken(...args: unknown[]): Promise<string> {
    let token = '';

    if (!this.activeInstance || typeof this.activeInstance !== 'string') {
      // No active provider
      return token;
    }

    const activeInstance = this.providerInstances.get(this.activeInstance);

    if (activeInstance) {
      token = await activeInstance.getToken(...args);
    }

    return token;
  }
}

export { type TazamaAuthProvider, type ProviderConstructor, TazamaAuthentication };
