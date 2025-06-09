interface TazamaAuthProvider<TgetTokenArgs extends unknown[] = unknown[]> {
  /**
   * To allow for flexibility around getTokens parameters we make make use of generics
   *
   * These are equivalent (contravariant example)
   *
   * (...args: [TArg1, TArg2]) => string
   *
   * (username: TArg1, password: TArg2) => string
   *
   * @type {(...args: T) => Promise<string>} returns jwt signed string
   */
  getToken: (...args: TgetTokenArgs) => Promise<string>;
}

type ProviderConstructor = new (...args: unknown[]) => TazamaAuthProvider<unknown[]>;

export type { TazamaAuthProvider, ProviderConstructor };
