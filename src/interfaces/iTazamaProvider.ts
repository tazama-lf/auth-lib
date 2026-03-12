interface TazamaAuthProvider<
  TgetTokenArgs extends unknown[] = unknown[],
  TfetchUsersReturnType = unknown[],
  TfetchUsersArgs extends unknown[] = unknown[],
> {
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

  /**
   * Fetch users by role from the authentication provider
   *
   * @type {(...args: TfetchUsersArgs) => Promise<TfetchUsersReturnType>} returns array of users
   */
  fetchUsersByRole?: (...args: TfetchUsersArgs) => Promise<TfetchUsersReturnType>;
}

// eslint-disable-next-line @typescript-eslint/no-unnecessary-type-arguments -- Explicit helps with implementers
type ProviderConstructor = new (...args: unknown[]) => TazamaAuthProvider<unknown[], unknown[], unknown[]>;

export type { TazamaAuthProvider, ProviderConstructor };
