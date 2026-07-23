export interface TazamaUser {
  id: string;
  username: string;
  firstName?: string;
  lastName?: string;
  email?: string;
  emailVerified: boolean;
  enabled: boolean;
  createdTimestamp: number;
  metadata?: Record<string, unknown>;
}
