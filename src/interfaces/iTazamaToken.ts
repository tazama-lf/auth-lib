export interface TazamaToken{
    exp: number;
    sid: string;
    iss: string;
    tokenString: string;
    clientId: string;
    claims: Array<string>;
}