import { JwtPayload } from "jsonwebtoken";

export interface KeycloakJwtToken extends JwtPayload{
    resource_access?: {
        account: {
            roles : Array<string>
        }
    }
}   