import { Logger } from "./Logger";

/**
 * @internal
 */
export class CryptoUtils {
    /**
     * Generate a guid TODO: This needs checking for RFC4122 version 4 guid compliance.
     */
    public static generateUUIDv4(): string {
        // @ts-ignore
        return ([1e7] + -1e3 + -4e3 + -8e3 + -1e11).replace(/[018]/g, c =>
            // tslint:disable-next-line:no-bitwise
            (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16)
        );
    }

    /**
     * PKCE: Generate a code verifier
     */
    public static generateCodeVerifier(): string {
        return CryptoUtils.generateUUIDv4() + CryptoUtils.generateUUIDv4() + CryptoUtils.generateUUIDv4();
    }

    /**
     * PKCE: Generate a code challenge
     */
    public static async generateCodeChallenge(code_verifier: string): Promise<string> {
        try {
            const codeVerifierUint8Array = new TextEncoder().encode(code_verifier)
            const hashed = await crypto.subtle.digest('SHA-256', codeVerifierUint8Array);
            return btoa(String.fromCharCode(...new Uint8Array(hashed)));
        }
        catch (err) {
            Logger.error("CryptoUtils.generateCodeChallenge", err);
            throw err;
        }
    }

    /**
     * Generates a base64-encoded string for a basic auth header
     */
    public static generateBasicAuth(client_id: string, client_secret: string): string {
        return btoa(client_id + ':' + client_secret);
    }
}
