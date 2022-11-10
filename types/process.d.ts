declare namespace NodeJS {
  export interface ProcessEnv {
    NODE_ENV: 'development' | 'production';
    NODE_PORT?: string;
    OIDC_CLIENT_ID: string;
    OIDC_PRIVATE_KEY: string;
    OIDC_ISSUER_DISCOVERY_ENDPOINT: string;
    OIDC_AUTHORIZE_REDIRECT_URI?: string;
    OIDC_LOGOUT_REDIRECT_URI?: string;
    IV_PUBLIC_KEY: string;
    IV_ISSUER: string;
  }
}
