import envSchema from "env-schema";

export interface ServerEnvironment {
  HOST: string;
  PORT: number;
  AUTHEN_ISSUER?: string;
  DATABASE_URL?: string;
  AUTHEN_SIGNING_SECRET?: string;
  AUTHEN_KEY_ROTATION_DAYS?: number;
  AUTHEN_TRUST_PROXY: boolean;
  OIDC_CLIENT_ID?: string;
  OIDC_REDIRECT_URI?: string;
}

declare module "fastify" {
  interface FastifyInstance {
    envs: ServerEnvironment;
  }
}

export function loadEnvironment(): ServerEnvironment {
  return envSchema<ServerEnvironment>({
    dotenv: true,
    schema: {
      type: "object",
      required: ["PORT", "HOST"],
      properties: {
        PORT: {
          type: "number",
          default: 3000,
        },

        HOST: { type: "string", default: "127.0.0.1" },

        AUTHEN_ISSUER: { type: "string" },
        OIDC_CLIENT_ID: { type: "string" },
        OIDC_REDIRECT_URI: { type: "string" },

        DATABASE_URL: { type: "string" },
        AUTHEN_SIGNING_SECRET: { type: "string" },
        AUTHEN_KEY_ROTATION_DAYS: { type: "number" },
        AUTHEN_TRUST_PROXY: { type: "boolean", default: false },
      },
    },
  });
}
