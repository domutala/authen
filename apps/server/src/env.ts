import type { FastifyInstance } from "fastify";
import fastifyEnv from "@fastify/env";

declare module "fastify" {
  interface FastifyInstance {
    envs: {
      HOST: string;
      PORT: number;

      AUTHEN_ISSUER?: string;

      DATABASE_URL?: string;
      AUTHEN_SIGNING_SECRET?: string;

      OIDC_CLIENT_ID?: string;
      OIDC_REDIRECT_URI?: string;
    };
  }
}

export async function registerEnv(app: FastifyInstance) {
  await app.register(fastifyEnv, {
    dotenv: true,
    confKey: "envs",
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
      },
    },
  });
}
