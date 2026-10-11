#!/usr/bin/env node

import { createHash, randomBytes } from "node:crypto";
import { createInterface } from "node:readline/promises";
import { stdin, stdout } from "node:process";

const options = parseArguments(process.argv.slice(2));
const baseUrl = withoutTrailingSlash(
  options.baseUrl ?? process.env.AUTHEN_BASE_URL ?? "http://127.0.0.1:3000",
);
const email = options.email ?? process.env.AUTHEN_EMAIL ?? "alice@example.com";
const clientId =
  options.clientId ?? process.env.OIDC_CLIENT_ID ?? "authen-web";
const redirectUri =
  options.redirectUri ??
  process.env.OIDC_REDIRECT_URI ??
  "http://localhost:3001/callback";

try {
  console.log(`1/5 Démarrage de l'authentification pour ${email}`);
  const started = await requestJson(`${baseUrl}/auth/email/start`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email }),
  });
  const transactionId = requiredString(started.body, "transactionId");

  const otp =
    options.otp ?? process.env.AUTHEN_OTP ?? (await askForOtp(transactionId));

  console.log("2/5 Vérification du code OTP et création de la session");
  const verified = await requestJson(`${baseUrl}/auth/email/verify`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ transactionId, code: otp }),
  });
  const cookie = sessionCookie(verified.response);

  console.log("3/5 Création de la requête OAuth/OIDC avec PKCE S256");
  const verifier = randomBytes(48).toString("base64url");
  const challenge = createHash("sha256")
    .update(verifier, "ascii")
    .digest("base64url");
  const state = randomBytes(24).toString("base64url");
  const nonce = randomBytes(24).toString("base64url");
  const authorizationUrl = new URL(`${baseUrl}/authorize`);
  authorizationUrl.search = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: "openid profile",
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });

  const authorization = await fetch(authorizationUrl, {
    headers: { cookie },
    redirect: "manual",
  });
  if (authorization.status !== 302) {
    throw await responseError("Autorisation refusée", authorization);
  }
  const callback = new URL(requiredHeader(authorization, "location"));
  if (callback.searchParams.get("state") !== state) {
    throw new Error("Le state OAuth retourné ne correspond pas à la requête");
  }
  const authorizationError = callback.searchParams.get("error");
  if (authorizationError) {
    throw new Error(`Erreur OAuth: ${authorizationError}`);
  }
  const code = requiredQueryParameter(callback, "code");

  console.log("4/5 Échange du code d'autorisation contre les jetons");
  const tokens = await requestJson(`${baseUrl}/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      client_id: clientId,
      redirect_uri: redirectUri,
      code_verifier: verifier,
    }),
  });
  const accessToken = requiredString(tokens.body, "access_token");

  console.log("5/5 Lecture de /userinfo avec le jeton d'accès");
  const userinfo = await requestJson(`${baseUrl}/userinfo`, {
    headers: { authorization: `Bearer ${accessToken}` },
  });

  console.log("\nFlux terminé avec succès.");
  console.log("Utilisateur:", JSON.stringify(userinfo.body, null, 2));
  console.log("Jetons:", JSON.stringify(tokens.body, null, 2));
} catch (error) {
  console.error("\nÉchec du flux:", error instanceof Error ? error.message : error);
  process.exitCode = 1;
}

async function askForOtp(transactionId) {
  if (!stdin.isTTY) {
    throw new Error(
      "OTP manquant. Utilisez --otp <code> ou la variable AUTHEN_OTP.",
    );
  }
  console.log(`Transaction créée: ${transactionId}`);
  console.log("Le serveur de développement affiche l'OTP dans ses logs.");
  const prompt = createInterface({ input: stdin, output: stdout });
  try {
    return (await prompt.question("Code OTP : ")).trim();
  } finally {
    prompt.close();
  }
}

async function requestJson(url, init = {}) {
  const response = await fetch(url, init);
  const text = await response.text();
  let body;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    throw new Error(`${init.method ?? "GET"} ${url}: réponse JSON invalide`);
  }
  if (!response.ok) {
    throw new Error(
      `${init.method ?? "GET"} ${url}: HTTP ${response.status} ${JSON.stringify(body)}`,
    );
  }
  return { response, body };
}

async function responseError(message, response) {
  const body = await response.text();
  return new Error(`${message}: HTTP ${response.status}${body ? ` ${body}` : ""}`);
}

function sessionCookie(response) {
  const setCookie = response.headers.get("set-cookie");
  if (!setCookie) throw new Error("Le serveur n'a pas créé de cookie de session");
  return setCookie.split(";", 1)[0];
}

function requiredHeader(response, name) {
  const value = response.headers.get(name);
  if (!value) throw new Error(`En-tête ${name} absent de la réponse`);
  return value;
}

function requiredQueryParameter(url, name) {
  const value = url.searchParams.get(name);
  if (!value) throw new Error(`Paramètre ${name} absent de l'URL de callback`);
  return value;
}

function requiredString(value, property) {
  if (
    typeof value !== "object" ||
    value === null ||
    typeof value[property] !== "string"
  ) {
    throw new Error(`Propriété ${property} absente de la réponse`);
  }
  return value[property];
}

function withoutTrailingSlash(value) {
  return value.replace(/\/+$/, "");
}

function parseArguments(arguments_) {
  const result = {};
  const names = new Map([
    ["--base-url", "baseUrl"],
    ["--email", "email"],
    ["--otp", "otp"],
    ["--client-id", "clientId"],
    ["--redirect-uri", "redirectUri"],
  ]);
  for (let index = 0; index < arguments_.length; index += 1) {
    const name = arguments_[index];
    if (name === "--help" || name === "-h") {
      printHelp();
      process.exit(0);
    }
    const property = names.get(name);
    if (!property) throw new Error(`Argument inconnu: ${name}`);
    const value = arguments_[index + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`Valeur manquante pour ${name}`);
    }
    result[property] = value;
    index += 1;
  }
  return result;
}

function printHelp() {
  console.log(`Usage: node scripts/oidc-flow.js [options]

Options:
  --base-url <url>       URL du serveur (défaut: http://127.0.0.1:3000)
  --email <adresse>      Adresse de connexion (défaut: alice@example.com)
  --otp <code>           OTP, sinon demandé interactivement
  --client-id <id>       Client OAuth (défaut: authen-web)
  --redirect-uri <url>   URI de callback enregistrée
  -h, --help             Afficher cette aide

Les mêmes valeurs peuvent être fournies via AUTHEN_BASE_URL, AUTHEN_EMAIL,
AUTHEN_OTP, OIDC_CLIENT_ID et OIDC_REDIRECT_URI.`);
}
