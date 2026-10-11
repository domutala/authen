import type { Clock } from "@authen/core";
import { createPrivateKey, createPublicKey, type KeyObject } from "node:crypto";
import {
  decryptPrivateKey,
  encryptPrivateKey,
  generateRsaKey,
} from "./crypto.js";
import type { SigningKeyRecord, SigningKeyStore } from "./types.js";

const DAY = 24 * 60 * 60 * 1000;

export interface KeyRingOptions {
  store: SigningKeyStore;
  clock: Clock;
  /** Secret qui chiffre les clés privées au repos. */
  encryptionSecret: string;
  /** Âge maximal de la clé active avant rotation automatique. Défaut : 90 jours. */
  rotationIntervalMs?: number;
  /** Durée pendant laquelle une ancienne clé reste dans le JWKS. Défaut : 1 heure. */
  overlapMs?: number;
  /** Fréquence de relecture du store. Défaut : 60 s. */
  cacheMs?: number;
  modulusLength?: number;
}

/**
 * Anneau de clés de signature persistées.
 *
 * - une clé `active` signe ;
 * - à l'échéance (ou sur `rotate()`), une nouvelle clé devient active et
 *   l'ancienne passe `retiring` : elle reste publiée et vérifiable pendant
 *   `overlapMs`, le temps que les tokens déjà émis expirent, puis disparaît.
 */
export class KeyRing {
  private readonly o: Required<Omit<KeyRingOptions, "store" | "clock">> &
    Pick<KeyRingOptions, "store" | "clock">;
  private records: SigningKeyRecord[] = [];
  private loadedAt = Number.NEGATIVE_INFINITY;
  private inflight: Promise<SigningKeyRecord[]> | null = null;
  private readonly privateKeys = new Map<string, KeyObject>();
  private readonly publicKeys = new Map<string, KeyObject>();

  constructor(options: KeyRingOptions) {
    this.o = {
      rotationIntervalMs: 90 * DAY,
      overlapMs: 60 * 60 * 1000,
      cacheMs: 60_000,
      modulusLength: 2048,
      ...options,
    };
  }

  get clock(): Clock {
    return this.o.clock;
  }

  /** Charge (et au besoin crée ou fait tourner) les clés. À appeler au démarrage. */
  async init(): Promise<void> {
    await this.sync(true);
  }

  /** Clé de signature courante. */
  async signingKey(): Promise<{ kid: string; privateKey: KeyObject }> {
    const records = await this.sync();
    const active = records.find((r) => r.status === "active");
    if (!active) throw new Error("Aucune clé de signature active");
    return { kid: active.kid, privateKey: this.privateKey(active) };
  }

  /** Clé publique pour vérifier un token (active ou en retrait). `null` si inconnue. */
  async verificationKey(kid: string): Promise<KeyObject | null> {
    let record = (await this.sync()).find((r) => r.kid === kid);
    // Clé créée par une autre instance depuis la dernière lecture.
    if (!record) record = (await this.sync(true)).find((r) => r.kid === kid);
    if (!record) return null;
    let key = this.publicKeys.get(kid);
    if (!key) {
      key = createPublicKey({ key: record.publicJwk as never, format: "jwk" });
      this.publicKeys.set(kid, key);
    }
    return key;
  }

  /** Contenu du JWKS : uniquement des clés publiques. */
  async jwks(): Promise<{ keys: Record<string, unknown>[] }> {
    const records = await this.sync();
    return { keys: records.map((r) => ({ ...r.publicJwk })) };
  }

  /** Rotation immédiate (incident, rotation manuelle). */
  async rotate(): Promise<string> {
    const records = await this.sync(true, true);
    const active = records.find((r) => r.status === "active");
    if (!active) throw new Error("Aucune clé de signature active");
    return active.kid;
  }

  private privateKey(record: SigningKeyRecord): KeyObject {
    let key = this.privateKeys.get(record.kid);
    if (!key) {
      key = createPrivateKey(
        decryptPrivateKey(
          this.o.encryptionSecret,
          record.kid,
          record.privateKeyEncrypted,
        ),
      );
      this.privateKeys.set(record.kid, key);
    }
    return key;
  }

  private sync(force = false, rotate = false): Promise<SigningKeyRecord[]> {
    const now = this.o.clock.now().getTime();
    if (!force && now - this.loadedAt < this.o.cacheMs) {
      return Promise.resolve(this.records);
    }
    // Les appels simultanés partagent la même synchronisation.
    if (this.inflight && !rotate) return this.inflight;

    const run = this.o.store
      .transaction(async (tx) => {
        const now = this.o.clock.now();
        let records = await tx.list();

        for (const record of records) {
          if (
            record.status === "retiring" &&
            record.expiresAt &&
            record.expiresAt <= now
          ) {
            await tx.delete(record.kid);
          }
        }
        records = records.filter(
          (r) => !(r.status === "retiring" && r.expiresAt && r.expiresAt <= now),
        );

        const active = records.find((r) => r.status === "active");
        const due =
          !active ||
          rotate ||
          active.createdAt.getTime() + this.o.rotationIntervalMs <=
            now.getTime();

        if (due) {
          if (active) {
            const retired: SigningKeyRecord = {
              ...active,
              status: "retiring",
              retiredAt: now,
              expiresAt: new Date(now.getTime() + this.o.overlapMs),
            };
            await tx.update(retired);
            records = records.map((r) => (r.kid === active.kid ? retired : r));
          }
          const generated = await generateRsaKey(this.o.modulusLength);
          const created: SigningKeyRecord = {
            kid: generated.kid,
            algorithm: "RS256",
            publicJwk: generated.publicJwk,
            privateKeyEncrypted: encryptPrivateKey(
              this.o.encryptionSecret,
              generated.kid,
              generated.privatePem,
            ),
            status: "active",
            createdAt: now,
            retiredAt: null,
            expiresAt: null,
          };
          await tx.insert(created);
          records = [...records, created];
        }
        return records;
      })
      .then((records) => {
        this.records = records;
        this.loadedAt = this.o.clock.now().getTime();
        for (const kid of [...this.privateKeys.keys()]) {
          if (!records.some((r) => r.kid === kid)) {
            this.privateKeys.delete(kid);
            this.publicKeys.delete(kid);
          }
        }
        return records;
      })
      .finally(() => {
        if (this.inflight === run) this.inflight = null;
      });
    this.inflight = run;
    return run;
  }
}
