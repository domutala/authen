import type { TransactionId } from "@authen/core";

export interface OtpMessage {
  /** Destinataire (adresse email). */
  to: string;
  /** Code en clair à envoyer : ne jamais le journaliser. */
  code: string;
  expiresAt: Date;
  transactionId: TransactionId;
}

/**
 * Port d'envoi du code. L'implémentation (SMTP, Resend, SES...) vit dans
 * un adaptateur "notifications" : le provider ne connaît aucun service d'email.
 */
export interface OtpSender {
  send(message: OtpMessage): Promise<void>;
}
