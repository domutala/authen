# Authen

**One identity. Any application. Any authentication provider.**

An open-source identity and authentication infrastructure for applications that need to work together — without tying their users to a particular framework, authentication method, or technology stack.

Build a single sign-on experience across your products, support the authentication providers your users prefer, and keep control of your identity infrastructure.

## Why this project?

Authentication often starts small: an email address, a password, and a login page.

But as a product grows, the same questions return. How do users move between applications without signing in again? How can they add a new authentication method without creating another account? How do you manage active sessions, revoke access, or introduce a provider that did not exist when the system was built?

These concerns should not have to be solved independently by every application.

Authen provides a shared foundation for identity, authentication, and sessions. Each application can focus on its own features while relying on a consistent, secure identity system.

## What it enables

### One account across multiple applications

A person has one central identity, even when using several independent applications. Sign in once and access connected applications through a single sign-on (SSO) experience, subject to each application's access policies.

### Authentication without provider lock-in

Support email and password, email verification codes, phone-based authentication, passkeys, Google, Apple, Microsoft, enterprise identity providers, and methods that may be introduced in the future.

Providers are extensions, not hard-coded assumptions. Applications do not need to understand how each provider authenticates a user.

### Multiple ways to access the same account

A user can connect several authentication methods to one account, switch between them, and remove a method without losing their identity or application data. Account linking and recovery are governed by explicit security policies.

### Sessions users can control

Manage active sessions, recognize connected devices, renew access securely, revoke an individual session, or sign out across devices. Short-lived access tokens and securely managed refresh tokens support these flows.

### Identity separate from application permissions

Authen establishes who a user is. Each application remains responsible for what that user can do with its own resources and data.

### Built for different applications and stacks

Use it with a single application, a suite of connected products, or third-party integrations. The core is designed in TypeScript with framework-independent contracts, so different servers, databases, and deployment models can be supported through adapters.

## How it works

```text
                            Authen
                ┌───────────────────────────┐
                │ Users & linked identities │
                │ Authentication providers  │
                │ Sessions & tokens         │
                │ Security policies         │
                │ Application integrations  │
                └─────────────┬─────────────┘
                              │
               ┌──────────────┼──────────────┐
               │              │              │
               ▼              ▼              ▼
          Application A  Application B  Application C
               │              │              │
               └────── Shared identity ──────┘
```

When someone opens an application, that application can delegate sign-in to Authen. Authen chooses the appropriate authentication flow, verifies the user's identity, and establishes a session. Other connected applications can then recognize the existing sign-in through a standards-based authorization flow, without sharing passwords or a single unrestricted cookie.

An Authen identity can be used across applications while each application keeps its own data, permissions, and business rules.

## Core concepts

| Concept         | Responsibility                                                  |
| --------------- | --------------------------------------------------------------- |
| **User**        | A stable account, independent of authentication methods.        |
| **Identity**    | A link between a user and an identity recognized by a provider. |
| **Profile**     | User-facing information, separate from authentication.          |
| **Credential**  | A means of proving identity, when a provider requires one.      |
| **Session**     | An authenticated connection that can expire or be revoked.      |
| **Provider**    | A pluggable mechanism for verifying identity.                   |
| **Application** | A client that delegates authentication to the platform.         |

These concepts are deliberately separated so that changing one authentication method does not require changing a user account or every connected application.

## Designed to be extended

Authen does not assume a fixed list of authentication providers. A provider declares its capabilities and implements a common contract. Different providers may use passwords, one-time challenges, redirects, passkeys, or other flows.

The same principle applies to infrastructure. Storage, cryptography, notifications, transport, and deployment are integration concerns rather than requirements imposed on the core.

This makes the project suitable for both products built from scratch and existing applications adopting centralized authentication incrementally.

## Security by design

Authentication infrastructure must make secure behavior the default. The architecture is designed around:

- Short-lived access tokens, controlled refresh-token rotation, and session revocation.
- Secure browser sessions, including HttpOnly cookies and appropriate CSRF protections.
- Explicit identity linking, account recovery, and authentication policies.
- Isolation between applications and provider configurations.
- Standards-based integrations using OAuth 2.0 and OpenID Connect.
- Auditable security events and clear boundaries between authentication and authorization.

Security depends on implementation, configuration, deployment, and ongoing review. Authen does not claim that installing it alone makes an application secure.

## Who is it for?

**Product teams** building multiple connected applications that should share a sign-in experience.

**Developers** who want reusable identity infrastructure without coupling their application to a particular authentication library or server framework.

**Organizations** that need control over authentication methods, user sessions, and integration with their own systems.

**Open-source maintainers** looking for an extensible foundation they can integrate, adapt, and contribute to.

## Documentation

This README introduces Authen. The full documentation covers the concepts, architecture, provider contract, authentication flows, integration guides, security model, deployment, and extension points.

**Documentation:** _Link coming soon_

The documentation will explain how to:

1. Understand the identity model and system boundaries.
2. Integrate an application and enable single sign-on.
3. Configure existing authentication providers or create a new one.
4. Manage sessions, tokens, account linking, and recovery.
5. Implement adapters for persistence, transport, and infrastructure.
6. Deploy, operate, and secure the platform.

## Project status

**Architecture and design phase.** Its public interfaces, implementation details, supported integrations, and release plan are still being defined. Features described here express the intended direction and should not be interpreted as already available.

## Open source and contributions

Authen is intended to be developed openly, with a focus on interoperability, extensibility, security, and long-term maintainability.

Contributions, design discussions, security reviews, documentation improvements, and new provider integrations will be welcome as the repository and contribution process take shape.

## License

Authen is open-source software licensed under
the [Apache License 2.0](./LICENSE).

---

**Your users belong to your product. Their identity should not depend on how they sign in.**
