# The vLEI trust chain: structures, rules, and what a verifier checks

Read this when you need to reason about credential shape, edge operators, or
what "verified" actually means. Contents:

1. [The five credential types](#the-five-credential-types)
2. [The six-step issuance chain](#the-six-step-issuance-chain)
3. [ACDC anatomy](#acdc-anatomy)
4. [Edge operators](#edge-operators)
5. [What a verifier checks](#what-a-verifier-checks)
6. [Revocation](#revocation)
7. [Mapping to the ISO 17442 series](#mapping-to-the-iso-17442-series)
8. [Well-known schema SAIDs](#well-known-schema-saids)

---

## The five credential types

ISO 17442-3:2024 clause 5 groups vLEI credentials into three categories. The
grouping matters more than the names: it tells you what question each credential
answers.

| Category | Credential | Answers |
|---|---|---|
| Entity | Qualified vLEI Issuer (QVI) | Is this organisation allowed to issue vLEIs? |
| Entity | Legal Entity (LE) | Is this organisation who it claims to be? |
| Authorization | QVI Issuer Authorization (OOR AUTH / ECR AUTH) | Did the legal entity actually ask for this role credential? |
| Role | Official Organizational Role (OOR) | Does this person hold a *registered* office here? |
| Role | Engagement Context Role (ECR) | Does this person act for the entity in this *functional* capacity? |

Two distinctions decide most design questions:

**OOR vs ECR.** An OOR asserts an office that is publicly discoverable in
formation or registration documents -- director, CEO, company secretary. ISO
17442-3 requires the role value to come from ISO 5009 where the role is
registered there. Only a QVI may issue an OOR. An ECR asserts a functional role
the entity defines for itself -- "Trade Finance Officer", "Authorised Signatory
up to USD 1m". A legal entity may issue ECRs directly, or contract a QVI to do
it as a value-added service. If you are designing an application, ECR is almost
always the credential you want for operational authority, and OOR is what you
want for legal accountability.

**Authorization credentials are not role credentials.** They flow *upward*, from
the legal entity to the QVI, and they exist so that a QVI can prove it was asked.
They are the reason a QVI cannot mint role credentials for a company that never
requested them.

---

## The six-step issuance chain

```
  GLEIF ──(1) QVI credential──▶ QVI
    QVI ──(2) LE credential───▶ Legal Entity
     LE ──(3) OOR AUTH────────▶ QVI
    QVI ──(4) OOR credential──▶ Person          [edge: I2I to the OOR AUTH]
     LE ──(5) ECR AUTH────────▶ QVI
     LE ──(6a) ECR credential─▶ Person          [direct issuance path]
    QVI ──(6b) ECR credential─▶ Person          [QVI-as-service path, via ECR AUTH]
```

Note the shape of steps 3-4: authority makes a round trip. The legal entity holds
the authority; it lends a scoped, single-purpose slice of that authority to the
QVI; the QVI spends it on exactly one credential. This is delegation with a
receipt, and it is why an audit later can show not only that a credential exists
but that it was requested.

In production, GLEIF also delegates an AID to the QVI (a `dip` inception event)
in addition to issuing the QVI credential. The credential says "you are
qualified"; the delegated AID means the QVI's identifier itself is anchored in
GLEIF's key event log. Compromising the QVI's keys does not let an attacker
re-anchor that delegation, because cooperative delegation requires a commitment
from both sides.

---

## ACDC anatomy

```json
{
  "v": "ACDC10JSON0001c2_",
  "d": "EBc...",           // SAID of this credential
  "u": "0AB...",           // optional salty nonce; makes the credential private
  "i": "EDe...",           // issuer AID
  "ri": "EFg...",          // credential registry (where issuance/revocation live)
  "s": "ENPXp1vQ...",      // schema SAID
  "a": {                   // attribute section
    "d": "EHi...",         //   SAID of the attribute block
    "i": "EJk...",         //   issuee AID -- the holder
    "dt": "2026-08-10T...",
    "LEI": "8755001ELOZEL05BVX22"
  },
  "e": {                   // edge section -- the authority links
    "d": "ELm...",
    "auth": { "n": "ENo...", "s": "EKA57bKB...", "o": "I2I" }
  },
  "r": {                   // rule section -- legal disclaimers
    "d": "EPq...",
    "usageDisclaimer": { "l": "..." },
    "issuanceDisclaimer": { "l": "..." }
  }
}
```

Every `d` field is a **SAID**: a digest computed over the structure with the `d`
field replaced by a same-length run of `#`. Because the placeholder and the
digest are the same length, the serialisation size never changes and anyone can
repeat the computation. Change one character anywhere and every enclosing SAID
breaks. This is what makes tamper-evidence structural rather than procedural.

The `u` field is worth understanding for privacy design. Without it, a credential
whose attributes are guessable (say, a small set of possible LEIs) can be
brute-forced from its SAID alone. Adding a high-entropy nonce blinds that. The
GLEIF framework makes ECR credentials private for exactly this reason.

---

## Edge operators

An edge is a pointer to the credential that authorises this one:

```json
"auth": { "n": "<SAID of target>", "s": "<required schema SAID>", "o": "I2I" }
```

`n` is the target's SAID -- unforgeable. `s` pins the target's schema, so an
attacker cannot swap in a different credential type that happens to be valid.
`o` is the operator, and it constrains identity correspondence:

| Operator | Rule | Why it matters |
|---|---|---|
| `I2I` | The **issuer** of this credential must be the **issuee** of the target | A QVI can only issue an OOR credential if it personally holds the matching OOR AUTH from that legal entity. Without I2I, any QVI could point at any authorisation. |
| `NI2I` | No identity correspondence required | The link is contextual or informational -- "this attestation relates to that credential" |
| (none) | Defaults to I2I semantics in ACDC | Used where the chain is a plain descent |

When you are designing a new credential type, choosing the operator *is* the
security design. Ask: if I omit the identity constraint, who else could stand in
the issuer's place? If the answer is "anyone holding a valid credential of that
type", you need I2I.

---

## What a verifier checks

A verifier that has never spoken to the issuer should still be able to answer
"can I rely on this?" from the presentation bundle alone. The sequence:

1. **Recompute every SAID.** Credential, attribute block, edge block, rule block.
   Any mismatch means the content was altered after signing.
2. **Check the schema SAID** against the expected credential type. A credential
   claiming to be an OOR but carrying an ECR schema is not an OOR.
3. **Verify the issuer's signature** using the key that was current in the
   issuer's KEL *at the sequence number where the issuance was anchored* -- not
   the issuer's key today. This is why key rotation does not invalidate
   previously issued credentials.
4. **Validate the LEI** per ISO 17442-1: 20 characters, check digit pair in
   [02..98], and the whole string mod 97 equals 1.
5. **Check registry status** in the issuer's TEL: an `iss` event with no
   subsequent `rev` event.
6. **Follow each edge**, enforcing the operator, and repeat steps 1-5 on the
   target. Recurse until you reach a credential issued directly by the root of
   trust.
7. **Confirm the root** is the GLEIF Root AID you expect. A chain that verifies
   perfectly back to *someone else's* root proves nothing.

Step 7 is the one people skip, and it is the one that matters. Cryptographic
verification tells you a chain is internally consistent; it does not tell you the
chain belongs to the ecosystem you trust. Pin the root.

---

## Revocation

Revocation is an event in the issuer's transaction event log, anchored into the
issuer's key event log. There is no CRL to fetch and no OCSP responder to trust
-- the revocation is part of the same append-only history as the issuance.

The consequence that surprises people: revoking a credential **collapses
everything chained below it**. Revoke a Legal Entity credential and every OOR and
ECR credential issued under it fails verification immediately, because the walk
in step 6 above hits a revoked node. This is a feature -- an entity whose LEI
lapses cannot leave authorised signatories in the field -- but it means
revocation is a high-blast-radius operation and applications should surface it
clearly.

---

## Mapping to the ISO 17442 series

| Part | Year | Scope | Relationship |
|---|---|---|---|
| 17442-1 | 2020 | LEI assignment: 20-character structure, MOD 97-10 check digits, the reference data record | Every vLEI credential must carry an LEI assigned under this part |
| 17442-2 | 2020 | Embedding the LEI in X.509 certificates via OID `1.3.6.1.4.1.52266.1` (and role in `.2`) | A **parallel** path, not a predecessor. X.509 gives authentication; the LEI gives unique persistent identity |
| 17442-3 | 2024 | Using the LEI in ACDC credentials | Normatively references only 17442-1 and ISO 5009 (official organizational roles) |

A design note that comes up constantly: 17442-2 and 17442-3 are **not** a
conversion pipeline. There is no standardised "X.509 to vLEI" transformation.
Where an existing PKI is useful is as an *identity assurance source* feeding the
QVI's verification of a legal entity's Designated and Legal Entity Authorized
Representatives (DARs and LARs) -- that is, as evidence in the onboarding
process, not as input to a format converter. Framing it correctly matters when
presenting to GLEIF or to a regulator.

---

## Well-known schema SAIDs

These are the published vLEI schema identifiers used by the GLEIF training
environment and by this sandbox:

| Credential | Schema SAID |
|---|---|
| QVI | `EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao` |
| Legal Entity | `ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY` |
| ECR AUTH | `EH6ekLjSr8V32WyFbGe1zXjTzFs9PkTYmupJ9H65O14g` |
| ECR | `EEy9PkikFcANV1l7EHukCeXqrzT1hNZjGlUk7wuMO5jw` |
| OOR AUTH | `EKA57bKBKxr_kN7iN5i7lMUxpMG-s19dRcmov1iDxz-E` |
| OOR | `EBNaNu-M9P5cgrnfl2Fvymy4E_jvxxyjb70PRtiANlJy` |

In the real environment these resolve over OOBI from the vLEI schema server at
`http://localhost:7723/oobi/<SAID>`.
