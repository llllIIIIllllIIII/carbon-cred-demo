# Designing applications on top of vLEI

Read this when the question shifts from "how does the trust chain work" to "what
should I build with it". The sandbox exists to let you answer the second question
cheaply, before committing to an issuer relationship.

## The design question that comes first

Before choosing credential types, answer this: **what decision does a verified
credential let someone stop doing?**

vLEI does not create new information. It removes the cost of re-establishing
information that is already true. So the value shows up wherever an organisation
currently pays -- in time, staff, or risk -- to answer "is this really you, and
are you allowed to do this?" Look for:

- A manual document check that repeats for every counterparty and every renewal
- A phone call to confirm that a signatory still holds their position
- A reconciliation step that exists only because two systems name the same
  company differently
- A delay measured in days that is pure verification latency, not analysis

If a proposed application does not eliminate one of these, the credential is
decoration.

## Four workable patterns

### 1. Reusable onboarding (KYC / supplier registration)

An organisation proves itself once to a QVI and then presents the resulting
credentials to every counterparty. The counterparty verifies cryptographically in
milliseconds rather than collecting documents.

- Credentials: LE (entity identity) + OOR (the officer who signs) or ECR (the
  operational contact)
- Verifier logic: chain to pinned GLEIF Root, check LEI status against the Global
  LEI Index, check the role is one your policy accepts
- Where the value lands: onboarding time drops from days to minutes; the same
  proof serves every counterparty, so the cost is paid once rather than N times

### 2. Signing authority on documents and transactions

Bind a signature to a person *and* the role they held at the moment of signing.
CESR proof signatures allow a signer to sign a whole document or specific
sections of it.

- Credentials: OOR for legally significant acts, ECR for delegated operational
  limits
- Verifier logic: verify the signature, then verify the role credential was not
  revoked *as of the signing timestamp* -- not as of today
- Design trap: "was this valid then" and "is this valid now" are different
  questions. Regulatory filings usually need the first; live payment
  authorisation needs the second. Decide explicitly, per workflow.

### 3. Supply chain and trade document provenance

Each participant signs the artefacts it produces. The receiving party verifies a
chain of provenance rather than trusting a PDF.

- Credentials: LE for each participant, ECR for the specific operational role
  ("Certifying Officer", "Customs Broker")
- Verifier logic: the chain of signatures over the document set, each anchored to
  a verified organisational identity
- Where the value lands: disputes shift from "is this document genuine" to
  substantive questions; audit becomes replay rather than investigation

### 4. Credit assessment and SME financing

The pattern with the largest addressable gap. A small enterprise's difficulty in
borrowing is substantially a *verification* problem: the lender cannot cheaply
establish that the business is real, that the person applying can bind it, and
that supporting data belongs to it.

- Credentials: LE (the business), OOR (the person who can borrow), ECR
  (accountant or agent acting on the business's behalf), plus **domain
  attestations chained as additional ACDCs** -- tax filing attestations, invoice
  attestations, customs records
- Verifier logic: chain each attestation to the LE credential, so a data point is
  not merely accompanied by a claim of provenance but cryptographically bound to
  a verified entity
- Design note: this is where ACDC's chaining beats a bag of verifiable
  credentials. The attestation does not say "this belongs to company X"; it is
  structurally *unable* to be presented as belonging to anyone else.

## Extending beyond the five credential types

ISO 17442-3 clause 5 explicitly permits other credential types, and says that
additional data about a role holder should be carried by chaining a further ACDC
to the role credential rather than by stretching the role credential's schema.
Follow that.

To add a domain credential in the sandbox, define your schema SAID, then chain it
to an LE or role credential with an appropriate operator:

```bash
# a tax-filing attestation bound to a verified legal entity
python scripts/vlei_sandbox.py issue \
  --type ecr --issuer le --holder person \
  --lei 8755001ELOZEL05BVX22 --person "Chen Wei" \
  --context-role "Tax Filing Agent" \
  --auth <LE credential SAID>
```

For a genuinely new schema, work through `references/trust-chain.md` and decide:
who may issue it, what it must chain to, and which operator enforces that. Then
model it in mock mode before writing the JSON Schema.

## Verifier design checklist

Whatever you build, the verifier should:

- [ ] Pin the expected root AID. A chain that verifies to an unexpected root is a
      failure, not a success.
- [ ] Enforce edge operators rather than merely following edges.
- [ ] Check revocation at every hop, not just the leaf.
- [ ] Evaluate validity **as of the relevant time**, which is not always now.
- [ ] Cross-check the LEI against the Global LEI Index for registration status --
      a credential can be cryptographically perfect while the underlying LEI has
      lapsed.
- [ ] Fail closed and say why. "Verification failed" without a reason makes
      support impossible; the sandbox's `verify` output shows the level of detail
      to aim for.
- [ ] Keep KERI at the edge. One verifier service; everything downstream consumes
      ordinary JSON with a trust decision attached.

## Sizing the claim honestly

Two constraints shape any business case and are better raised by you than by a
sceptic in the room:

**LEI is a prerequisite with real cost.** Every vLEI credential carries an LEI
assigned under ISO 17442-1, obtained from an LEI Issuer with an annual renewal
obligation. For a population of small enterprises this is a genuine adoption
barrier, and any credible plan must say who bears it. The Validation Agent model
-- where a financial institution folds LEI issuance into KYC it already performs
-- exists precisely to address this.

**Verification is not trustworthiness.** The rule block that every vLEI
credential carries says so explicitly: a valid credential does not assert that
the entity is reputable, safe to deal with, or compliant. It asserts identity,
authority, and role. Applications that quietly promise more than that will
disappoint, and the disclaimer text is in the credential for anyone to read.
