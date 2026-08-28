---
name: vlei-sandbox
description: Spin up a working GLEIF verifiable LEI (vLEI) environment locally and build applications against it. Use this skill whenever the user mentions vLEI, verifiable LEI, LEI credentials, GLEIF, KERI, ACDC, CESR, AIDs, KERIA, Signify, qualified vLEI issuers, OOR or ECR credentials, ISO 17442, or organizational digital identity -- and also when they describe a problem it solves without naming it, such as verifying which person is authorised to sign for a company, reusable KYC or supplier onboarding, cryptographic proof of corporate identity in supply chain or trade finance, or SME credit assessment that depends on proving a business is real. Covers simulating the full trust chain (GLEIF to QVI to legal entity to role holder), issuing and revoking chained credentials, verifying a credential back to the root of trust, validating LEI check digits per ISO 17442-1, and graduating to a real Docker KERIA stack.
---

# vLEI Sandbox

A working model of the GLEIF verifiable LEI trust chain that runs in seconds with
no infrastructure, plus a path to the real KERIA stack when the simulation stops
being enough.

## Why this exists

vLEI has a steep entry cost that is mostly incidental. The concepts -- KERI key
event logs, ACDC chained credentials, CESR encoding, the GLEIF governance
hierarchy -- are learnable, but the usual first step is standing up Docker
containers, resolving OOBIs, and coordinating multisig ceremonies before you can
issue a single credential. That ordering is backwards for anyone trying to work
out whether vLEI fits their problem.

This skill inverts it. Mock mode gives you real Ed25519 signatures, real CESR
encoding, real self-addressing identifiers, and real edge-operator enforcement,
with zero dependencies beyond Python. You can design a credential scheme, break
it deliberately, and understand exactly what a verifier will and will not accept
-- in an afternoon, on a laptop, offline. Then you graduate.

## Two modes

| | Mock (default) | Real |
|---|---|---|
| Requires | Python 3.8+ | Docker Compose v2.23+ |
| Startup | instant | ~60s image pull |
| Signatures | real Ed25519 | real Ed25519 |
| SAIDs / CESR | real | real |
| Witnesses, OOBI, IPEX | modelled away | actual protocol |
| Multisig, delegation ceremonies | simplified | full |
| Good for | credential design, verifier logic, teaching, demos | integration, protocol behaviour, pre-production |

Start in mock mode unless the user explicitly needs protocol-level behaviour.
Most application design questions are answered faster there.

## Getting started

Everything runs through one script. From the skill directory:

```bash
python scripts/vlei_sandbox.py demo
```

This builds the entire six-step trust chain -- GLEIF qualifies a QVI, the QVI
issues a Legal Entity credential, the entity authorises an official role, the QVI
issues the OOR credential, the entity issues an ECR credential directly -- and
then verifies the result back to the root of trust, printing every check it
performs. Run it first. The narrated output is the fastest available explanation
of how the ecosystem fits together, and it is a strong live demo.

Then show what breaks:

```bash
python vlei_sandbox.py status                     # list credentials and SAIDs
python vlei_sandbox.py revoke --said <LE SAID>    # revoke the entity credential
python vlei_sandbox.py verify --said <OOR SAID>   # now fails -- the chain collapsed
```

That sequence -- revoking one credential and watching everything beneath it fail
-- lands the core idea better than any diagram: authority is linked, not asserted.

## Command reference

**Setup**

```bash
python vlei_sandbox.py init [--force]
python vlei_sandbox.py demo [--lei <18 chars>] [--person NAME] [--role ROLE] [--context-role ROLE]
python vlei_sandbox.py status
```

**Actors (AID controllers)**

```bash
python vlei_sandbox.py actor add --alias gleif --registry gleifRegistry --root
python vlei_sandbox.py actor add --alias qvi --registry qviRegistry --delegator gleif
python vlei_sandbox.py actor list
python vlei_sandbox.py actor rotate --alias qvi      # pre-rotation: AID survives
```

`--root` marks the ecosystem root of trust. `--delegator` produces a delegated
inception (`dip`) event, mirroring how GLEIF delegates AIDs to QVIs.

**Credentials**

```bash
python vlei_sandbox.py issue --type qvi      --issuer gleif --holder qvi --lei <LEI>
python vlei_sandbox.py issue --type le       --issuer qvi --holder le --lei <LEI> --auth <QVI SAID>
python vlei_sandbox.py issue --type oor-auth --issuer le --holder qvi --lei <LEI> \
    --person "Jane Doe" --role "Chief Executive Officer" --subject-aid <person AID> --auth <LE SAID>
python vlei_sandbox.py issue --type oor      --issuer qvi --holder person --lei <LEI> \
    --person "Jane Doe" --role "Chief Executive Officer" --auth <OOR AUTH SAID>
python vlei_sandbox.py issue --type ecr      --issuer le --holder person --lei <LEI> \
    --person "Jane Doe" --context-role "Trade Finance Officer" --auth <LE SAID>

python vlei_sandbox.py revoke --said <SAID>
python vlei_sandbox.py verify --said <SAID>
python vlei_sandbox.py present --said <SAID> --out presentation.json
```

Add `--json` to `issue` to print the full ACDC. Use `--data '{"key":"value"}'`
for attributes beyond the built-in flags.

The tool refuses issuance that would break the governance rules -- a credential
with no authorising edge, an edge to the wrong credential type, an LEI that fails
its checksum. Those refusals are worth demonstrating; they show the model is
enforcing something rather than decorating JSON.

**LEI arithmetic (ISO 17442-1)**

```bash
python vlei_sandbox.py lei make YZ83GD8L7GG84979J5     # -> YZ83GD8L7GG84979J516
python vlei_sandbox.py lei check YZ83GD8L7GG84979J516  # -> VALID
```

**Diagrams**

```bash
python vlei_sandbox.py chain --out chain.mmd    # Mermaid, ready for slides or docs
```

**Real environment**

```bash
python vlei_sandbox.py real scaffold   # copy docker-compose.yaml into the project
python vlei_sandbox.py real up
python vlei_sandbox.py real status
python vlei_sandbox.py real logs
python vlei_sandbox.py real down
```

## Working with a user

Match the depth to what they are actually trying to decide.

**"Explain vLEI to me"** -- run `demo` and walk through its output. Do not
lecture first; the artefacts are more convincing than the theory, and the
narration in the output covers the concepts in the order they become necessary.

**"Can vLEI solve <problem>?"** -- read `references/application-patterns.md`
before answering. The honest answer is often "partly", and the constraints there
(LEI cost, the difference between verified and trustworthy) matter more to a real
decision than the capabilities do.

**"Help me design credentials for X"** -- model it in mock mode. Create the
actors, issue the chain, then deliberately attack it: try to issue without
authorisation, chain to the wrong type, revoke a parent. A design that survives
that in mock mode is worth building for real.

**"How do I integrate this?"** -- read `references/real-environment.md`. Push
toward keeping KERI at the edge: one verifier service speaking the protocol,
ordinary JSON downstream.

**"Is my X.509 / existing PKI a shortcut?"** -- be straight about it. ISO 17442-2
(LEI in X.509) and 17442-3 (LEI in ACDC) are parallel paths, not a conversion
pipeline. Existing PKI is genuinely valuable as an identity assurance source
feeding a QVI's verification of company representatives, but there is no
standardised format conversion, and framing it as one will not survive contact
with GLEIF or a regulator. `references/trust-chain.md` has the detail.

## Reference material

Read these as needed rather than upfront:

- `references/trust-chain.md` -- credential types, ACDC anatomy, edge operators,
  the full verifier checklist, ISO 17442 series mapping, well-known schema SAIDs.
  Read before answering any question about credential structure or what
  "verified" means.
- `references/real-environment.md` -- Docker stack, Signify-TS client patterns,
  IPEX presentation, known friction, the path to production. Read before touching
  `real` mode or writing integration code.
- `references/application-patterns.md` -- four workable application patterns,
  how to extend beyond the five standard credential types, verifier design
  checklist, and the two constraints worth raising before a sceptic does. Read
  before scoping or pitching an application.

## Implementation notes

- **Fidelity.** SAIDs, CESR qualification, edge operators, TEL revocation
  semantics, and pre-rotation all behave as specified. Signatures are real
  Ed25519, verified on every `verify` call.
- **Digest algorithm.** KERI's default is Blake3-256 (CESR code `E`). Blake3 is
  not in the Python standard library, so the sandbox falls back to Blake2b-256
  (code `F`) -- also a valid CESR digest code. Identifiers therefore begin with
  `F` rather than `E` unless the optional `blake3` package is installed, in which
  case they match production exactly: `pip install blake3`. Mention this if a
  user notices the prefix difference; it is a substitution, not an error.
- **Signing backend.** Uses `cryptography` or `PyNaCl` when present, and a
  dependency-free pure-Python Ed25519 otherwise. `init` reports which.
- **State.** A single readable `.vlei/state.json` in the working directory.
  Inspect it freely -- seeing the KELs and TELs as plain JSON is instructive.
  It contains private key seeds, so it is a sandbox artefact and should never be
  committed or reused for anything real.
- **What is deliberately absent.** Witness receipting, OOBI resolution over the
  wire, IPEX message exchange, multisig thresholds, watchers. These are protocol
  concerns that do not change credential design. Reach for `real` mode when they
  become the question.

## Portability

The skill is plain Python plus Markdown, with no framework dependencies, so it
works unchanged in Claude Code, Codex, Gemini CLI, or a bare terminal. An agent
that can read files and run shell commands has everything it needs. If your agent
reads `AGENTS.md` rather than `SKILL.md`, both are present and point to the same
content.
