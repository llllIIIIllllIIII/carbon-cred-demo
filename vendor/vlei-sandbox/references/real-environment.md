# Real environment: KERIA, witnesses, and Signify

Read this when mock mode is no longer enough -- when you need witness receipts,
OOBI discovery, IPEX presentation exchange, or multisig, or when you are about to
integrate with a Qualified vLEI Issuer for real.

## When to graduate from mock mode

Mock mode is the right tool while you are working out **what** credentials your
application needs, how they chain, and what your verifier logic must enforce.
Graduate when any of these become the question:

- **Availability and duplicity detection.** Witnesses receipt key events and make
  a controller's KEL independently observable. Nothing in mock mode models a
  controller trying to sign two conflicting events.
- **Discovery.** Real parties find each other's KELs and schemas over OOBI URLs
  and then prove key possession with challenge-response. Mock mode assumes
  everyone already knows everyone.
- **Presentation protocol.** IPEX (grant / admit) is the actual credential
  handoff. Its notification and acceptance semantics affect UX design.
- **Multisig and delegation ceremonies.** GLEIF Root and QVI AIDs are multisig in
  production. Threshold coordination has real operational cost you should feel
  before you design around it.
- **Talking to a QVI.** Nothing you produce in mock mode will be accepted by a
  real issuer.

## Bring the stack up

```bash
python scripts/vlei_sandbox.py real scaffold    # copy docker-compose.yaml here
python scripts/vlei_sandbox.py real up
python scripts/vlei_sandbox.py real status
```

Services and ports:

| Service | Port | Role |
|---|---|---|
| `vlei-server` | 7723 | Serves the official vLEI ACDC schemas over OOBI |
| `witness-demo` | 5642-5647 | Six witnesses: wan, wil, wes, wit, wub, wyz |
| `keria` | 3901 / 3902 / 3903 | Multi-tenant KERI agent (admin / agent / boot) |
| `sally-hook` | 9923 | Receives IPEX presentations as JSON -- your integration seam |

Sanity check that schemas resolve:

```bash
curl -s http://localhost:7723/oobi/ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY | head -20
```

Tear down with `real down` -- this removes volumes, so the sandbox starts clean.

## The Signify client model

KERIA is an agent that holds *no* signing keys. Keys stay client-side in Signify;
KERIA stores encrypted state and does the networking. This split is the reason
the architecture is credible for regulated use: your cloud agent operator cannot
sign on your behalf.

```
Signify client (holds keys)  ──HTTP──▶  KERIA agent  ──▶  witnesses / peers
       │                                    │
   signs everything              stores KELs, TELs, credentials
```

Install and connect:

```bash
npm install signify-ts@0.3.0-rc1
```

```typescript
import { SignifyClient, ready, randomPasscode, Tier, Saider } from 'signify-ts';

await ready();
const bran = randomPasscode();                 // 21-char seed; persist it or lose the keystore
const client = new SignifyClient(
  'http://localhost:3901',                     // admin
  bran, Tier.low,
  'http://localhost:3903'                      // boot
);
await client.boot();
await client.connect();
```

Create an identifier with witnesses and publish an OOBI:

```typescript
const WITNESS_AIDS = [
  'BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha',  // wan
  'BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM',  // wil
  'BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX',  // wes
];

const op = await client.identifiers().create('le', {
  toad: 3, wits: WITNESS_AIDS,
});
await client.operations().wait(await op.op());
await client.identifiers().addEndRole('le', 'agent', client.agent!.pre);

const oobi = await client.oobis().get('le', 'agent');
console.log(oobi.oobis[0]);   // hand this to the counterparty
```

Resolve the schemas every party will need:

```typescript
const SCHEMA_SERVER = 'http://vlei-server:7723';   // container-internal hostname
for (const said of [
  'EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao',  // QVI
  'ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY',  // LE
  'EKA57bKBKxr_kN7iN5i7lMUxpMG-s19dRcmov1iDxz-E',  // OOR AUTH
  'EBNaNu-M9P5cgrnfl2Fvymy4E_jvxxyjb70PRtiANlJy',  // OOR
]) {
  await client.oobis().resolve(`${SCHEMA_SERVER}/oobi/${said}`);
}
```

Issue a chained credential -- the edge block is built exactly as mock mode builds
it, which is the point of prototyping there first:

```typescript
const registry = await client.registries().create({ name: 'le', registryName: 'leRegistry' });

const edge = Saider.saidify({
  d: '',
  qvi: { n: qviCredential.sad.d, s: qviCredential.sad.s },
})[1];

const result = await client.credentials().issue('le', {
  ri: registrySaid,
  s: 'ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY',
  a: { i: holderPrefix, LEI: '8755001ELOZEL05BVX22' },
  e: edge,
  r: rules,
});
await client.operations().wait(result.op);
```

Present it over IPEX:

```typescript
const [grant, gsigs, gend] = await client.ipex().grant({
  senderName: 'le', recipient: holderPrefix, acdc: credential, /* iss, anc ... */
});
await client.ipex().submitGrant('le', grant, gsigs, gend, [holderPrefix]);
// the holder waits for the /exn/ipex/grant notification, then admits
```

## Wiring your application in

The `sally-hook` service is the cleanest integration point for a first
application. Sally acts as a verifier: it receives an IPEX presentation, walks
the chain, and POSTs a JSON summary to your webhook. That gives you a
conventional HTTP integration surface -- your loan origination system, ERP, or
filing gateway does not need to speak KERI at all.

Architecturally this is the pattern worth adopting: **keep KERI at the edge.**
One verifier service speaks the protocol; everything behind it consumes ordinary
verified JSON with a trust decision already attached.

## Known friction

- **Passcode (`bran`) loss is unrecoverable.** It seeds the keystore. Treat it
  like a wallet seed phrase from day one, including in demos.
- **Witness `toad` must be reachable.** If the threshold of witnesses cannot be
  contacted, inception hangs rather than failing loudly. Check `real logs`.
- **OOBI hostnames differ inside and outside the container network.** Use
  `http://vlei-server:7723` from other containers, `http://localhost:7723` from
  your laptop. Mixing them produces confusing resolution failures.
- **Schema SAIDs are content-addressed.** Editing a schema changes its SAID and
  every credential referencing the old one keeps referencing the old one. Version
  deliberately.
- **`docker compose` version.** The bundled compose file uses inline `configs`,
  which needs Compose v2.23+. Upgrade if you see "unsupported config".

## Moving toward production

You cannot self-issue credentials that a real verifier will trust: the chain must
terminate at the GLEIF Root AID, and only GLEIF can issue QVI credentials. The
realistic path is:

1. Prototype the credential design and verifier logic in mock mode.
2. Prove the workflow end to end on the local KERIA stack.
3. Obtain LEIs for the legal entities involved (an LOU assigns these; a
   Validation Agent arrangement can fold this into an existing KYC process).
4. Engage a Qualified vLEI Issuer to issue LE and role credentials against those
   LEIs, and pin the GLEIF Root AID in your verifier.
