#!/usr/bin/env python3
"""vLEI Sandbox -- simulate the GLEIF verifiable LEI trust chain locally.

Two modes:
  mock (default)  Pure Python. No Docker, no network. Real Ed25519 signatures,
                  real CESR encoding, real SAIDs, real edge-operator enforcement.
  real            Docker Compose bringing up KERIA + witnesses + schema server,
                  driven by Signify-TS. See `real` subcommands and
                  references/real-environment.md.

Run `python vlei_sandbox.py --help` for the command list, or jump straight in
with `python vlei_sandbox.py demo`.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cesr  # noqa: E402
import keri  # noqa: E402

WORKSPACE = ".vlei"
STATE_FILE = "state.json"

# ---------------------------------------------------------------------------
# vLEI credential catalogue
#
# Schema SAIDs are the well-known values published in the GLEIF vLEI schema
# registry and used by the official training environment, so credentials minted
# here carry the same schema identifiers a real verifier would expect to see.
# ---------------------------------------------------------------------------
SCHEMAS = {
    "qvi": "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
    "le": "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY",
    "ecr-auth": "EH6ekLjSr8V32WyFbGe1zXjTzFs9PkTYmupJ9H65O14g",
    "ecr": "EEy9PkikFcANV1l7EHukCeXqrzT1hNZjGlUk7wuMO5jw",
    "oor-auth": "EKA57bKBKxr_kN7iN5i7lMUxpMG-s19dRcmov1iDxz-E",
    "oor": "EBNaNu-M9P5cgrnfl2Fvymy4E_jvxxyjb70PRtiANlJy",
}

SCHEMA_NAMES = {
    "qvi": "Qualified vLEI Issuer vLEI Credential",
    "le": "Legal Entity vLEI Credential",
    "ecr-auth": "Legal Entity Engagement Context Role Authorization",
    "ecr": "Legal Entity Engagement Context Role vLEI Credential",
    "oor-auth": "Legal Entity Official Organizational Role Authorization",
    "oor": "Legal Entity Official Organizational Role vLEI Credential",
}

# What each credential type requires, who may issue it, and how it links back.
# `edge_from` names the credential type that must authorise this one.
CRED_RULES = {
    "qvi":      {"attrs": ["LEI"], "edge_from": None,  "operator": None},
    "le":       {"attrs": ["LEI"], "edge_from": "qvi", "operator": None,
                 "edge_name": "qvi"},
    "oor-auth": {"attrs": ["AID", "LEI", "personLegalName", "officialRole"],
                 "edge_from": "le", "operator": None, "edge_name": "le"},
    "oor":      {"attrs": ["LEI", "personLegalName", "officialRole"],
                 "edge_from": "oor-auth", "operator": "I2I", "edge_name": "auth"},
    "ecr-auth": {"attrs": ["AID", "LEI", "personLegalName", "engagementContextRole"],
                 "edge_from": "le", "operator": "I2I", "edge_name": "le"},
    "ecr":      {"attrs": ["LEI", "personLegalName", "engagementContextRole"],
                 "edge_from": "le", "operator": "I2I", "edge_name": "le",
                 "alt_edge_from": "ecr-auth", "private": True},
}

RULES_BLOCK = {
    "d": "",
    "usageDisclaimer": {
        "l": "Usage of a valid, unexpired, and non-revoked vLEI Credential, as "
             "defined in the associated Ecosystem Governance Framework, does not "
             "assert that the Legal Entity is trustworthy, honest, reputable in "
             "its business dealings, safe to do business with, or compliant with "
             "any laws or that an implied or expressly intended purpose will be "
             "fulfilled."
    },
    "issuanceDisclaimer": {
        "l": "All information in a valid, unexpired, and non-revoked vLEI "
             "Credential, as defined in the associated Ecosystem Governance "
             "Framework, is accurate as of the date the validation process was "
             "complete. The vLEI Credential has been issued to the legal entity "
             "or person named in the vLEI Credential as the subject; and the "
             "qualified vLEI Issuer exercised reasonable care to perform the "
             "validation process set forth in the vLEI Ecosystem Governance "
             "Framework."
    },
}


# ---------------------------------------------------------------------- LEI
LEI_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def lei_to_digits(s):
    out = []
    for ch in s.upper():
        if ch.isdigit():
            out.append(ch)
        elif ch.isalpha():
            out.append(str(ord(ch) - ord("A") + 10))
        else:
            raise ValueError(f"invalid LEI character: {ch!r}")
    return "".join(out)


def lei_check_digits(base18):
    """ISO 17442-1 clause 5.2: convert, append '00', mod 97, subtract from 98."""
    if len(base18) != 18:
        raise ValueError("LEI base must be exactly 18 characters")
    remainder = int(lei_to_digits(base18) + "00") % 97
    return f"{98 - remainder:02d}"


def lei_validate(lei):
    """Returns (ok, reason). Mirrors ISO 17442-1 Annex A verification."""
    lei = lei.upper()
    if len(lei) != 20:
        return False, "LEI must be 20 characters"
    if not all(c in LEI_ALPHABET for c in lei):
        return False, "LEI must be upper-case alphanumeric only"
    if not lei[18:].isdigit():
        return False, "check digit pair must be numeric"
    if not ("02" <= lei[18:] <= "98"):
        return False, f"check digit pair {lei[18:]} outside valid range [02..98]"
    if int(lei_to_digits(lei)) % 97 != 1:
        return False, f"checksum failed (expected pair {lei_check_digits(lei[:18])})"
    return True, "valid"


# ------------------------------------------------------------------ workspace
def ws_path(root=None):
    return os.path.join(root or os.getcwd(), WORKSPACE)


def state_path(root=None):
    return os.path.join(ws_path(root), STATE_FILE)


def load_state(root=None):
    p = state_path(root)
    if not os.path.exists(p):
        die("No sandbox here. Run `vlei_sandbox.py init` first.")
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def save_state(state, root=None):
    os.makedirs(ws_path(root), exist_ok=True)
    with open(state_path(root), "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)


def die(msg, code=1):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(code)


def load_controller(state, alias):
    if alias not in state["actors"]:
        die(f"unknown actor {alias!r}. Known: {', '.join(state['actors']) or '(none)'}")
    return keri.Controller(alias, state["actors"][alias])


def store_controller(state, ctl):
    state["actors"][ctl.alias] = ctl.to_state()


# ------------------------------------------------------------------- commands
def cmd_init(args):
    root = args.dir
    if os.path.exists(state_path(root)) and not args.force:
        die("sandbox already exists here; pass --force to reset")
    state = {
        "version": 1,
        "mode": "mock",
        "digest": cesr.DIGEST_NAME,
        "signing_backend": keri.ed.BACKEND,
        "actors": {},
        "credentials": {},
        "root_aid": None,
    }
    save_state(state, root)
    print(f"Initialised vLEI sandbox in {ws_path(root)}")
    print(f"  digest algorithm : {cesr.DIGEST_NAME} (CESR code {cesr.DIGEST_CODE})")
    print(f"  signing backend  : {keri.ed.BACKEND}")
    print("\nNext: `demo` for the full trust chain, or `actor add --alias gleif --root`.")


def cmd_actor_add(args):
    state = load_state(args.dir)
    if args.alias in state["actors"] and not args.force:
        die(f"actor {args.alias!r} already exists; pass --force to recreate")
    ctl = keri.Controller(args.alias)
    delegator = None
    if args.delegator:
        parent = load_controller(state, args.delegator)
        delegator = parent.aid
    ctl.incept(delegator=delegator)
    if args.registry:
        ctl.create_registry(args.registry)
    store_controller(state, ctl)
    if args.root:
        state["root_aid"] = ctl.aid
    save_state(state, args.dir)
    print(f"{args.alias}")
    print(f"  AID       : {ctl.aid}")
    print(f"  key       : {ctl.verkey}")
    print(f"  next (pre-rotated digest) : {ctl.kel[0]['event']['n'][0]}")
    if delegator:
        print(f"  delegated from : {args.delegator} ({delegator})")
    if args.registry:
        print(f"  registry  : {ctl.registries[args.registry]['regk']}")
    if args.root:
        print("  marked as ecosystem root of trust")


def cmd_actor_list(args):
    state = load_state(args.dir)
    if not state["actors"]:
        print("(no actors yet)")
        return
    for alias, s in state["actors"].items():
        mark = "  <root>" if s["aid"] == state.get("root_aid") else ""
        regs = ", ".join(r["regk"][:12] + "..." for r in s["registries"].values())
        print(f"{alias:<10} {s['aid']}  kel={len(s['kel'])}{mark}")
        if regs:
            print(f"{'':<10} registries: {regs}")


def cmd_actor_rotate(args):
    state = load_state(args.dir)
    ctl = load_controller(state, args.alias)
    old = ctl.verkey
    event = ctl.rotate()
    store_controller(state, ctl)
    save_state(state, args.dir)
    print(f"{args.alias} rotated at sequence {event['s']}")
    print(f"  retired key : {old}")
    print(f"  current key : {ctl.verkey}")
    print(f"  AID unchanged : {ctl.aid}")
    print("\nThe identifier survived the key change -- this is the property an "
          "X.509 certificate cannot offer, since rekeying there means reissuing "
          "the certificate.")


def cmd_registry_create(args):
    state = load_state(args.dir)
    ctl = load_controller(state, args.alias)
    regk = ctl.create_registry(args.name)
    store_controller(state, ctl)
    save_state(state, args.dir)
    print(f"registry {args.name!r} for {args.alias}: {regk}")


def resolve_registry(ctl, name=None):
    if not ctl.registries:
        raise ValueError(f"{ctl.alias} has no credential registry; create one first")
    if name:
        if name not in ctl.registries:
            raise ValueError(f"{ctl.alias} has no registry {name!r}")
        return name
    return next(iter(ctl.registries))


def issue_credential(state, cred_type, issuer_alias, holder_alias, attributes,
                     auth_said=None, registry=None):
    """Shared issuance path used by both `issue` and `demo`."""
    spec = CRED_RULES[cred_type]
    issuer = load_controller(state, issuer_alias)
    holder = load_controller(state, holder_alias)

    missing = [a for a in spec["attrs"] if a not in attributes]
    if missing:
        raise ValueError(
            f"{cred_type} credential requires {', '.join(spec['attrs'])}; "
            f"missing: {', '.join(missing)}"
        )
    if "LEI" in attributes:
        ok, why = lei_validate(attributes["LEI"])
        if not ok:
            raise ValueError(f"LEI {attributes['LEI']}: {why}")

    edges = None
    expected = [t for t in (spec.get("edge_from"), spec.get("alt_edge_from")) if t]
    if expected:
        if not auth_said:
            raise ValueError(
                f"{cred_type} must be authorised by a {' or '.join(expected)} "
                "credential; pass --auth <SAID>"
            )
        target = state["credentials"].get(auth_said)
        if not target:
            raise ValueError(f"authorising credential {auth_said} not found")
        if target["type"] not in expected:
            raise ValueError(
                f"{cred_type} must chain to a {' or '.join(expected)} credential, "
                f"but {auth_said[:12]}... is a {target['type']} credential"
            )
        edge_name = spec["edge_name"]
        if target["type"] == spec.get("alt_edge_from"):
            edge_name = "auth"
        edges = keri.make_edge(edge_name, target["acdc"], spec.get("operator"))

    reg_name = resolve_registry(issuer, registry)
    said, acdc = keri.build_acdc(
        issuer_aid=issuer.aid,
        registry_key=issuer.registries[reg_name]["regk"],
        schema_said=SCHEMAS[cred_type],
        holder_aid=holder.aid,
        attributes=attributes,
        edges=edges,
        rules=RULES_BLOCK,
        private=spec.get("private", False),
    )
    issuer.issue_event(reg_name, said)
    sig = keri.sign_bytes(issuer.seed, cesr.dumps(acdc))
    store_controller(state, issuer)
    state["credentials"][said] = {
        "type": cred_type,
        "issuer": issuer_alias,
        "holder": holder_alias,
        "registry": reg_name,
        "acdc": acdc,
        "sig": sig,
        "issuer_key_at_issuance": issuer.verkey,
    }
    return said, acdc


def cmd_issue(args):
    state = load_state(args.dir)
    attributes = {}
    if args.data:
        try:
            attributes = json.loads(args.data)
        except json.JSONDecodeError as e:
            die(f"--data is not valid JSON: {e}")
    for key, val in (("LEI", args.lei), ("personLegalName", args.person),
                     ("officialRole", args.role),
                     ("engagementContextRole", args.context_role),
                     ("AID", args.subject_aid)):
        if val:
            attributes[key] = val
    try:
        said, acdc = issue_credential(
            state, args.type, args.issuer, args.holder, attributes,
            auth_said=args.auth, registry=args.registry,
        )
    except (ValueError, KeyError) as e:
        die(str(e))
    save_state(state, args.dir)
    print(f"issued {SCHEMA_NAMES[args.type]}")
    print(f"  SAID   : {said}")
    print(f"  issuer : {args.issuer} ({acdc['i']})")
    print(f"  holder : {args.holder} ({acdc['a']['i']})")
    if args.json:
        print(json.dumps(acdc, indent=2, ensure_ascii=False))


def cmd_revoke(args):
    state = load_state(args.dir)
    entry = state["credentials"].get(args.said)
    if not entry:
        die(f"unknown credential {args.said}")
    issuer = load_controller(state, entry["issuer"])
    try:
        rev = issuer.revoke_event(entry["registry"], args.said)
    except (KeyError, ValueError) as e:
        die(str(e))
    store_controller(state, issuer)
    save_state(state, args.dir)
    print(f"revoked {args.said}")
    print(f"  TEL event : {rev['d']} at {rev['dt']}")
    print("  Any credential chaining to this one will now fail verification.")


# ---------------------------------------------------------------- verification
def verify_credential(state, said, depth=0, seen=None):
    """Walk a credential back to the root of trust, checking every hop.

    Returns (ok, list_of_findings). Findings are (level, text) with level in
    {'ok','fail','info'} so callers can render them however they like.
    """
    seen = seen or set()
    findings = []
    indent = "  " * depth

    entry = state["credentials"].get(said)
    if not entry:
        return False, [("fail", f"{indent}credential {said} not found")]
    if said in seen:
        return False, [("fail", f"{indent}cycle detected at {said}")]
    seen.add(said)

    acdc = entry["acdc"]
    label = SCHEMA_NAMES.get(entry["type"], entry["type"])
    findings.append(("info", f"{indent}{label}"))
    findings.append(("info", f"{indent}  SAID {said}"))
    ok = True

    # 1. structural integrity
    good, detail = cesr.verify_said(acdc, label="d")
    if good:
        findings.append(("ok", f"{indent}  SAID recomputes -- contents unaltered"))
    else:
        ok = False
        findings.append(("fail", f"{indent}  SAID mismatch: {detail}"))

    # 2. schema is a recognised vLEI credential type
    if acdc["s"] == SCHEMAS.get(entry["type"]):
        findings.append(("ok", f"{indent}  schema SAID matches the {entry['type']} schema"))
    else:
        ok = False
        findings.append(("fail", f"{indent}  unrecognised schema {acdc['s']}"))

    # 3. issuer signature
    issuer = state["actors"].get(entry["issuer"])
    if issuer and keri.verify_bytes(entry["issuer_key_at_issuance"],
                                    cesr.dumps(acdc), entry["sig"]):
        findings.append(("ok", f"{indent}  issuer signature valid ({entry['issuer']})"))
    else:
        ok = False
        findings.append(("fail", f"{indent}  issuer signature invalid"))

    # 4. LEI checksum, where the credential carries one
    lei = acdc["a"].get("LEI")
    if lei:
        good, why = lei_validate(lei)
        findings.append((("ok" if good else "fail"),
                         f"{indent}  LEI {lei}: {why} (ISO 17442-1)"))
        ok = ok and good

    # 5. revocation status from the issuer's TEL
    status = keri.Controller(entry["issuer"], issuer).credential_status(said) if issuer else None
    if status == "issued":
        findings.append(("ok", f"{indent}  registry status: issued, not revoked"))
    else:
        ok = False
        findings.append(("fail", f"{indent}  registry status: {status or 'unknown'}"))

    # 6. follow the edge to the authorising credential
    edges = acdc.get("e")
    if not edges:
        if acdc["i"] == state.get("root_aid"):
            findings.append(("ok", f"{indent}  issued directly by the root of trust -- chain complete"))
        else:
            ok = False
            findings.append(("fail", f"{indent}  no edge and issuer is not the root of trust"))
        return ok, findings

    for name, node in edges.items():
        if name == "d":
            continue
        target_said = node["n"]
        target = state["credentials"].get(target_said)
        if not target:
            ok = False
            findings.append(("fail", f"{indent}  edge {name!r} points at unknown credential"))
            continue
        if target["acdc"]["s"] != node["s"]:
            ok = False
            findings.append(("fail", f"{indent}  edge {name!r} schema pin does not match target"))
            continue
        operator = node.get("o")
        if operator == "I2I":
            if acdc["i"] == target["acdc"]["a"]["i"]:
                findings.append(("ok", f"{indent}  edge {name!r} I2I satisfied: issuer holds the authorisation"))
            else:
                ok = False
                findings.append(("fail", f"{indent}  edge {name!r} I2I violated: issuer of this credential is "
                                         f"not the issuee of {target_said[:12]}..."))
                continue
        else:
            findings.append(("ok", f"{indent}  edge {name!r} -> {target['type']} credential"))
        sub_ok, sub = verify_credential(state, target_said, depth + 1, seen)
        findings.extend(sub)
        ok = ok and sub_ok

    return ok, findings


def cmd_verify(args):
    state = load_state(args.dir)
    ok, findings = verify_credential(state, args.said)
    symbols = {"ok": "  [ok]  ", "fail": "  [FAIL]", "info": "        "}
    print("Verification walk (leaf to root of trust)\n")
    for level, text in findings:
        print(f"{symbols[level]} {text}" if level != "info" else f"        {text}")
    print()
    print("RESULT: chain verified" if ok else "RESULT: chain BROKEN")
    sys.exit(0 if ok else 2)


def cmd_present(args):
    """Build a presentation bundle: the credential plus everything a verifier
    needs to check it without asking the issuer anything."""
    state = load_state(args.dir)
    bundle = {"credential": None, "chain": [], "kels": {}, "tels": {}}
    stack, seen = [args.said], set()
    while stack:
        said = stack.pop()
        if said in seen:
            continue
        seen.add(said)
        entry = state["credentials"].get(said)
        if not entry:
            die(f"unknown credential {said}")
        item = {"said": said, "type": entry["type"], "acdc": entry["acdc"],
                "sig": entry["sig"], "issuer_key": entry["issuer_key_at_issuance"]}
        if said == args.said:
            bundle["credential"] = item
        else:
            bundle["chain"].append(item)
        actor = state["actors"][entry["issuer"]]
        bundle["kels"][actor["aid"]] = actor["kel"]
        for reg in actor["registries"].values():
            if said in reg["tel"]:
                bundle["tels"][said] = reg["tel"][said]
        for name, node in (entry["acdc"].get("e") or {}).items():
            if name != "d":
                stack.append(node["n"])
    text = json.dumps(bundle, indent=2, ensure_ascii=False)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"presentation bundle written to {args.out} "
              f"({len(bundle['chain']) + 1} credentials, {len(bundle['kels'])} KELs)")
    else:
        print(text)


def cmd_chain(args):
    """Render the current trust chain as Mermaid -- useful for slides and docs."""
    state = load_state(args.dir)
    lines = ["graph TD"]
    for alias, s in state["actors"].items():
        tag = " (root)" if s["aid"] == state.get("root_aid") else ""
        lines.append(f'    {alias}["{alias}{tag}<br/>{s["aid"][:16]}..."]')
    for said, entry in state["credentials"].items():
        status = keri.Controller(
            entry["issuer"], state["actors"][entry["issuer"]]
        ).credential_status(said)
        if status == "revoked":
            lines.append(f'    {entry["issuer"]} -.->|"{entry["type"]} (revoked)"| {entry["holder"]}')
        else:
            lines.append(f'    {entry["issuer"]} -->|"{entry["type"]}"| {entry["holder"]}')
    print("\n".join(lines))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print(f"\n(written to {args.out})", file=sys.stderr)


def cmd_status(args):
    state = load_state(args.dir)
    print(f"mode            : {state['mode']}")
    print(f"digest          : {state['digest']}")
    print(f"signing backend : {state['signing_backend']}")
    print(f"root of trust   : {state.get('root_aid') or '(not set)'}")
    print(f"actors          : {len(state['actors'])}")
    print(f"credentials     : {len(state['credentials'])}")
    for said, e in state["credentials"].items():
        st = keri.Controller(e["issuer"], state["actors"][e["issuer"]]).credential_status(said)
        print(f"  {e['type']:<9} [{st:<7}] {e['issuer']} -> {e['holder']}")
        print(f"  {'':<9} {said}")


def cmd_lei(args):
    if args.action == "check":
        ok, why = lei_validate(args.value)
        print(f"{args.value.upper()}: {'VALID' if ok else 'INVALID'} -- {why}")
        sys.exit(0 if ok else 2)
    base = args.value.upper()
    if len(base) != 18:
        die("provide the 18-character LEI body without check digits")
    print(base + lei_check_digits(base))


# --------------------------------------------------------------------- demo
def cmd_demo(args):
    """Build the whole GLEIF trust chain end to end, narrating each step."""
    root = args.dir
    if os.path.exists(state_path(root)):
        shutil.rmtree(ws_path(root))
    cmd_init(argparse.Namespace(dir=root, force=True))
    state = load_state(root)
    print()

    lei_le = args.lei or ("8755001" + "ELOZEL05BVX")
    lei_le = lei_le[:18]
    lei_le = lei_le + lei_check_digits(lei_le)
    lei_qvi = "5493001KJTIIGC8Y1R"
    lei_qvi = lei_qvi + lei_check_digits(lei_qvi)

    steps = []

    def actor(alias, registry=None, root_flag=False, delegator=None):
        ctl = keri.Controller(alias)
        parent_aid = state["actors"][delegator]["aid"] if delegator else None
        ctl.incept(delegator=parent_aid)
        if registry:
            ctl.create_registry(registry)
        store_controller(state, ctl)
        if root_flag:
            state["root_aid"] = ctl.aid
        print(f"  {alias:<8} {ctl.aid}")
        return ctl

    print("Step 0 -- create the actors and their key event logs")
    actor("gleif", registry="gleifRegistry", root_flag=True)
    actor("qvi", registry="qviRegistry", delegator="gleif")
    actor("le", registry="leRegistry")
    actor("person")
    print("         (qvi's AID is delegated from gleif -- a 'dip' inception event,")
    print("          so compromising the QVI alone cannot re-anchor its authority)")

    def step(n, title, cred_type, issuer, holder, attrs, auth=None):
        said, _ = issue_credential(state, cred_type, issuer, holder, attrs, auth_said=auth)
        print(f"\nStep {n} -- {title}")
        print(f"  {issuer} -> {holder}")
        print(f"  SAID {said}")
        steps.append((cred_type, said))
        return said

    qvi_said = step(1, "GLEIF qualifies the vLEI issuer", "qvi",
                    "gleif", "qvi", {"LEI": lei_qvi})

    le_said = step(2, "QVI issues the Legal Entity credential", "le",
                   "qvi", "le", {"LEI": lei_le}, auth=qvi_said)

    person_aid = state["actors"]["person"]["aid"]
    oor_auth_said = step(3, "Legal Entity authorises an official role", "oor-auth",
                         "le", "qvi",
                         {"AID": person_aid, "LEI": lei_le,
                          "personLegalName": args.person, "officialRole": args.role},
                         auth=le_said)

    oor_said = step(4, "QVI issues the OOR credential to the person", "oor",
                    "qvi", "person",
                    {"LEI": lei_le, "personLegalName": args.person,
                     "officialRole": args.role},
                    auth=oor_auth_said)

    ecr_said = step(5, "Legal Entity issues an engagement context role directly", "ecr",
                    "le", "person",
                    {"LEI": lei_le, "personLegalName": args.person,
                     "engagementContextRole": args.context_role},
                    auth=le_said)

    save_state(state, root)

    print("\n" + "=" * 72)
    print("Verifying the OOR credential back to GLEIF")
    print("=" * 72 + "\n")
    ok, findings = verify_credential(state, oor_said)
    symbols = {"ok": "  [ok]  ", "fail": "  [FAIL]", "info": "        "}
    for level, text in findings:
        print(f"{symbols[level]} {text}" if level != "info" else f"        {text}")
    print("\nRESULT: chain verified" if ok else "\nRESULT: chain BROKEN")

    print("\nTry next:")
    print(f"  python {os.path.basename(__file__)} verify --said {ecr_said}")
    print(f"  python {os.path.basename(__file__)} revoke --said {le_said}")
    print(f"  python {os.path.basename(__file__)} verify --said {oor_said}"
          "     # now fails: revoking the LE credential collapses everything below it")
    print(f"  python {os.path.basename(__file__)} chain")
    print(f"  python {os.path.basename(__file__)} present --said {oor_said} --out presentation.json")


# ----------------------------------------------------------------- real mode
COMPOSE = "docker-compose.yaml"


def assets_dir():
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "assets")


def cmd_real(args):
    if args.action == "scaffold":
        target = args.dir or os.getcwd()
        src = os.path.join(assets_dir(), COMPOSE)
        dst = os.path.join(target, COMPOSE)
        shutil.copy(src, dst)
        print(f"wrote {dst}")
        print("Bring the stack up with: python vlei_sandbox.py real up")
        print("Then read references/real-environment.md for the Signify-TS walkthrough.")
        return

    if shutil.which("docker") is None:
        die("docker not found on PATH. Mock mode needs none of this -- "
            "run `vlei_sandbox.py demo` instead.")

    compose = os.path.join(args.dir or os.getcwd(), COMPOSE)
    if not os.path.exists(compose):
        compose = os.path.join(assets_dir(), COMPOSE)

    cmds = {
        "up": ["docker", "compose", "-f", compose, "up", "-d"],
        "down": ["docker", "compose", "-f", compose, "down", "-v"],
        "status": ["docker", "compose", "-f", compose, "ps"],
        "logs": ["docker", "compose", "-f", compose, "logs", "--tail", "50"],
    }
    result = subprocess.run(cmds[args.action])
    if args.action == "up" and result.returncode == 0:
        print("\nEndpoints:")
        print("  KERIA admin   http://localhost:3901")
        print("  KERIA boot    http://localhost:3903")
        print("  witness pool  http://localhost:5642-5644")
        print("  vLEI schemas  http://localhost:7723")
        print("\nNext: references/real-environment.md")
    sys.exit(result.returncode)


# ------------------------------------------------------------------- plumbing
def build_parser():
    p = argparse.ArgumentParser(
        prog="vlei_sandbox.py",
        description="Simulate the GLEIF vLEI trust chain locally.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--dir", default=None, help="workspace root (default: cwd)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("init", help="create a sandbox workspace")
    sp.add_argument("--force", action="store_true")
    sp.set_defaults(func=cmd_init)

    sp = sub.add_parser("demo", help="run the full six-step trust chain end to end")
    sp.add_argument("--lei", help="18-char LEI body for the legal entity")
    sp.add_argument("--person", default="Jane Doe")
    sp.add_argument("--role", default="Chief Executive Officer")
    sp.add_argument("--context-role", default="Trade Finance Officer")
    sp.set_defaults(func=cmd_demo)

    ap = sub.add_parser("actor", help="manage AID controllers")
    asub = ap.add_subparsers(dest="action", required=True)
    a = asub.add_parser("add")
    a.add_argument("--alias", required=True)
    a.add_argument("--registry", help="also create a credential registry with this name")
    a.add_argument("--delegator", help="alias of the delegating controller")
    a.add_argument("--root", action="store_true", help="mark as ecosystem root of trust")
    a.add_argument("--force", action="store_true")
    a.set_defaults(func=cmd_actor_add)
    a = asub.add_parser("list")
    a.set_defaults(func=cmd_actor_list)
    a = asub.add_parser("rotate")
    a.add_argument("--alias", required=True)
    a.set_defaults(func=cmd_actor_rotate)

    rp = sub.add_parser("registry", help="manage credential registries")
    rsub = rp.add_subparsers(dest="action", required=True)
    r = rsub.add_parser("create")
    r.add_argument("--alias", required=True)
    r.add_argument("--name", required=True)
    r.set_defaults(func=cmd_registry_create)

    sp = sub.add_parser("issue", help="issue a vLEI credential")
    sp.add_argument("--type", required=True, choices=list(SCHEMAS))
    sp.add_argument("--issuer", required=True)
    sp.add_argument("--holder", required=True)
    sp.add_argument("--auth", help="SAID of the authorising credential")
    sp.add_argument("--registry", help="issuer registry name (default: first)")
    sp.add_argument("--lei")
    sp.add_argument("--person", help="personLegalName")
    sp.add_argument("--role", help="officialRole (ISO 5009 for OOR)")
    sp.add_argument("--context-role", help="engagementContextRole")
    sp.add_argument("--subject-aid", help="AID attribute for authorisation credentials")
    sp.add_argument("--data", help="extra attributes as a JSON object")
    sp.add_argument("--json", action="store_true", help="print the full ACDC")
    sp.set_defaults(func=cmd_issue)

    sp = sub.add_parser("revoke", help="revoke a credential via its registry TEL")
    sp.add_argument("--said", required=True)
    sp.set_defaults(func=cmd_revoke)

    sp = sub.add_parser("verify", help="walk a credential back to the root of trust")
    sp.add_argument("--said", required=True)
    sp.set_defaults(func=cmd_verify)

    sp = sub.add_parser("present", help="export a self-contained presentation bundle")
    sp.add_argument("--said", required=True)
    sp.add_argument("--out")
    sp.set_defaults(func=cmd_present)

    sp = sub.add_parser("chain", help="render the trust chain as Mermaid")
    sp.add_argument("--out")
    sp.set_defaults(func=cmd_chain)

    sp = sub.add_parser("status", help="summarise the sandbox")
    sp.set_defaults(func=cmd_status)

    sp = sub.add_parser("lei", help="ISO 17442-1 check digit tools")
    sp.add_argument("action", choices=["check", "make"])
    sp.add_argument("value")
    sp.set_defaults(func=cmd_lei)

    sp = sub.add_parser("real", help="drive the Docker-based KERIA environment")
    sp.add_argument("action", choices=["scaffold", "up", "down", "status", "logs"])
    sp.set_defaults(func=cmd_real)

    return p


def main():
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
