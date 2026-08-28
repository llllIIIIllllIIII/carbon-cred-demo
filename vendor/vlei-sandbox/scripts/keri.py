"""A small, honest model of KERI and ACDC.

This is not a reimplementation of keripy. It is a teaching and prototyping model
that keeps the parts which determine whether an application design is sound --
key event logs, pre-rotation, credential registries with revocation state,
self-addressing identifiers, and chained credentials with edge operators -- and
omits the parts that only matter in a distributed deployment (witness receipts,
OOBI discovery over the wire, mailbox delivery, multisig coordination).

Everything produced here is structurally shaped like real KERI/ACDC output and
verifies under the same rules, so logic proven against this model transfers to
KERIA/Signify with the network layer swapped in.
"""

import datetime

import cesr
import ed25519_compat as ed


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%f+00:00"
    )


# --------------------------------------------------------------------- keys
def new_keypair():
    """Return (seed_qb64, verkey_qb64) for a transferable Ed25519 key."""
    seed = ed.generate_seed()
    pub = ed.public_key(seed)
    return cesr.encode(cesr.CODE_ED25519_SEED, seed), cesr.encode(cesr.CODE_ED25519, pub)


def sign_bytes(seed_qb64, data):
    seed = cesr.decode(seed_qb64)
    return cesr.encode(cesr.CODE_ED25519_SIG, ed.sign(seed, data))


def verify_bytes(verkey_qb64, data, sig_qb64):
    try:
        return ed.verify(cesr.decode(verkey_qb64), data, cesr.decode(sig_qb64))
    except Exception:
        return False


# ------------------------------------------------------------------ controller
class Controller:
    """An AID controller: current keys, the pre-rotation commitment, and a KEL.

    Pre-rotation is the security property worth understanding here. At inception
    the controller commits to a *digest* of the next key set, not the key itself.
    An attacker who steals today's signing key still cannot rotate the identifier,
    because they cannot produce a key set matching a digest they have never seen.
    This is why KERI identifiers survive key compromise while X.509 certificates
    must be revoked and reissued.
    """

    def __init__(self, alias, state=None):
        self.alias = alias
        if state:
            self.__dict__.update(state)
        else:
            self.seed, self.verkey = new_keypair()
            self.next_seed, self.next_verkey = new_keypair()
            self.aid = None
            self.kel = []
            self.registries = {}

    # ---- serialisation
    def to_state(self):
        return {
            "alias": self.alias,
            "aid": self.aid,
            "seed": self.seed,
            "verkey": self.verkey,
            "next_seed": self.next_seed,
            "next_verkey": self.next_verkey,
            "kel": self.kel,
            "registries": self.registries,
        }

    # ---- key events
    def incept(self, witnesses=None, toad=0, delegator=None):
        """Create the inception event. For a self-addressing AID the identifier
        prefix IS the SAID of this event, which is what makes the identifier
        self-certifying: no registry is needed to bind key to name."""
        witnesses = witnesses or []
        event = {
            "v": cesr.versify("KERI", "JSON", 0),
            "t": "dip" if delegator else "icp",
            "d": "",
            "i": "",
            "s": "0",
            "kt": "1",
            "k": [self.verkey],
            "nt": "1",
            "n": [cesr.digest(self.next_verkey.encode())],
            "bt": f"{toad:x}",
            "b": witnesses,
            "c": [],
            "a": [],
        }
        if delegator:
            event["di"] = delegator
        said, event = cesr.saidify(event, label="d", also=("i",))
        self.aid = said
        self.kel = [self._sealed(event)]
        return event

    def rotate(self):
        """Rotate to the pre-committed key set and commit to a fresh one."""
        self.seed, self.verkey = self.next_seed, self.next_verkey
        self.next_seed, self.next_verkey = new_keypair()
        prior = self.kel[-1]["event"]
        event = {
            "v": cesr.versify("KERI", "JSON", 0),
            "t": "rot",
            "d": "",
            "i": self.aid,
            "s": f"{len(self.kel):x}",
            "p": prior["d"],
            "kt": "1",
            "k": [self.verkey],
            "nt": "1",
            "n": [cesr.digest(self.next_verkey.encode())],
            "bt": "0",
            "br": [],
            "ba": [],
            "a": [],
        }
        _, event = cesr.saidify(event, label="d")
        self.kel.append(self._sealed(event))
        return event

    def interact(self, seals):
        """Anchor arbitrary seals (registry inceptions, credential issuances)
        into the KEL. Anchoring is what gives a credential's issuance a place in
        the issuer's immutable history rather than floating free."""
        prior = self.kel[-1]["event"]
        event = {
            "v": cesr.versify("KERI", "JSON", 0),
            "t": "ixn",
            "d": "",
            "i": self.aid,
            "s": f"{len(self.kel):x}",
            "p": prior["d"],
            "a": seals,
        }
        _, event = cesr.saidify(event, label="d")
        self.kel.append(self._sealed(event))
        return event

    def _sealed(self, event):
        return {"event": event, "sig": sign_bytes(self.seed, cesr.dumps(event))}

    # ---- credential registry (TEL)
    def create_registry(self, name):
        """A credential registry is a transaction event log whose inception is
        anchored in the issuer's KEL. Issuance and revocation are events in it,
        which is how a verifier can check revocation status cryptographically
        instead of trusting a CRL endpoint."""
        vcp = {
            "v": cesr.versify("KERI", "JSON", 0),
            "t": "vcp",
            "d": "",
            "i": "",
            "ii": self.aid,
            "s": "0",
            "c": ["NB"],
            "bt": "0",
            "b": [],
            "n": cesr.encode(cesr.CODE_SALT_128, ed.generate_seed()[:16]),
        }
        regk, vcp = cesr.saidify(vcp, label="d", also=("i",))
        self.interact([{"i": regk, "s": "0", "d": vcp["d"]}])
        self.registries[name] = {"regk": regk, "vcp": vcp, "tel": {}}
        return regk

    def issue_event(self, registry_name, credential_said):
        reg = self.registries[registry_name]
        iss = {
            "v": cesr.versify("KERI", "JSON", 0),
            "t": "iss",
            "d": "",
            "i": credential_said,
            "s": "0",
            "ri": reg["regk"],
            "dt": now(),
        }
        _, iss = cesr.saidify(iss, label="d")
        reg["tel"][credential_said] = [iss]
        self.interact([{"i": credential_said, "s": "0", "d": iss["d"]}])
        return iss

    def revoke_event(self, registry_name, credential_said):
        reg = self.registries[registry_name]
        events = reg["tel"].get(credential_said)
        if not events:
            raise KeyError(f"credential {credential_said} not in registry {registry_name}")
        if any(e["t"] == "rev" for e in events):
            raise ValueError("credential already revoked")
        rev = {
            "v": cesr.versify("KERI", "JSON", 0),
            "t": "rev",
            "d": "",
            "i": credential_said,
            "s": "1",
            "ri": reg["regk"],
            "p": events[-1]["d"],
            "dt": now(),
        }
        _, rev = cesr.saidify(rev, label="d")
        events.append(rev)
        self.interact([{"i": credential_said, "s": "1", "d": rev["d"]}])
        return rev

    def credential_status(self, credential_said):
        for reg in self.registries.values():
            events = reg["tel"].get(credential_said)
            if events:
                return "revoked" if any(e["t"] == "rev" for e in events) else "issued"
        return None


# ----------------------------------------------------------------------- ACDC
def build_acdc(issuer_aid, registry_key, schema_said, holder_aid, attributes,
               edges=None, rules=None, private=False):
    """Assemble an Authentic Chained Data Container.

    Sections, in the order a verifier reads them:
      i  issuer AID          -- who is asserting this
      ri registry            -- where issuance/revocation state lives
      s  schema SAID         -- what shape the payload must have
      a  attribute block     -- the claims, including the issuee `i`
      e  edge block          -- pointers to the credentials that authorise this one
      r  rule block          -- the legal disclaimers that bound the assertion

    The edge block is the whole trick behind the vLEI: authority is not asserted,
    it is *linked*, and the link is a cryptographic digest that cannot be forged.
    """
    attrs = {"d": "", "i": holder_aid, "dt": now()}
    attrs.update(attributes)
    _, attrs = cesr.saidify(attrs, label="d", protocol="ACDC")

    acdc = {
        "v": cesr.versify("ACDC", "JSON", 0),
        "d": "",
        "i": issuer_aid,
        "ri": registry_key,
        "s": schema_said,
        "a": attrs,
    }
    if private:
        acdc["u"] = cesr.encode(cesr.CODE_SALT_128, ed.generate_seed()[:16])
    if edges:
        _, edges = cesr.saidify(edges, label="d", protocol="ACDC")
        acdc["e"] = edges
    if rules:
        _, rules = cesr.saidify(rules, label="d", protocol="ACDC")
        acdc["r"] = rules

    said, acdc = cesr.saidify(acdc, label="d", protocol="ACDC")
    return said, acdc


def make_edge(name, target_acdc, operator=None):
    """Build an edge block pointing at an authorising credential.

    `n` is the SAID of the target credential and `s` pins the schema it must
    have, so an attacker cannot substitute a different credential type. The
    operator constrains *who* may rely on the link:

      I2I  issuer-to-issuee: the issuer of this credential must be the issuee of
           the target. This is what stops a QVI from issuing an OOR credential
           without holding the matching authorisation from that legal entity.
      NI2I not-issuer-to-issuee: the link is informational; no identity
           correspondence is required.
    """
    edge = {"d": ""}
    node = {"n": target_acdc["d"], "s": target_acdc["s"]}
    if operator:
        node["o"] = operator
    edge[name] = node
    _, edge = cesr.saidify(edge, label="d", protocol="ACDC")
    return edge
