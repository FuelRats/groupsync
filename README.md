# groupsync — Anope 2.1 module

Makes [api.fuelrats.com](https://github.com/fuelrats/api.fuelrats.com) the source of truth for
**IRC channel access** (ChanServ privileges/modes). On login the module pulls a user's per-channel
role-derived flags from the API and authorizes them through ChanServ's privilege system
(`OnGroupCheckPriv`), so modes are applied durably by ChanServ. It also accepts one-time
API-minted SASL token logins (see "SASL token login" below). Out of scope: other authentication
(the API keeps mirroring `bcrypt:` + cert into NickCore) and vhosts (HostServ).

This is a **fresh Anope 2.1.26 implementation**. The prior Anope 2.0 attempt is kept for design
reference only at `reference/groupsync-anope20.cpp.orig` (discarded — do not build).

## Design & spec

- Plan: `api.fuelrats.com` → `thoughts/plans/groupsync-implementation.md`
- Research: `thoughts/research/groupsync-irc-permission-sync.md`
- FLAGS-letter → privilege mapping (authoritative): `thoughts/research/groupsync-flags-priv-mapping.md`
- Approved role→channel→flags policy: `thoughts/research/groupsync-policy-FINAL.md` + `groupsync-group-channels.json`

## Build & deploy

Third-party module compiled **into** the Anope 2.1 Docker image (no hot MODLOAD). The image
Dockerfile clones Anope 2.1.26, drops third-party `.cpp` into `/src/modules/third/`, then
cmake+make+install. Reference 2.1 idioms: `fuelrats/offlinemsg` (2.1 port). Async HTTP pattern:
Anope `modules/database/db_sql.cpp` / `modules/extra/mysql.cpp` worker thread.

The container runs `--nofork` (`Anope::NoFork` set) → no process fork, so the curl worker thread
can be spawned safely from the module ctor in this deployment (still guard defensively).

`/* RequiredLibraries: curl,jansson */` in the source links the libs. The image Dockerfile also
needs the dev+runtime packages:

```dockerfile
# --- build stage: add to the apt-get install line ---
#   libcurl4-openssl-dev libjansson-dev
COPY groupsync.cpp /src/modules/third/groupsync.cpp
# --- runtime stage: add to the apt-get install line ---
#   libcurl4 libjansson4
```

Then add the config block (`groupsync.example.conf`) to `services.conf` after chanserv/nickserv,
drop the `anope.read` bearer into the `apitokenfile` path (0600), rebuild the image, restart.

**Dev loop (stilton):** build ctx `~/anope-2.1-build` (Dockerfile clones 2.1.26, `COPY`s third
modules), config bind-mounted at `~/anope-2.1-build/testconf/conf/`, container `anope-2_1-dev`.
Rebuild + restart to test; watch `testconf/logs/services.log.*`.

## SASL token login

Lets a client log in to NickServ over SASL PLAIN with a one-time token instead of the account
password (used by the rat Kiwi "Log in with Fuel Rats" flow). The API mints the token before each
connect and returns it as the SASL password:

```text
frk1:<unix ts>:<lowercase hex HMAC-SHA256(secret, "<account>|<unix ts>")>
```

`<account>` is the SASL authcid exactly as the client sends it, and `<unix ts>` is the timestamp
text exactly as it appears in the token. The key is the secret file's contents as ASCII.

`OnCheckAuthentication` accepts the token only if all of these hold, and otherwise does nothing,
so the normal password checks fail the login (904) and `badpasslimit` applies:

- the password starts with `frk1:` and the request comes from `ns_sasl_plain` (NickServ
  IDENTIFY, RECOVER, GROUP, RPC and webcpanel never accept a token);
- the password is `frk1:<digits>:<64 lowercase hex>`;
- the authcid is a registered nick (`NickAlias::Find`);
- `|now - ts| <= sasltoken_maxage`;
- the HMAC matches (constant-time compare);
- the MAC has not logged in before (used MACs are kept for 2 x maxage).

On success it logs `groupsync: SASL token login for <account> from <ip>`. `ns_sasl_plain` still
refuses suspended and unconfirmed accounts and enforces `ns_identify:maxlogins`.

Config (in the `groupsync` module block, see `groupsync.example.conf`):

- `sasltoken_secretfile`: path to a 0600 file, readable by the Anope user, holding only the
  secret (at least 32 characters). Unset means no token login. A missing, unreadable or short
  file is logged and turns token login off; channel sync keeps running.
- `sasltoken_maxage`: seconds either side of the timestamp, default 60, capped at 60.

The keys are read at module load and on every rehash. The HMAC uses the `sha256` provider from
`enc_sha2`, which must be loaded. Use a secret of its own (for example `openssl rand -hex 32`),
not the Matrix bridge's `matrix_token` secret.

## Add-on B — `m_rolesync` (UnrealIRCd module)

`m_rolesync.c` is a companion **UnrealIRCd** module (build into the IRCd, not Anope). It lets
role-holders into invite-only (`+i`) channels without a stored invite — the join-time equivalent
of the channel-mode grants above.

With `rolesync = yes` set in the groupsync Anope module block, the Anope side emits an `fr_gated`
client ModData listing each user's authorised `+i` channels (via S2S `MD`). On `PRE_LOCAL_JOIN`,
`m_rolesync` grants the join (bypassing `+i`/`+k`/`+l`) iff the channel is `+i`, the user's
`fr_gated` set contains it, and the preserved restrictions hold (`+b`/`+e` ban, `+z` secure,
`+O` oper). It is additive-only — it never denies a join — and registers ahead of
`m_autoban`/`m_fruser`. Build for the target UnrealIRCd version:

```sh
cp m_rolesync.c <unrealircd-src>/src/modules/third/
cd <unrealircd-src> && make custommodule MODULEFILE=m_rolesync
# then: loadmodule "third/m_rolesync"; in unrealircd.conf on every server
```
