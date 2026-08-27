# groupsync — Anope 2.1 module

Makes [api.fuelrats.com](https://github.com/fuelrats/api.fuelrats.com) the source of truth for
**IRC channel access** (ChanServ privileges/modes). On login the module pulls a user's per-channel
role-derived flags from the API and authorizes them through ChanServ's privilege system
(`OnGroupCheckPriv`), so modes are applied durably by ChanServ. Out of scope: authentication
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
