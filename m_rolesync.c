/*
 * m_rolesync — groupsync join interception for invite-only channels (Add-on B).
 *
 * The Anope groupsync module sets an `fr_gated` client ModData on identified
 * users: a comma-separated list of the invite-only (+i) channels their website
 * roles authorise. This UnrealIRCd module reads that at join time and, for an
 * authorised user, lets them into a +i channel without a stored invite —
 * the join-time equivalent of the channel-mode grants groupsync already
 * applies.
 *
 * Design invariants (see thoughts/plans/groupsync-implementation.md, Add-on B):
 *   - NEVER HOOK_DENY. This module is purely additive: it can grant a join it
 *     would otherwise be denied, never block a join others would allow.
 *   - HOOK_ALLOW at PRE_LOCAL_JOIN skips can_join() ENTIRELY, so we must
 *     re-check the restrictions we intend to PRESERVE before allowing:
 *       preserve +b/+e (is_banned), +z (secure-only), +O (oper-only);
 *       bypass    +i/+k/+l (that is the whole point).
 *   - Registered with a priority that runs BEFORE m_autoban/m_fruser so our
 *     HOOK_ALLOW wins the loop and their DENY can't preempt a legitimate grant.
 *
 * ModData `fr_gated` MUST declare serialize/unserialize/free AND remote_write=1
 * (Risk 62/63): without the callbacks cmd_md silently drops the inbound MD from
 * services; without remote_write the leaf rejects services' write to a local
 * client's moddata. Build into BOTH IRC images (hub native + leaf container).
 *
 * Fetch/join race (Add-on B): the Anope groupsync module fetches access on a
 * background thread, so `fr_gated` is set a moment AFTER login. A client that
 * auto-joins a +i channel at connect can beat it — the join is denied by +i
 * before `fr_gated` exists, and nothing re-joins them when it arrives. To close
 * this, when we decline a +i join *only because `fr_gated` isn't set yet*, we
 * remember the attempt and, once `fr_gated` shows up (polled on a short timer),
 * re-drive the JOIN through the normal path (which re-enters this hook and now
 * authorises it). A set-but-excluding `fr_gated` is a genuine deny — not
 * remembered.
 */
#include "unrealircd.h"

ModuleHeader MOD_HEADER = {
    "third/m_rolesync",
    "1.1",
    "groupsync join interception for +i channels (fr_gated)",
    "fuelrats",
    "unrealircd-6",
};

/* Run ahead of m_autoban/m_fruser (priority 0): lower value = called first. */
#define ROLESYNC_JOIN_PRIO (-1000000)

/* Deferred-join retry: poll cadence, how long to keep retrying, and a cap so a
 * client spamming +i joins can't grow the list without bound. */
#define ROLESYNC_RETRY_MSEC 400
#define ROLESYNC_PENDING_TTL 6
#define ROLESYNC_PENDING_MAX 512
/* Generous fixed bound for a channel name (UnrealIRCd has no public
 * CHANNELLEN); strlcpy truncates safely regardless. */
#define ROLESYNC_CHANNAMELEN 256

/* A +i join we declined only because fr_gated hadn't synced yet. Keyed by UID
 * (re-resolved each tick, so a quit client's entry simply drops). */
typedef struct RolesyncPending {
  char uid[IDLEN + 1];
  char channel[ROLESYNC_CHANNAMELEN];
  time_t expires;
  struct RolesyncPending *next;
} RolesyncPending;

static RolesyncPending *rolesync_pending = NULL;
static int rolesync_pending_count = 0;
static Event *rolesync_retry_event = NULL;

static ModDataInfo *rolesync_md = NULL;

static const char *rolesync_serialize(ModData *m) {
  return m->str ? m->str : NULL;
}
static void rolesync_free(ModData *m) { safe_free(m->str); }
static void rolesync_unserialize(const char *str, ModData *m) {
  safe_free(m->str);
  if (str)
    safe_strdup(m->str, str);
}

/* Is `channame` present in the client's fr_gated set (comma-separated, exact
 * case-insensitive channel-name match)? */
static int rolesync_authorized(Client *client, const char *channame) {
  const char *gated = moddata_client_get(client, "fr_gated");
  if (BadPtr(gated))
    return 0;

  char buf[512];
  strlcpy(buf, gated, sizeof(buf));

  for (char *tok = strtok(buf, ","); tok; tok = strtok(NULL, ",")) {
    while (*tok == ' ')
      tok++;
    if (!strcasecmp(tok, channame))
      return 1;
  }
  return 0;
}

/* Remember a +i join declined only because fr_gated hadn't synced yet, so the
 * retry timer can re-drive it once fr_gated arrives. Idempotent per
 * uid+channel; refuses to grow past the cap. */
static void rolesync_remember(Client *client, const char *channame) {
  RolesyncPending *p;

  for (p = rolesync_pending; p; p = p->next) {
    if (!strcmp(p->uid, client->id) && !strcasecmp(p->channel, channame)) {
      p->expires = TStime() + ROLESYNC_PENDING_TTL;
      return;
    }
  }

  if (rolesync_pending_count >= ROLESYNC_PENDING_MAX)
    return;

  p = safe_alloc(sizeof(RolesyncPending));
  strlcpy(p->uid, client->id, sizeof(p->uid));
  strlcpy(p->channel, channame, sizeof(p->channel));
  p->expires = TStime() + ROLESYNC_PENDING_TTL;
  p->next = rolesync_pending;
  rolesync_pending = p;
  rolesync_pending_count++;
}

/* Poll pending deferred joins. For each: drop if the client is gone or the TTL
 * lapsed; once fr_gated has arrived, decide once — re-drive the JOIN if it now
 * authorises the channel, then drop either way. A JOIN re-enters
 * rolesync_prejoin (fr_gated now set), which re-checks the preserved
 * restrictions before allowing. */
static EVENT(rolesync_retry_ev) {
  time_t now = TStime();
  RolesyncPending **pp = &rolesync_pending;

  while (*pp) {
    RolesyncPending *p = *pp;
    int drop = 0;
    Client *client = find_client(p->uid, NULL);

    if (!client || !MyUser(client) || now > p->expires) {
      drop = 1;
    } else {
      const char *gated = moddata_client_get(client, "fr_gated");
      if (!BadPtr(gated)) {
        Channel *channel = find_channel(p->channel);
        if (channel && has_channel_mode(channel, 'i') &&
            !IsMember(client, channel) &&
            rolesync_authorized(client, channel->name)) {
          const char *parv[3];
          parv[0] = client->name;
          parv[1] = channel->name;
          parv[2] = NULL;
          do_cmd(client, NULL, "JOIN", 2, parv);
        }
        drop = 1; /* fr_gated present → resolved; stop retrying */
      }
      /* else: fr_gated still absent → keep waiting until expiry */
    }

    if (drop) {
      *pp = p->next;
      rolesync_pending_count--;
      safe_free(p);
    } else {
      pp = &p->next;
    }
  }
}

/*
 * PRE_LOCAL_JOIN: grant an authorised role-holder entry to a +i channel,
 * preserving bans / secure-only / oper-only. Additive only — never denies.
 */
static int rolesync_prejoin(Client *client, Channel *channel, const char *key) {
  /* Only intervene for invite-only channels; otherwise the normal join path
   * already decides correctly. */
  if (!has_channel_mode(channel, 'i'))
    return HOOK_CONTINUE;

  /* If fr_gated hasn't synced yet, this is likely the login-fetch race: let +i
   * decline for now, but remember so the retry timer re-drives the join once
   * fr_gated arrives. A present-but-excluding fr_gated is a genuine deny below.
   */
  if (BadPtr(moddata_client_get(client, "fr_gated"))) {
    rolesync_remember(client, channel->name);
    return HOOK_CONTINUE;
  }

  /* Only intervene for a user whose roles authorise THIS channel. */
  if (!rolesync_authorized(client, channel->name))
    return HOOK_CONTINUE;

  /* Preserve +b/+e — a banned role-holder stays out. */
  if (is_banned(client, channel, BANCHK_JOIN, NULL, NULL))
    return HOOK_CONTINUE;

  /* Preserve +z — a non-secure user stays out of a secure-only channel. */
  if (has_channel_mode(channel, 'z') && !IsSecure(client))
    return HOOK_CONTINUE;

  /* Preserve +O — a non-oper stays out of an oper-only channel. */
  if (has_channel_mode(channel, 'O') && !IsOper(client))
    return HOOK_CONTINUE;

  /* Authorised and all preserved restrictions satisfied: allow, bypassing
   * +i/+k/+l. HOOK_ALLOW stops other modules, so m_autoban/m_fruser can't
   * subsequently deny this join. */
  return HOOK_ALLOW;
}

MOD_INIT() {
  ModDataInfo mreq;

  MARK_AS_GLOBAL_MODULE(modinfo);

  memset(&mreq, 0, sizeof(mreq));
  mreq.name = "fr_gated";
  mreq.type = MODDATATYPE_CLIENT;
  mreq.serialize = rolesync_serialize;
  mreq.unserialize = rolesync_unserialize;
  mreq.free = rolesync_free;
  mreq.sync = MODDATA_SYNC_NORMAL;
  mreq.remote_write = 1;
  rolesync_md = ModDataAdd(modinfo->handle, mreq);
  if (!rolesync_md) {
    config_error("m_rolesync: ModDataAdd(fr_gated) failed");
    return MOD_FAILED;
  }

  HookAdd(modinfo->handle, HOOKTYPE_PRE_LOCAL_JOIN, ROLESYNC_JOIN_PRIO,
          rolesync_prejoin);

  rolesync_retry_event =
      EventAdd(modinfo->handle, "rolesync_retry", rolesync_retry_ev, NULL,
               ROLESYNC_RETRY_MSEC, 0);
  return MOD_SUCCESS;
}

MOD_LOAD() { return MOD_SUCCESS; }

MOD_UNLOAD() {
  RolesyncPending *p, *next;

  if (rolesync_retry_event) {
    EventDel(rolesync_retry_event);
    rolesync_retry_event = NULL;
  }
  for (p = rolesync_pending; p; p = next) {
    next = p->next;
    safe_free(p);
  }
  rolesync_pending = NULL;
  rolesync_pending_count = 0;
  return MOD_SUCCESS;
}
