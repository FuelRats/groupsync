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
 */
#include "unrealircd.h"

ModuleHeader MOD_HEADER = {
    "third/m_rolesync",
    "1.0",
    "groupsync join interception for +i channels (fr_gated)",
    "fuelrats",
    "unrealircd-6",
};

/* Run ahead of m_autoban/m_fruser (priority 0): lower value = called first. */
#define ROLESYNC_JOIN_PRIO (-1000000)

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

/*
 * PRE_LOCAL_JOIN: grant an authorised role-holder entry to a +i channel,
 * preserving bans / secure-only / oper-only. Additive only — never denies.
 */
static int rolesync_prejoin(Client *client, Channel *channel, const char *key) {
  /* Only intervene for invite-only channels; otherwise the normal join path
   * already decides correctly. */
  if (!has_channel_mode(channel, 'i'))
    return HOOK_CONTINUE;

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
  return MOD_SUCCESS;
}

MOD_LOAD() { return MOD_SUCCESS; }
MOD_UNLOAD() { return MOD_SUCCESS; }
