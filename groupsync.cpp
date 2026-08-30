/*
 * groupsync — makes api.fuelrats.com the source of truth for IRC channel
 * access.
 *
 * On login (and on a NickServ GROUPSYNC push) the module fetches a user's
 * per-channel role flags from the API over a background worker thread, caches
 * them keyed by account email, and authorizes them through ChanServ's privilege
 * system via OnGroupCheckPriv. ChanServ then applies the corresponding channel
 * status modes durably (the direct-mode-set path is not durable —
 * SetCorrectModes strips modes from users lacking the privilege).
 *
 * Out of scope: authentication (the API keeps mirroring bcrypt + cert into
 * NickCore) and vhosts (HostServ). This module sends neither.
 *
 * Built against the Anope 2.1.26 module API. See README.md + the api repo
 * thoughts/plans/groupsync-implementation.md for the full design.
 *
 * Copyright 2026 The Fuel Rats Mischief
 * Author: Alex Sørlie
 */

/// BEGIN CMAKE
///   pkg_search_module("CURL" IMPORTED_TARGET REQUIRED "libcurl")
///   target_link_libraries(${SO} PRIVATE PkgConfig::CURL)
///   pkg_search_module("JANSSON" IMPORTED_TARGET REQUIRED "jansson")
///   target_link_libraries(${SO} PRIVATE PkgConfig::JANSSON)
/// END CMAKE

#include "module.h"

#include <curl/curl.h>
#include <jansson.h>

#include <atomic>
#include <cctype>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <fstream>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace {
/* Max requests queued for the worker before new ones are dropped (Risk 14). */
const size_t QUEUE_CAP = 256;
/* Default per-request API timeout in seconds. */
const long DEFAULT_TIMEOUT = 5;

/* A user's cached channel access: lowercased channel name -> the set of
 * Anope privilege NAMES the group-configured FLAGS letters expand to. */
using ChannelPrivs = std::map<std::string, std::set<std::string>>;

std::string ToLower(const std::string &in) {
  std::string out(in);
  for (auto &ch : out)
    ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
  return out;
}

/* FLAGS letter -> Anope privilege name(s). Authoritative mapping from the
 * running chanserv.conf (see
 * thoughts/research/groupsync-flags-priv-mapping.md). Any letter not in this
 * table is invalid and dropped on parse (Risk 41). */
const std::map<char, std::vector<std::string>> &FlagPrivs() {
  static const std::map<char, std::vector<std::string>> map = {
      {'f', {"ACCESS_CHANGE", "ACCESS_LIST"}},
      {'K', {"AKICK", "BADWORDS", "SIGNKICK"}},
      {'s', {"ASSIGN", "MODE", "SET"}},
      {'H', {"AUTOHALFOP"}},
      {'O', {"AUTOOP"}},
      {'Q', {"AUTOOWNER"}},
      {'A', {"AUTOPROTECT"}},
      {'V', {"AUTOVOICE"}},
      {'b', {"BAN"}},
      {'c', {"FANTASY"}},
      {'F', {"FOUNDER"}},
      {'G', {"GETKEY"}},
      {'h', {"HALFOP", "HALFOPME"}},
      {'I', {"INFO"}},
      {'i', {"INVITE"}},
      {'k', {"KICK"}},
      {'m', {"MEMO"}},
      {'N', {"NOKICK"}},
      {'o', {"OP", "OPME"}},
      {'q', {"OWNER", "OWNERME"}},
      {'a', {"PROTECT", "PROTECTME"}},
      {'B', {"SAY"}},
      {'t', {"TOPIC"}},
      {'u', {"UNBAN"}},
      {'U', {"UNBANME"}},
      {'v', {"VOICE", "VOICEME"}},
  };
  return map;
}

struct FetchRequest final {
  std::string email;
  uint64_t accountId = 0; // NickCore::GetId() handle for applying; 0 if unknown
};

// One role from the API. `hidden` roles (opers Anope already whois-tags, and
// the internal service group) are still delivered so the module can RETRACT any
// stale SWHOIS line for them; they are never set.
struct RoleTag final {
  std::string name;    // group machine name → SWHOIS line tag "fr-role:<name>"
  std::string display; // the whois text (ignored when hidden)
  bool hidden = false;
};

struct FetchResult final {
  std::string email;
  uint64_t accountId = 0;
  bool ok =
      false; // false = fetch/parse error → keep cache, do NOT revoke (Risk 44)
  long httpError = 0; // -1 curl error, else HTTP status when ok == false
  unsigned droppedFlags = 0;
  ChannelPrivs channels; // empty (with ok == true) means "no access" → revoke
  std::vector<RoleTag> roles; // rendered as SWHOIS lines (Add-on A)
};

size_t WriteCallback(char *ptr, size_t size, size_t nmemb, void *userdata) {
  auto *buf = static_cast<std::string *>(userdata);
  buf->append(ptr, size * nmemb);
  return size * nmemb;
}
} // namespace

class GroupsyncModule;

/*
 * Background worker: owns the blocking curl+jansson work. Inherits Thread
 * (which is a Pipe), so it can wake the main thread via Notify() → OnNotify().
 * The worker NEVER touches Anope objects or Log() — it only produces
 * plain-string FetchResults that the main thread consumes in OnNotify (Risk
 * 40).
 */
class GroupsyncWorker final : public Thread {
private:
  GroupsyncModule *module;

  std::mutex mutex;
  std::condition_variable cond;
  std::atomic<bool> stopping{false};
  std::deque<FetchRequest> queue;
  std::deque<FetchResult> results;

  /* Config snapshot, guarded by mutex so OnReload can update it safely. */
  std::string apiurl;
  std::string token;
  long timeout = DEFAULT_TIMEOUT;

  FetchResult DoFetch(const FetchRequest &req, const std::string &url_base,
                      const std::string &bearer, long tmo) {
    FetchResult res;
    res.email = req.email;
    res.accountId = req.accountId;

    CURL *curl = curl_easy_init();
    if (!curl)
      return res;

    char *escaped = curl_easy_escape(curl, req.email.c_str(), 0);
    std::string url = url_base + "/anope?email=" + (escaped ? escaped : "");
    if (escaped)
      curl_free(escaped);

    std::string body;
    std::string authHeader = "Authorization: Bearer " + bearer;
    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, authHeader.c_str());

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, tmo);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);

    CURLcode rc = curl_easy_perform(curl);
    long httpCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (rc != CURLE_OK) {
      res.httpError = -1;
      return res;
    }
    if (httpCode != 200) {
      res.httpError = httpCode;
      return res;
    }

    json_error_t jerr;
    json_t *root = json_loads(body.c_str(), 0, &jerr);
    if (!root)
      return res;

    json_t *channels = json_object_get(root, "channels");
    if (json_is_object(channels)) {
      const char *chan;
      json_t *value;
      json_object_foreach(channels, chan, value) {
        if (!json_is_string(value))
          continue;
        std::string flags = json_string_value(value);
        std::set<std::string> privs;
        for (char letter : flags) {
          auto it = FlagPrivs().find(letter);
          if (it == FlagPrivs().end()) {
            ++res.droppedFlags;
            continue;
          }
          for (const auto &priv : it->second)
            privs.insert(priv);
        }
        res.channels[ToLower(chan)] = std::move(privs);
      }
    }

    json_t *roles = json_object_get(root, "roles");
    if (json_is_array(roles)) {
      size_t idx;
      json_t *entry;
      json_array_foreach(roles, idx, entry) {
        if (!json_is_object(entry))
          continue;
        json_t *name = json_object_get(entry, "name");
        json_t *display = json_object_get(entry, "display");
        json_t *hidden = json_object_get(entry, "hidden");
        if (!json_is_string(name))
          continue;
        std::string tagName = json_string_value(name);
        std::string text =
            json_is_string(display) ? json_string_value(display) : tagName;
        res.roles.emplace_back(
            RoleTag{std::move(tagName), std::move(text), json_is_true(hidden)});
      }
    }

    json_decref(root);
    res.ok = true;
    return res;
  }

public:
  GroupsyncWorker(GroupsyncModule *mod, const std::string &url,
                  const std::string &bearer, long tmo)
      : module(mod), apiurl(url), token(bearer), timeout(tmo) {}

  void UpdateConfig(const std::string &url, const std::string &bearer,
                    long tmo) {
    std::lock_guard<std::mutex> lock(this->mutex);
    this->apiurl = url;
    this->token = bearer;
    this->timeout = tmo;
  }

  /* Synchronous fetch for the push path (Risk 48): snapshots the config and
   * runs the blocking curl inline so the caller can apply + acknowledge before
   * replying. Uses its own curl easy handle, so it is safe to run on the main
   * thread concurrently with the worker's own DoFetch. */
  FetchResult FetchNow(const FetchRequest &req) {
    std::string url;
    std::string bearer;
    long tmo;
    {
      std::lock_guard<std::mutex> lock(this->mutex);
      url = this->apiurl;
      bearer = this->token;
      tmo = this->timeout;
    }
    return this->DoFetch(req, url, bearer, tmo);
  }

  void Enqueue(const FetchRequest &req) {
    {
      std::lock_guard<std::mutex> lock(this->mutex);
      if (this->queue.size() >= QUEUE_CAP)
        return;
      for (const auto &pending : this->queue)
        if (pending.accountId == req.accountId && pending.email == req.email)
          return;
      this->queue.push_back(req);
    }
    this->cond.notify_one();
  }

  void Stop() {
    this->stopping = true;
    this->cond.notify_all();
  }

  void Run() override {
    while (!this->stopping) {
      FetchRequest req;
      std::string url;
      std::string bearer;
      long tmo;
      {
        std::unique_lock<std::mutex> lock(this->mutex);
        this->cond.wait(
            lock, [this] { return !this->queue.empty() || this->stopping; });
        if (this->stopping)
          break;
        req = this->queue.front();
        this->queue.pop_front();
        url = this->apiurl;
        bearer = this->token;
        tmo = this->timeout;
      }

      FetchResult res = this->DoFetch(req, url, bearer, tmo);

      {
        std::lock_guard<std::mutex> lock(this->mutex);
        this->results.push_back(std::move(res));
      }
      this->Notify();
    }
  }

  /* Runs on the MAIN thread. Safe to touch Anope objects + Log here. */
  void OnNotify() override;
};

/*
 * NickServ GROUPSYNC <email> — oper/U-lined trigger to re-sync a user without
 * re-login (the API-owned push path in Phase C calls this). Applies immediately
 * if the account is online; otherwise the cache is refreshed for the next join.
 */
class CommandGroupsync final : public Command {
private:
  GroupsyncModule *module;

public:
  CommandGroupsync(Module *creator, GroupsyncModule *mod);

  void Execute(CommandSource &source,
               const std::vector<Anope::string> &params) override;

  bool OnHelp(CommandSource &source, const Anope::string &) override {
    this->SendSyntax(source);
    source.Reply(" ");
    source.Reply(_("Re-fetches the given account's channel roles from the API\n"
                   "and reapplies them. Restricted to Services Operators."));
    return true;
  }
};

/*
 * The module: owns the worker and the cache, answers the privilege oracle, and
 * drives mode (re)application. All cache access is guarded by cacheMutex.
 */
class GroupsyncModule final : public Module {
private:
  GroupsyncWorker *worker = nullptr;
  CommandGroupsync commandgroupsync;

  std::mutex cacheMutex;
  std::map<std::string, ChannelPrivs>
      cache; // lowercased email -> channel privs
  std::map<std::string, uint64_t>
      emailToId; // lowercased email -> account id (online users)
  std::map<std::string, std::set<std::string>>
      appliedRoleTags; // lowercased email -> SWHOIS tags currently set (Add-on
                       // A)
  std::map<std::string, std::set<std::string>>
      emittedGated; // lowercased email -> +i channels last emitted as fr_gated
                    // (Add-on B revocation diff)

  std::string apiurl;
  std::string tokenFile;
  long timeout = DEFAULT_TIMEOUT;
  bool rolesyncEnabled =
      false; // emit fr_gated ModData for m_rolesync (Add-on B)

  static bool curlInitialised;

  std::string ReadToken(const std::string &path) {
    if (path.empty())
      return "";
    std::ifstream file(path);
    std::string token;
    std::getline(file, token);
    while (!token.empty() && (token.back() == '\n' || token.back() == '\r' ||
                              token.back() == ' '))
      token.pop_back();
    return token;
  }

  void LoadConfig() {
    auto &block = Config->GetModule(this);
    this->apiurl = block.Get<const Anope::string>("apiurl").str();
    this->tokenFile = block.Get<const Anope::string>("apitokenfile").str();
    int configured = block.Get<int>("apitimeout");
    this->timeout = configured > 0 ? configured : DEFAULT_TIMEOUT;
    this->rolesyncEnabled = block.Get<bool>("rolesync");
  }

  void ApplyChannel(Channel *c, User *u) {
    if (!c->ci)
      return;
    auto access = c->ci->AccessFor(u);
    for (auto *cms : ModeManager::GetStatusChannelModesByRank())
      if (!access.HasPriv("AUTO" + cms->name))
        c->RemoveMode(NULL, cms, u->GetUID());
    c->SetCorrectModes(u, true);
  }

  void ApplyModes(NickCore *nc) {
    for (auto *u : nc->users)
      for (const auto &[c, memb] : u->chans)
        this->ApplyChannel(c, u);
  }

  /* Render the account's roles as tagged SWHOIS lines on each online session
   * (Add-on A). Diffs against the tags we last set for this account so a
   * removed role's line is withdrawn. Every tag is DELETED before it is set:
   * `SendSWhois` appends rather than replacing, so a plain re-apply would stack
   * duplicate lines — delete-before-set collapses any stale/duplicate copies to
   * exactly one, and hidden roles are deleted without being re-set. */
  void ApplySwhois(const std::string &email, const std::vector<RoleTag> &roles,
                   NickCore *nc) {
    std::string key = ToLower(email);
    std::set<std::string>
        payloadTags;               // every tag in this payload (shown+hidden)
    std::set<std::string> newTags; // shown tags only → next diff baseline
    for (const auto &role : roles) {
      std::string tag = "fr-role:" + role.name;
      payloadTags.insert(tag);
      if (!role.hidden)
        newTags.insert(tag);
    }

    std::set<std::string> oldTags;
    {
      std::lock_guard<std::mutex> lock(this->cacheMutex);
      auto it = this->appliedRoleTags.find(key);
      if (it != this->appliedRoleTags.end())
        oldTags = it->second;
    }

    MessageSource source(Me);
    for (auto *u : nc->users) {
      // Retract tags we previously set that this payload no longer mentions
      // (role fully removed from the user).
      for (const auto &tag : oldTags)
        if (!payloadTags.count(tag))
          IRCD->SendSWhoisDel(source, u, tag, "");
      // Delete-then-set every payload tag: clears duplicate/stale lines and
      // drops hidden (oper/service) roles; sets each shown role exactly once.
      for (const auto &role : roles) {
        std::string tag = "fr-role:" + role.name;
        IRCD->SendSWhoisDel(source, u, tag, "");
        if (!role.hidden)
          IRCD->SendSWhois(source, u, tag, Anope::CurTime, role.display);
      }
    }

    {
      std::lock_guard<std::mutex> lock(this->cacheMutex);
      this->appliedRoleTags[key] = std::move(newTags);
    }
  }

  void EvictIfLastSession(User *u) {
    NickCore *nc = u->Account();
    if (!nc)
      return;
    for (auto *other : nc->users)
      if (other != u)
        return; // another session remains → keep cache

    std::string key = ToLower(nc->email.str());
    std::lock_guard<std::mutex> lock(this->cacheMutex);
    this->cache.erase(key);
    this->emailToId.erase(key);
    this->appliedRoleTags.erase(key);
    this->emittedGated.erase(key);
  }

  /* Emit the `fr_gated` client ModData that `m_rolesync` reads to admit
   * role-holders to invite-only channels (Add-on B). The gated set is the
   * user's accessible channels that are *currently* +i — kept small (Risk 30).
   * On revocation (a channel dropped from the set), SVSPART any online session
   * still sitting in that now-unauthorized +i channel. No-op unless `rolesync`
   * is enabled in the config. */
  void EmitGatedModData(const std::string &email, const ChannelPrivs &channels,
                        NickCore *nc) {
    if (!this->rolesyncEnabled)
      return;

    std::string key = ToLower(email);

    std::set<std::string> gated;
    for (const auto &[chan, privs] : channels) {
      Channel *c = Channel::Find(chan);
      if (c && c->HasMode("INVITE"))
        gated.insert(c->name.str());
    }

    std::string csv;
    for (const auto &chan : gated) {
      if (!csv.empty())
        csv += ",";
      csv += chan;
    }

    if (!csv.empty())
      Log(this) << "groupsync: fr_gated for " << email << " = [" << csv << "]";

    for (auto *u : nc->users)
      Uplink::Send("MD", "client", u->GetUID(), "fr_gated", Anope::string(csv));

    std::set<std::string> oldGated;
    {
      std::lock_guard<std::mutex> lock(this->cacheMutex);
      auto it = this->emittedGated.find(key);
      if (it != this->emittedGated.end())
        oldGated = it->second;
    }

    MessageSource source(Me);
    for (const auto &chan : oldGated) {
      if (gated.count(chan))
        continue; // still authorised
      Channel *c = Channel::Find(chan);
      if (!c || !c->HasMode("INVITE"))
        continue; // gone or no longer gated → nothing to enforce
      for (auto *u : nc->users)
        if (c->FindUser(u))
          IRCD->SendSVSPart(source, u, c->name, "groupsync: access revoked");
    }

    {
      std::lock_guard<std::mutex> lock(this->cacheMutex);
      this->emittedGated[key] = std::move(gated);
    }
  }

public:
  GroupsyncModule(const Anope::string &modname, const Anope::string &creator)
      : Module(modname, creator, THIRD), commandgroupsync(this, this) {
    if (!GroupsyncModule::curlInitialised) {
      curl_global_init(CURL_GLOBAL_DEFAULT);
      GroupsyncModule::curlInitialised = true;
    }
  }

  ~GroupsyncModule() override {
    if (this->worker) {
      this->worker->Stop();
      this->worker->Join();
      delete this->worker;
    }
  }

  void EnqueueByEmail(const std::string &email, uint64_t accountId) {
    if (!this->worker || email.empty())
      return;
    FetchRequest req;
    req.email = email;
    req.accountId = accountId;
    this->worker->Enqueue(req);
  }

  /* Resolve a known online account id for this email (if any) and enqueue. */
  void EnqueueByEmailResolvingId(const std::string &email) {
    uint64_t id = 0;
    {
      std::lock_guard<std::mutex> lock(this->cacheMutex);
      auto it = this->emailToId.find(ToLower(email));
      if (it != this->emailToId.end())
        id = it->second;
    }
    this->EnqueueByEmail(email, id);
  }

  /* Synchronous push (the API's outbox path): fetch + apply inline and report
   * whether it succeeded, so the caller can acknowledge that the resync was
   * *applied* rather than merely received (Risk 48). Runs on the main thread —
   * ApplyResult touches Anope objects, which is safe here. */
  bool PushSync(const std::string &email) {
    if (!this->worker || email.empty())
      return false;

    FetchRequest req;
    req.email = email;
    {
      std::lock_guard<std::mutex> lock(this->cacheMutex);
      auto it = this->emailToId.find(ToLower(email));
      if (it != this->emailToId.end())
        req.accountId = it->second;
    }

    FetchResult res = this->worker->FetchNow(req);
    this->ApplyResult(res);
    return res.ok;
  }

  void ApplyResult(FetchResult &res) {
    if (!res.ok) {
      Log(this) << "groupsync: fetch failed for " << res.email << " (http "
                << res.httpError << ") — keeping cache";
      return;
    }
    if (res.droppedFlags)
      Log(this) << "groupsync: dropped " << res.droppedFlags
                << " invalid flag letter(s) for " << res.email;

    {
      std::lock_guard<std::mutex> lock(this->cacheMutex);
      this->cache[ToLower(res.email)] = res.channels;
    }

    if (res.accountId) {
      NickCore *nc = NickCore::FindId(res.accountId);
      if (nc) {
        this->ApplyModes(nc);
        this->ApplySwhois(res.email, res.roles, nc);
        this->EmitGatedModData(res.email, res.channels, nc);
      }
    }
  }

  /* --- events (plain overrides; auto-attached at load) --- */

  void OnPostInit() override {
    this->LoadConfig();
    std::string token = this->ReadToken(this->tokenFile);
    if (this->apiurl.empty())
      Log(this) << "groupsync: no apiurl configured — module will not fetch";
    this->worker =
        new GroupsyncWorker(this, this->apiurl, token, this->timeout);
    this->worker->Start();
  }

  void OnReload(Configuration::Conf &conf) override {
    auto &block = conf.GetModule(this);
    this->apiurl = block.Get<const Anope::string>("apiurl").str();
    this->tokenFile = block.Get<const Anope::string>("apitokenfile").str();
    int configured = block.Get<int>("apitimeout");
    this->timeout = configured > 0 ? configured : DEFAULT_TIMEOUT;
    this->rolesyncEnabled = block.Get<bool>("rolesync");
    if (this->worker)
      this->worker->UpdateConfig(this->apiurl, this->ReadToken(this->tokenFile),
                                 this->timeout);
  }

  void OnUserLogin(User *u) override {
    NickCore *nc = u->Account();
    if (!nc)
      return;
    std::string email = nc->email.str();
    if (email.empty())
      return;
    uint64_t id = nc->GetId();
    {
      std::lock_guard<std::mutex> lock(this->cacheMutex);
      this->emailToId[ToLower(email)] = id;
    }
    this->EnqueueByEmail(email, id);
  }

  void OnJoinChannel(User *u, Channel *c) override {
    NickCore *nc = u->Account();
    if (!nc)
      return;
    {
      std::lock_guard<std::mutex> lock(this->cacheMutex);
      auto it = this->cache.find(ToLower(nc->email.str()));
      if (it == this->cache.end() || !it->second.count(ToLower(c->name.str())))
        return;
    }
    this->ApplyChannel(c, u);
  }

  EventReturn OnGroupCheckPriv(const AccessGroup *group,
                               const Anope::string &priv) override {
    if (!group || !group->nc || !group->ci)
      return EVENT_CONTINUE;

    std::lock_guard<std::mutex> lock(this->cacheMutex);
    auto account = this->cache.find(ToLower(group->nc->email.str()));
    if (account == this->cache.end())
      return EVENT_CONTINUE;
    auto channel = account->second.find(ToLower(group->ci->name.str()));
    if (channel == account->second.end())
      return EVENT_CONTINUE;
    if (channel->second.count(priv.str()))
      return EVENT_ALLOW;
    return EVENT_CONTINUE;
  }

  void OnNickLogout(User *u) override { this->EvictIfLastSession(u); }

  void OnUserQuit(User *u, const Anope::string &) override {
    this->EvictIfLastSession(u);
  }

  void OnUplinkSync(Server *) override {
    /* Reconcile after a (re)link: re-fetch every online identified user so
     * grants are reapplied. TODO: batch via POST /anope/bulk for scale. */
    for (const auto &[nick, u] : UserListByNick) {
      NickCore *nc = u->Account();
      if (!nc || nc->email.empty())
        continue;
      this->EnqueueByEmail(nc->email.str(), nc->GetId());
    }
  }
};

bool GroupsyncModule::curlInitialised = false;

void GroupsyncWorker::OnNotify() {
  std::deque<FetchResult> drained;
  {
    std::lock_guard<std::mutex> lock(this->mutex);
    std::swap(drained, this->results);
  }
  for (auto &res : drained)
    this->module->ApplyResult(res);
}

CommandGroupsync::CommandGroupsync(Module *creator, GroupsyncModule *mod)
    : Command(creator, "nickserv/groupsync", 1, 1), module(mod) {
  this->SetDesc(_("Resync a user's IRC channel roles from the API"));
  this->SetSyntax(_("\037email\037"));
}

void CommandGroupsync::Execute(CommandSource &source,
                               const std::vector<Anope::string> &params) {
  if (!source.IsServicesOper()) {
    source.Reply(_("Access denied."));
    return;
  }
  // Apply synchronously and report an applied/failed acknowledgement the API's
  // outbox can parse — a bare command success is not proof the modes landed.
  bool applied = this->module->PushSync(params[0].str());
  Log(LOG_COMMAND, source, this)
      << "to resync groupsync roles for " << params[0];
  if (applied)
    source.Reply(_("groupsync applied for %s."), params[0].c_str());
  else
    source.Reply(_("groupsync failed for %s."), params[0].c_str());
}

MODULE_INIT(GroupsyncModule)
