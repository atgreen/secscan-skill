<!-- Per-CWE taint knowledge base + sanitizer/source taxonomy. Read once before
     s4 and keep in context; the relevant CWE row is applied in s4 (discovery),
     s5 (pre-filter), and especially s6 (adversarial verify). Adapted from
     vvaharness's generic.kb.yaml / CweKB.prompt_block and validator_hints.yaml;
     see NOTICE. This is knowledge, not a rulebook — the code still decides. -->
# secscan CWE knowledge base

A per-CWE decision reference. It encodes the traps models fall for — defenses
that *look* real but aren't, and the conditions that make a finding a genuine
false positive — so verification rests on the code, not on recall.

## How to read each entry
For the CWE(s) a finding touches, splice its row into your reasoning:
- **sources / sinks** — where untrusted input enters, where it bites. Use in s1
  mapping and s4 discovery to know what to trace.
- **SANITIZERS — if ANY sits on the confirmed path, REFUTE.** A recognized,
  correctly-applied control between source and sink kills the finding. (But
  confirm it covers *every* route into the sink, per s6.)
- **NON-SANITIZERS — these look safe but are NOT; do NOT refute on their basis
  alone.** Seeing one of these is not a defense. This is the list that prevents
  killing a *real* bug.
- **FP CHECKS — if ANY is true, REFUTE.** Concrete conditions under which the
  candidate is genuinely not exploitable.
- **BYPASS HINTS — TRY these before you refute.** Realistic techniques an
  attacker uses to defeat a naive defense. In s6, if a defense is present, you
  must show these do *not* slip past it before returning FALSE_POSITIVE; if one
  does, the finding stands (and gains a concrete exploit).

> Absence of a CWE row means fall back to the lens defaults and gates. This KB is
> a curated subset of common classes, not an exhaustive taxonomy.

---

## CWE-89 — SQL injection
- **sources:** request params, form fields, query strings, path params, headers, JSON bodies, cookies
- **sinks:** string-built SQL passed to execute/query/update; dynamic SQL for table/column/`ORDER BY` names
- **SANITIZERS (refute):** parameterized queries / prepared statements; server-side allow-lists for dynamic identifiers
- **NON-SANITIZERS (not a defense):** manual escaping; regex blacklists for SQL keywords
- **FP CHECKS (refute):** taint reaches a *bound parameter value*, not the SQL string; query is static and only values are bound
- **BYPASS HINTS (try first):** stacked queries via `;` if the driver allows multi-statement; second-order (value stored, later concatenated elsewhere); numeric context with no quotes (wrong variable parameterized); identifier position — `ORDER BY`/`LIMIT`/table/column — cannot be parameterized; `--` or `/*` to truncate the intended clause

## CWE-78 — OS command injection
- **sources:** user input, argv/env, request params, config values
- **sinks:** shell invocation, `Runtime.exec`, `Process.Start`, `child_process.exec`; any string passed to a shell or eval-style runner
- **SANITIZERS (refute):** argv-array execution with the shell disabled; strict allow-list of commands and arguments
- **NON-SANITIZERS:** quoting only; blocking a few punctuation characters
- **FP CHECKS (refute):** command is constant and arguments are not attacker-controlled
- **BYPASS HINTS (try first):** argument injection (leading `-`, `--flag=val`) even in array form; shell metachar in a value the callee itself passes to a shell; `$(...)`/backtick if any downstream eval; newline/CRLF splitting into a second command

## CWE-79 — Cross-site scripting (HTML/template output)
- **sources:** HTTP input, comments, markdown, profiles, stored text
- **sinks:** `innerHTML`, `document.write`, `render_template_string`, `res.send(html)`, template raw blocks, safe markers, triple-stache, `Markup()`
- **SANITIZERS (refute):** context-aware HTML encoding; template auto-escape that stays enabled end-to-end
- **NON-SANITIZERS:** `strip_tags`; URL encoding; JSON serialization
- **FP CHECKS (refute):** sink is `textContent`/`innerText`/a JSON response
- **BYPASS HINTS (try first):** context mismatch (HTML-encoded value placed in a JS string or URL); `javascript:`/`data:` URI in `href`/`src`; DOM clobbering, SVG `<script>`, template-literal injection; mXSS via `innerHTML` round-trip; event-handler attribute (`onerror`, `onload`)

## CWE-22 — Path traversal (incl. archive/zip-slip members)
- **sources:** user-supplied filename, path, upload name; zip member names, tar entries, import paths
- **sinks:** `open`/read/write/delete/`sendFile`/`serveFile`, or archive extraction, on attacker-influenced paths
- **SANITIZERS (refute):** canonicalize *then* verify the result is inside a fixed base dir; server-side id→path mapping with no raw joins
- **NON-SANITIZERS:** `basename` alone; single `../` replacement; prefix check *before* resolve
- **FP CHECKS (refute):** path is constant or fully server-derived; archive members validated against a fixed extraction root
- **BYPASS HINTS (try first):** URL-encoded `..%2f`, double-encoded `..%252f`; Windows `..\`, mixed `/`+`\`, UNC `\\host\share`; null-byte truncation on legacy runtimes; symlink inside the base dir pointing outside; absolute-path bypass when only `../` is filtered

## CWE-918 — Server-side request forgery (SSRF)
- **sources:** user URL, webhook target, callback URL, redirect URL
- **sinks:** `requests`/`fetch`/`HttpClient`/`curl`/`file_get_contents` on remote URLs
- **SANITIZERS (refute):** host allow-list applied *after* DNS resolution; private-range + loopback blocking on *every* hop
- **NON-SANITIZERS:** scheme allow-list only; string prefix checks on hosts
- **FP CHECKS (refute):** URL is fixed or drawn from a trusted allow-list
- **BYPASS HINTS (try first):** decimal/octal/hex IP (`2130706433`, `0x7f000001`, `0177.0.0.1`); IPv6 `[::ffff:127.0.0.1]`, `[::]`, `0.0.0.0`; DNS rebinding / TOCTOU between resolve and connect; redirect chain to an internal host, `gopher://`/`file://`; cloud metadata endpoints (`169.254.169.254`)

## CWE-502 — Unsafe deserialization
- **sources:** untrusted blob, file, message, cookie, session payload
- **sinks:** `pickle.loads`, `ObjectInputStream.readObject`, `BinaryFormatter.Deserialize`, native/YAML loaders that run constructors or gadgets
- **SANITIZERS (refute):** `safe_load` / data-only parsing; class allow-list filter applied *before* object creation
- **NON-SANITIZERS:** signature check *after* deserialization; class-name blacklists
- **FP CHECKS (refute):** input is immutable trusted data and cannot be attacker-writable
- **BYPASS HINTS (try first):** gadget chain in an allowed type's transitive deps; polymorphic type field (`@class`, `$type`) pointing at a dangerous type; nested/wrapped payload that passes the outer allow-list

## CWE-611 — XML external entity (XXE)
- **sources:** XML input from a request, file, message, or partner system
- **sinks:** XML parsers with DTD / entity resolution enabled
- **SANITIZERS (refute):** disable DTDs and external entities *before* parsing (hardened/defused factory)
- **NON-SANITIZERS:** post-parse exception handling; schema validation alone
- **FP CHECKS (refute):** a defused parser or equivalent hardened factory is used
- **BYPASS HINTS (try first):** parameter entities (`% ent`) when general entities are disabled; external DTD via `SYSTEM` with a redirect; XInclude, XSLT `document()`, `schemaLocation`

## CWE-601 — Open redirect
- **sources:** `next`, `returnUrl`, `redirect`, `callback`, `destination` params
- **sinks:** response redirects and client-side navigation sinks
- **SANITIZERS (refute):** relative-path allow-list or exact-host allow-list
- **NON-SANITIZERS:** `startswith('/')`; substring host checks
- **FP CHECKS (refute):** redirect target is fully server-constant
- **BYPASS HINTS (try first):** scheme-relative `//evil.com`, backslash `/\evil.com`; userinfo trick `https://trusted.com@evil.com`; whitespace/control chars before the scheme; case/unicode normalization of the host

## CWE-798 — Hardcoded credentials
- **sources:** source-code literals, checked-in configs, fixtures, docs
- **sinks:** API keys, passwords, JWTs, private keys, cloud credentials
- **SANITIZERS (refute):** secret-manager lookup or runtime injection from secure storage
- **NON-SANITIZERS:** base64 encoding; renaming the variable
- **FP CHECKS (refute):** string is clearly a non-secret placeholder or a public example token
- **BYPASS HINTS (try first):** credential moved but the old literal still referenced via a fallback; env var read but the *default value* is the old secret
- *(Report by `file:line` + match count, never the value; a leaked secret is unresolved until rotated — see SKILL.md s9 and remediate.md r3.)*

## CWE-94 — Code / expression injection
- **sources:** template fragments, user expressions, rule text, scripts
- **sinks:** `eval`, `exec`, `ScriptEngine`, `new Function`, template eval
- **SANITIZERS (refute):** literal allow-lists; sandboxed expression engines
- **NON-SANITIZERS:** character stripping; blacklists; string concatenation
- **FP CHECKS (refute):** expression is fully authored by trusted code and never data-derived

## CWE-1333 — ReDoS (regex denial of service)
- **sources:** attacker-controlled text evaluated by a complex regex
- **sinks:** catastrophic-backtracking patterns in search / validation
- **SANITIZERS (refute):** linear-time regex or bounded matching with input limits
- **NON-SANITIZERS:** short-circuit checks that still leave the bad regex path reachable
- **FP CHECKS (refute):** pattern is precompiled and not evaluated on attacker-controlled length
- **BYPASS HINTS (try first):** input length not bounded *before* the regex; alternation still nesting under a quantifier

## CWE-295 — TLS verification disabled
- **sources:** client config, deployment config, README/setup instructions
- **sinks:** `verify=false`, `rejectUnauthorized=false`, `InsecureSkipVerify`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `curl -k`, `TrustAllCerts`, empty trust managers, hostname verifier returning true
- **SANITIZERS (refute):** TLS verification enabled with a trusted-CA / pinning policy
- **NON-SANITIZERS:** accepting any certificate; environmental trust without verification
- **FP CHECKS (refute):** dev-only harness or isolated test fixture that never ships
- *(A README/script that **instructs** disabling TLS is reportable even though it isn't executable — see SKILL.md s4.)*

## CWE-306 / CWE-862 / CWE-639 — Missing authn / authz / IDOR
- **sources:** public/anonymous request; scheduler/webhook/admin/CLI trigger; tenant/object/row/account id from path, query, or body
- **sinks:** privileged endpoint or control-plane action with no auth gate; object access with no ownership/role/policy check
- **SANITIZERS (refute):** authentication required before the sensitive action; server-side authorization tied to the resource and the authenticated principal
- **NON-SANITIZERS:** UI-only restriction / client-side gating; hiding the id from the UI; UUIDs or random ids "alone"; unguarded localhost assumptions
- **FP CHECKS (refute):** route is internal-only and unreachable from any external entry point; resource is intentionally global/public; id is scoped by server-side tenant context before use

## CWE-352 — CSRF on state-changing actions
- **sources:** browser-originated requests, forms, fetches, cookies
- **sinks:** state-changing endpoints with no anti-CSRF verification
- **SANITIZERS (refute):** anti-CSRF token or SameSite gate checked on *every* state change
- **NON-SANITIZERS:** custom header names only; `Referer` check alone
- **FP CHECKS (refute):** action is read-only, or a token is required and validated

## CWE-20 — Missing input validation
- **sources:** any untrusted field crossing a trust boundary
- **sinks:** security-sensitive business logic consuming unchecked input
- **SANITIZERS (refute):** strict type/range/format/allow-list validation
- **NON-SANITIZERS:** null checks; length checks only
- **FP CHECKS (refute):** all attacker-controlled inputs are normalized and validated before use

## CWE-327 / CWE-326 — Weak or broken crypto
- **sources:** secrets, credentials, tokens, PII, payment data
- **sinks:** MD5/SHA1 for security, hard-coded IVs, obsolete protocols, truncated keys, low-entropy secrets
- **SANITIZERS (refute):** modern authenticated encryption; strong hash + key-size choices
- **NON-SANITIZERS:** HMAC with a weak hash; unsalted fast-hash password storage; homegrown crypto; obscurity
- **FP CHECKS (refute):** crypto is legacy-only and not used for any security decision

## CWE-434 — Unrestricted file upload
- **sources:** user file uploads, multipart forms, drag-and-drop
- **sinks:** storage or execution of uploaded content without validation
- **SANITIZERS (refute):** type/extension/size allow-lists + storage outside the web root
- **NON-SANITIZERS:** extension blacklists; MIME type alone
- **FP CHECKS (refute):** upload is converted to inert data or stored under a non-executable path

## CWE-400 — Unbounded resource consumption
- **sources:** user-controlled pagination, loops, recursion, batch size, uploads
- **sinks:** CPU/memory/disk amplification without hard caps
- **SANITIZERS (refute):** server-side quotas, paging limits, timeouts, bounded queues
- **NON-SANITIZERS:** client hints; best-effort throttling
- **FP CHECKS (refute):** resource use is bounded by server-enforced limits

## CWE-117 / CWE-200 — Log injection & sensitive-data / information exposure
- **sources:** user-controlled strings, headers, stack traces, request bodies; PII/PAN/tokens/secrets/debug traces; config dumps, internal ids
- **sinks:** raw log lines, audit events, CSV export; public responses, error pages, diagnostic endpoints, metrics/tracing spans
- **SANITIZERS (refute):** structured logging with escaping/field separation; redaction/masking before write; least-information responses; internal-only diagnostics
- **NON-SANITIZERS:** trimming; length checks; removing a few delimiters; suffix-masking only; hiding the UI button; client-side-only protections
- **FP CHECKS (refute):** output is structured and encoded before emission; sensitive fields redacted before emission; response is explicitly internal and externally inaccessible
- *(Log injection with no downstream parser is noise-floor per gates.md rule E; a real downstream parser makes it a sink.)*

---

## Shared taxonomy — source & sink recognition (s1, s4)

### Recognized sanitizer names
A call from this set on the confirmed path is a *candidate* sanitizer — grep for
it, then confirm it covers every route in **and that it is the right control for
the CWE of the sink the path actually arrives at**. The set splits three ways,
and the split is the whole point: whether a name counts as a defense can only be
decided once you know which sink it's defending.

**UNIVERSAL — safe regardless of what consumes the value.** These exist to make
a string safe to use, so a hit anywhere on the path neutralizes taint for any
sink class:
`escape`, `quote`, `strip_tags`, `html_escape`, `xml_escape`, `quote_plus`,
`urlencode`, `bleach_clean`, `prepared_statement`, `parameterized`.

**CLASS-SPECIFIC — only neutralizes its own CWE, and only at the sink it
reaches.** Decide these at *sink arrival*, never per hop: the same tainted string
can pass a coercion and still reach a different sink unharmed.
| Name | Neutralizes | Does nothing for |
|---|---|---|
| `int`, `float`, `bool`, `to_int` | CWE-89 / CWE-90 (SQL, LDAP) | command injection, path traversal, authz gaps built from the same value |
| `encode`, `html_escape` | CWE-79 (server-emitted XSS) | SQL, shell, header, or template contexts |

A numeric coercion stops a SQL payload built from that value and does **nothing**
for a command-injection payload built from the *same* string reaching a different
sink. A coerced-to-`int` id defends SQLi but not an authz gap.

**UNPROVEN BY NAME — never refute on these alone.** `validate`, `clean`,
`sanitize`, and anything else whose name merely asserts safety. `validate_input(x)`
is not evidence that any particular sink class was neutralized; it is evidence
that somebody named a function well. Open it and find out what it actually does —
if you can't, it is a NON-SANITIZER for this path. Treating this family as
universal is a known way to lose real command- and SQL-injection findings behind
an aptly-named but unproven function.

### Reflection / dynamic-dispatch sinks (per language)
Attacker-influenced names reaching these enable RCE/type-confusion — trace them:
- **Java:** `getMethod`, `getDeclaredMethod`, `getDeclaredField`, `getField`,
  `getConstructor`, `getDeclaredConstructor`, `forName`, `invoke`,
  `newInstance`, `MethodHandles.lookup()`
- **Python:** `getattr`, `setattr`, `__import__`, `importlib.import_module`,
  `vars`, `type`, `eval`, `exec`, `compile`
- **C#:** `GetType`, `GetMethod(s)`, `GetConstructor(s)`, `Invoke`,
  `CreateDelegate`, `Activator.CreateInstance`, `Assembly.Load(From|File)`,
  `Type.InvokeMember`

### Framework lifecycle sources (taint origins)
Treat framework-bound request data as tainted at the boundary:
- **Spring:** `@RequestParam`, `@PathVariable`, `@RequestBody`
- **Django:** `request.GET` / `request.POST` / `request.META`
- **ASP.NET:** `[FromQuery]`, `[FromRoute]`, `[FromBody]`
- **Route parameters** (`/user/{id}`) are tainted and flow to the mapped handler arg.
- **Response dataflow:** tainted data reaching a response object
  (`JsonResponse`, `ResponseEntity`, `Ok`/`BadRequest`, `res.send`) is an output
  sink — hunt XSS/injection on emission, not just on ingestion.

## Common antipatterns (never count as a defense)
client-side validation only · manual escaping instead of parameterization /
context-aware encoding · blacklist / regex filtering instead of allow-lists ·
prefix or substring checks before canonicalization/resolution · UI-only auth or
authorization · hardcoded secrets/tokens/credentials in source.
