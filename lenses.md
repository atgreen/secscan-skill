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
