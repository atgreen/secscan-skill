<!-- SPDX-License-Identifier: Apache-2.0
     Copyright 2026 Anthony Green
     Per-language "where to look first" hints, adapted from vvaharness's
     LANG_HINTS (vvaharness/lang/hints.py); see NOTICE. -->

# Language hints — where to look first

**Load only the blocks for languages s1 actually found.** This file is a
reference, not a prompt: reading it end to end wastes the budget the rest of the
skill is built to save. A Go repo loads `go`; a Rails app loads `ruby`; a
mainframe batch job loads `cobol` and `jcl`.

Each block is a **starting set, not a checklist**. It names the constructs that
most often carry a defect in that language — it does not bound what's there, and
a clean sweep of every bullet is not a clean file. Everything found here still
goes through the gates in `gates.md` and the CWE row in `cwe-kb.md`: these hints
tell you where to *look*, never what to conclude.

Languages with their own specialist lens in `lenses.md` are not repeated here —
C/C++/Rust are covered by `memory-safety`, PHP by `php` and `wordpress`. The
per-CWE sink lists and the reflection/framework taxonomy in `cwe-kb.md` already
cover Java, Python, JavaScript and TypeScript at the sink level.

---

## go
- HTML built with `text/template` instead of `html/template`, or a
  `template.HTML()` cast on a request-derived string — the cast is the bug, it
  disables escaping by design.
- `filepath.Join(base, userInput)` without `filepath.Clean` *and* a prefix check
  back to `base`. `..` segments still escape after `Join`.
- `exec.Command("sh", "-c", x)`, or argv elements assembled from request fields.
- Maps, slices, or struct fields written from multiple goroutines with no mutex
  or channel hand-off — look at handlers sharing package-level state.
- Two-step file operations on a path another principal can swap between the
  calls: `os.Stat` → `os.Open`, an existence check → `os.Remove` (TOCTOU).
- `x.(T)` without the `, ok` form on a value that came from a JSON/YAML decode —
  a wrong type panics the handler. Rate it as the availability bug it is; a
  recovered panic in middleware may cap it at low.
- `err` assigned and not checked on a security-relevant call (signature verify,
  auth lookup, permission check) — Go makes this easy to do silently.

## ruby
- `Marshal.load` on request or uploaded bytes — RCE, and there is no safe mode.
  `Oj.load` in non-strict mode is equally unsafe.
- `YAML.load` on untrusted input. **Version-dependent:** with Psych 4 (bundled
  from Ruby 3.1) `YAML.load` is safe-by-default and rejects arbitrary classes;
  on Psych 3 / Ruby ≤ 3.0, or wherever `aliases: true` / `permitted_classes` has
  been widened, it deserializes arbitrary objects. Establish the Ruby and Psych
  version from the gemspec or Gemfile.lock before you rate it.
- Views emitting unescaped content: `raw`, `.html_safe`, `<%== %>`, Haml `!=`,
  Slim `==` on a request-derived value.
- `params.permit!`, or a blanket `permit(...)` that admits role/admin/owner
  fields, or `update(params[:model])` straight onto the record — mass assignment.
- Request-supplied symbols into dynamic dispatch: `send(params[:m])`,
  `public_send`, `constantize` / `safe_constantize` on a user string.
- `system` / `exec` / backticks / `%x{}` / `Open3.*` with any request-derived
  fragment. Also `Kernel.open(user)` and `IO.read(user)` — a leading `|` in the
  argument runs a process.

## csharp
- Deserialization of request, viewstate, or queue data through `BinaryFormatter`,
  `SoapFormatter`, `NetDataContractSerializer`, `LosFormatter`,
  `ObjectStateFormatter`, or `JavaScriptSerializer` with a custom type resolver.
  **Version-dependent:** `BinaryFormatter` is obsolete from .NET 5, throws by
  default from .NET 8, and is removed in .NET 9 — check the target framework
  before rating it, and check whether an app-context switch has re-enabled it.
- Newtonsoft `TypeNameHandling` set to anything but `None` on attacker-reachable
  JSON, or a custom `SerializationBinder` that doesn't constrain types.
- `SqlCommand` / `OracleCommand` / `NpgsqlCommand` whose `CommandText` is built
  with `+` or `$"...{x}..."` rather than `Parameters.Add`.
- `Path.Combine(root, user)` or `File.*` / `Directory.*` on request input without
  `Path.GetFullPath` plus a containment check back to `root`. `Path.Combine`
  discards `root` entirely when the second argument is absolute.
- `XmlDocument.Load` / `XDocument.Load` / `XmlReader.Create` without
  `DtdProcessing = Prohibit` and a null `XmlResolver`.
- `Process.Start` with a filename or arguments from the request, and especially
  with `UseShellExecute = true`.

## kotlin
- JVM deserialization surfaces inherited from Java: `ObjectInputStream`, Jackson
  polymorphic typing (`@JsonTypeInfo`, default typing), SnakeYAML `Yaml()` on
  request bytes.
- Queries built with `$var` string templates in Exposed, JDBC, or Room raw SQL
  instead of bound `?` parameters — string templates make this look tidier than
  the equivalent Java concatenation, not safer.
- **(Android)** exported `Activity` / `Service` / `Receiver` / `Provider`
  consuming `Intent` extras without validating origin or contents — intent
  redirection, extra-driven file or URL loads. An `intent-filter` in the manifest
  exports the component implicitly on older `targetSdk` values.
- `File(base, userInput)` or `Paths.get(user)` without canonicalising and
  asserting the result stays under the intended root.
- `Runtime.exec` / `ProcessBuilder` with string-template argv.
- A platform type (`String!`) from Java interop used where null was assumed —
  the null check Kotlin would have forced is absent at the boundary.

## swift
- `application(_:open:options:)`, `onOpenURL`, or universal-link handlers where
  URL components feed file paths, WebView loads, or auth state — a custom scheme
  is attacker-invocable by any app on the device.
- `String(format: x, ...)` or `NSString(format:)` where `x` itself is external —
  bridged ObjC varargs, so `%n`/`%@` style format-string abuse applies.
- Secrets in `UserDefaults`, a plist, or an app-group container rather than the
  Keychain; Keychain items without an appropriate `kSecAttrAccessible*` class.
- `FileManager` operations on paths assembled from URL or query input without
  resolving symlinks and bounding the result to the sandbox directory.
- `WKWebView` loading an attacker-influenced URL with JavaScript enabled, or a
  `WKScriptMessageHandler` exposing privileged native calls to page content.

## elixir
- `:erlang.binary_to_term/1` on untrusted input — RCE via fun and atom creation.
  `binary_to_term(bin, [:safe])` is the guarded form, and `:safe` still permits
  atom-table growth in older OTP releases.
- `Code.eval_string` / `Code.eval_quoted` reached from request data.
- `String.to_atom` / `List.to_atom` on user input — the atom table is never
  garbage-collected, so this is an unbounded-memory DoS.
  `String.to_existing_atom` is the fix.
- Ecto queries built with raw interpolation: `fragment("... #{x} ...")`, or
  `Repo.query` with an interpolated string. `fragment` interpolation is *not*
  parameterized the way a pinned `^value` is.
- Phoenix templates using `raw/1` or a hand-built `{:safe, ...}` tuple around
  user content.
- `System.cmd` / `:os.cmd` / `Port.open({:spawn, ...})` with user-influenced
  arguments — note `:os.cmd` takes a shell string, `System.cmd` takes argv.
- `GenServer` / `Agent` state keyed by user input and never pruned — unbounded
  growth in a long-lived process.

## solidity
- **Reentrancy:** an external call (`.call{value:}`, `.transfer`, token
  `transferFrom`, an ERC-777 or ERC-721 receive hook) *before* state updates.
  Look for checks-effects-interactions ordering or a `nonReentrant` guard.
  (CWE-841)
- **Access control:** state-changing, `selfdestruct`, `delegatecall`, or
  owner-setter functions missing `onlyOwner`/role modifiers or left
  `public`/`external`; an uninitialized owner; `tx.origin` used for authorization
  (phishable — `msg.sender` is the correct check).
- **Arbitrary delegatecall / proxy:** `delegatecall` to an address from input, or
  an upgradeable proxy whose implementation slot is settable by a non-admin —
  full takeover.
- **Unchecked low-level call:** `(bool ok, ) = addr.call(...)` whose `ok` is
  discarded; unchecked ERC-20 return values (some tokens return `false` rather
  than reverting).
- **Arithmetic and funds:** overflow without SafeMath on pre-0.8 pragmas
  (0.8 added checked arithmetic by default — confirm the pragma before rating);
  rounding and precision loss in share maths; `block.timestamp` or `blockhash`
  used as randomness; a price read from a single spot AMM (oracle manipulation).
- **Easy to miss:** storage collision in proxies or mis-ordered inherited state
  variables; default visibility; shadowed state variables; a `require` with `||`
  where one clause is always true, which disables the check entirely.

## cobol
- `EXEC SQL ... END-EXEC` where host variables are built with `STRING`/`UNSTRING`
  from terminal or CICS input — dynamic SQL injection into DB2.
- `EXEC CICS RECEIVE` and BMS maps: trace `DFHCOMMAREA` and map fields to
  wherever they reach `EXEC SQL`, a `CALL`, file I/O, or
  `EXEC CICS LINK`/`XCTL` without validation.
- `ACCEPT FROM CONSOLE` / `SYSIN` — untrusted batch input entering business logic.
- `MOVE` of a larger `PIC` item into a smaller one (silent truncation), and
  `COMPUTE` without `ON SIZE ERROR` (silent overflow) on `COMP`/`COMP-3` fields
  used for amounts, indices, or lengths.
- `OCCURS ... DEPENDING ON` where the count comes from input — out-of-bounds
  subscript.
- `CALL identifier` — a dynamic call whose target program name is a variable.
  Ask whether untrusted input can choose the program.
- Copybooks (`.cpy`) shared across programs with `REDEFINES` that reinterpret
  tainted alphanumeric data as numeric or packed without validation.

## jcl
- Symbolic parameters (`&VAR`) flowing into `DSN=`, `PGM=`, `PARM=`, or `SYSIN`.
  If a caller or scheduler sets them, look for dataset-name or program-name
  injection.
- `DD` statements with `DISP=(MOD|OLD,DELETE)`, or `IDCAMS DELETE` / `IEFBR14`
  steps targeting datasets named via substitutable parameters.
- `IKJEFT01` / `IRXJCL` / `BPXBATCH` steps — TSO, REXX, or USS commands built
  from `PARM=` or `SYSTSIN` including externally supplied values.
- FTP/SFTP (`FTP PARM=`, `BPXBATCH SH`) or NJE transmit steps with hardcoded
  credentials in inline `SYSIN` or an unprotected PARMLIB member.
- Jobs running under a high-privilege `USER=` (RACF/ACF2 context) that accept
  operator- or scheduler-supplied parameters.
