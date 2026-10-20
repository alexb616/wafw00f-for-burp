# wafw00f for Burp

A native **Burp Suite** extension (Montoya API) that brings the detection logic of
[**wafw00f**](https://github.com/enablesecurity/wafw00f) directly into Burp. It
fingerprints the Web Application Firewall / CDN / security solution protecting a
site from its HTTP responses, and publishes the findings as **issues** attached to
the target in *Target → Issues*.

> **Credit — this is a port, not the original tool.**
> All detection intelligence (the WAF signatures and the generic-detection
> heuristics) comes from **wafw00f**, created and maintained by
> [EnableSecurity](https://github.com/enablesecurity/wafw00f) and its contributors.
> This project only re-implements wafw00f's evaluation model in Java so it
> integrates with Burp Suite in a natural, first-class way (passive on scope,
> active probing from the UI/context menu, and results reported as Burp audit
> issues). The signatures remain © their respective wafw00f authors. If you want
> the canonical, standalone command-line tool, use wafw00f itself.

## Why an extension (and not a custom scan check)

Both approaches were considered:

- A **passive** `ScanCheck` only inspects already-captured traffic and **cannot
  send the attack request** wafw00f relies on (many WAFs only reveal themselves on
  their block page).
- An **active** `ScanCheck` runs per *insertion point* inside a scan, which doesn't
  match the "when a target is added to scope" trigger and would repeat the work many
  times per host.

An **extension** gives the best of both: it detects hosts entering scope
(`ScopeChangeHandler`), supports manual launching (context menu + button) and
**still** reports results as `AuditIssue` entries in *Target → Issues* via
`SiteMap.add(auditIssue)`.

## How it works

- **Passive detection (automatic, ON by default).** An `HttpHandler` watches
  **Proxy** and **Repeater** traffic for **in-scope** hosts — without sending a
  single new request — and applies the header/cookie/content signatures. When the
  scope changes it also immediately re-scans whatever is already in that host's site
  map. Zero noise.
- **Active probing (manual).** From the *wafw00f* tab (URL field + button) or by
  right-clicking a request → *"wafw00f: active probe this host"*. It sends the
  normal request plus `centralAttack` (XSS + SQLi + LFI in GET parameters with
  random names), evaluates all signatures and, if none match, runs wafw00f's
  **generic detection** (status-code and `Server` header differences). It follows
  redirects.
- **Evaluation model.** Signatures are evaluated over a pair
  *(normal response, attack response)*. In passive mode both are the same observed
  response, so block-page signatures only fire if the captured traffic was already a
  block page (no false positives from payloads that were never sent).
- **Reporting.** Each new WAF per host is published as an informational `AuditIssue`
  (severity *Information*; *Certain* for a signature match, *Tentative* for generic)
  under the host in *Target → Issues*, with the request/response as evidence. If an
  **active probe** finishes without detecting anything, an informational
  *"No WAF detected (active probe)"* issue is published.
- **Persistence.** Settings (passive on/off, find-all) are kept across Burp restarts
  via Montoya `Preferences`.

## The signatures (signatures.json)

wafw00f's plugins are 100% declarative. They are converted automatically into a
boolean tree in `src/main/resources/com/wafw00f/burp/signatures.json` (OR between
checks, AND inside schemas, with the `matchHeader` / `matchCookie` / `matchContent`
/ `matchStatus` / `matchReason` primitives and their `attack` flag). The Java engine
loads and evaluates them at runtime, so **you can edit or add signatures without
touching the Java code** — edit the JSON and recompile (or reload it).

To regenerate the signatures when wafw00f is updated:

```bash
# clone wafw00f and run the converter
python3 tools/convert_plugins.py /path/to/wafw00f/wafw00f src/main/resources/com/wafw00f/burp
```

## Requirements

- A recent Burp Suite (Community or Professional). The Montoya API needs the JRE 17+
  that Burp already ships. *AuditIssues* are visible in both editions; integration
  with Burp's own active scanner is a Professional feature, but this extension does
  not need it.
- To build: JDK 17+ (compiled to bytecode 17).

## Build

With the wrapper (no local Gradle needed; it downloads Gradle 8.14.3):

```bash
./gradlew jar            # Linux/Mac
gradlew.bat jar          # Windows
```

Or with a system Gradle: `gradle jar`.

The JAR is produced at `build/libs/wafw00f-for-burp-0.1.0.jar`.

The default build resolves the Montoya API from **Maven Central**
(`net.portswigger.burp.extensions:montoya-api:2026.7`, declared in
`build.gradle`). The Montoya API is `compileOnly` — Burp supplies it at
runtime — so no runtime dependencies are added.

### Offline / air-gapped fallback

The repo also ships `libs/montoya-api-2026.7.jar` precisely for environments
without Maven Central access. To build offline, swap the dependency in
`build.gradle` to the local jar and drop the `repositories` block:

```groovy
// repositories { mavenCentral() }
dependencies {
    compileOnly files('libs/montoya-api-2026.7.jar')
}
```

## Load into Burp

1. Burp → **Extensions** → **Installed** → **Add**.
2. Extension type: **Java**.
3. Select `build/libs/wafw00f-for-burp-0.1.0.jar`.
4. In *Output* you should see `[wafw00f] loaded 172 signatures (0 regex compile errors).`
5. A **wafw00f** tab appears.

## Usage

- **Passive:** leave *Enable passive WAF detection* checked, put the target in scope
  and browse it through the proxy. Detected WAFs appear in *Target → Issues* and in
  the tab's table.
- **Active:** type the URL in the tab and press *Run active probe*, or right-click any
  request → *active probe this host*.
- **Find all:** check the box to not stop at the first WAF (reports every match),
  equivalent to `wafw00f -a`.
- **Reset detections:** clears the dedup memory to re-evaluate hosts.

## Project layout

```
build.gradle, settings.gradle, gradlew[.bat]   Build (Gradle + wrapper)
libs/montoya-api-2026.7.jar                     Burp API (compile-only)
tools/convert_plugins.py                        wafw00f plugins -> signatures.json converter
src/main/resources/.../signatures.json          172 signatures (editable)
src/main/resources/.../wafprio.json             Detection priority order
src/main/java/com/wafw00f/burp/
  WafDetectorExtension.java                      Entry point (wiring)
  core/                                          Payloads, Config, DetectionResult, Json, Urls
  engine/                                        Signature engine (Condition, Signature, Store, Engine)
  http/ActiveProber.java                         Builds/sends probe requests
  scan/                                          Passive, scope, generic, dedup, issue reporting
  ui/                                            Swing tab + context menu
```

## Limitations and notes

- Detection is *best-effort*: it can produce false positives/negatives, just like
  wafw00f. The active probe sends offensive payloads — use it only against targets
  you are authorized to test.
- Passive mode only looks at in-scope **Proxy**/**Repeater** traffic.
- Room to grow: tuning signatures, exporting results (CSV/JSON like wafw00f), or
  registering an optional passive `ScanCheck` to integrate with Burp's own scans.

## License

Released under the **BSD 3-Clause License**, matching the upstream
[wafw00f](https://github.com/enablesecurity/wafw00f) project. See `LICENSE` for
the full text and `NOTICE` for attribution to the upstream wafw00f project
(signatures © EnableSecurity and contributors) and to PortSwigger (Montoya
API).
