# netskope-ssl-configure-script

Scripts that make developer CLIs, libraries and desktop apps trust the Netskope SSL-inspection CA.

> **Fork:** this repository is a fork of [ns-toconnor/ssl-configure-script](https://github.com/ns-toconnor/ssl-configure-script), extended for Netskope **Secure Enrollment** (tenant API and local STAgent certificates instead of the legacy org-key flow), with more supported tools and Docker support. This version adds the **silent, non-interactive deployment scripts** described below.

> **Disclaimer:** These scripts are based on publicly available Netskope and individual CLI/tool vendor documentation. They are **not** an official Netskope product and are **not supported by Netskope**. Use at your own risk.

## What this fork adds

- **Works when the tenant CA can't be fetched automatically.** The interactive scripts read the CA from the local Netskope client or download it from the tenant, which fails with *Protect Client Configuration and Resources* or Secure Configuration Services. The new build scripts take the tenant certificates you download (root, intermediate and remote users) and check that they belong together.
- **Silent, non-interactive configuration** for GPO / MDM rollout (Windows PowerShell, macOS/Linux bash): no prompts, no API token, runs as SYSTEM/root or as a normal user.
- **Machine-wide and per-user coverage** when run elevated: machine-scope variables and every user profile on Windows; every local account's shell files on macOS/Linux, plus a LaunchAgent (macOS) / `environment.d` (Linux) so GUI apps get the variables too.
- **Configures tools that aren't installed yet.** Environment variables are set for 17 variables covering Python, Azure CLI, AWS CLI, Node.js/npm/Yarn, Git, Go, Ruby, Cargo, gcloud, conda and more, so they work if a tool is installed later. File-based config (Git, Azure Storage Explorer) is skipped and logged when the tool is missing.
- **Never overwrites existing values blindly.** Custom CA bundles that already trust Netskope are kept; custom bundles that don't are merged with the Netskope CA so internal CAs keep working; stale or previous Netskope paths are replaced. `-Force` / `-f` overrides this.
- **Detailed troubleshooting log**: timestamped, with the current value, where it was read from, why each setting was kept or changed, bundle hashes, Netskope CA identity and expiry, and a closing summary.
- **Dry-run mode** (`-DryRun` / `-x`) and meaningful exit codes for MDM reporting.
- **Hardened bundle build**: validates every certificate, checks that the intermediate is signed by the root and that nothing is expired, swapped or duplicated, normalises line endings, writes atomically, supports offline builds.

## Silent deployment (GPO / MDM)

For mass deployment where the tenant CA can't be read from the client or downloaded (*Protect Client Configuration and Resources*, Secure Configuration Services), use the two-step, non-interactive scripts. They never prompt and never need an API token.

| Step | Where it runs | Windows | macOS / Linux |
| --- | --- | --- | --- |
| 1. Build the bundle | Once, on an admin machine | [build_cert_bundle_windows.ps1](build_cert_bundle_windows.ps1) | [build_cert_bundle_unix.sh](build_cert_bundle_unix.sh) |
| 2. Configure tools | Every endpoint (GPO / Intune / Jamf...) | [silent_configure_tools_windows.ps1](silent_configure_tools_windows.ps1) | [silent_configure_tools_unix.sh](silent_configure_tools_unix.sh) |

### Step 1 — build `netskope-cert-bundle.pem`

1. In the tenant, go to **Settings → Manage → Certificates → Netskope Certificates** and download the three certificates. Save them **in the same directory as the build script** with these names:

   | Save as | Tenant download | Required |
   | --- | --- | --- |
   | `netskope-root-ca.pem` | Netskope root certificate | **Yes**: this CA signs the traffic inspected by the Netskope Client |
   | `netskope-intermediate-ca.pem` | Netskope intermediate certificate | Recommended (warning if missing) |
   | `netskope-remote-users-ca.pem` | Netskope root certificate (remote users) | Recommended (warning if missing) |

   > The **remote users** certificate on its own is **not** enough: traffic through the Netskope Client is signed by the tenant root → intermediate chain, so tools would still fail with `self signed certificate in certificate chain`. Older versions of this README asked only for that certificate (as `netskope-cert.pem`); the build scripts now stop with a migration message if they find only that file.

2. Run the build script (no arguments needed):
   - Windows: `powershell -ExecutionPolicy Bypass -File .\build_cert_bundle_windows.ps1`
   - macOS/Linux: `./build_cert_bundle_unix.sh`
3. `netskope-cert-bundle.pem` appears next to it: the Netskope certificates first (root, intermediate, remote users), then the Mozilla root bundle from `curl.se`. The header records which ones were included (`# netskope-certs: root, intermediate, remote-users`) and how many (`# netskope-cert-count: 3`).

Before writing anything, the build checks the inputs, so a wrong or swapped file fails on the admin machine instead of on the endpoints:

- each file holds exactly one valid certificate
- the root and remote-users certificates are self-signed
- the intermediate is **signed by** the root (signature checked, not just the name: every tenant's root is named `CN=certadmin`, so a root from another tenant would pass a name check)
- no certificate is expired (warning if it expires within 90 days)
- no certificate appears under two names

Line endings are normalised and the output is written atomically.

Offline packaging: pass a local copy of Mozilla's `cacert.pem` (`-MozillaBundlePath` on Windows, `-m` on Unix). Other options:

| | Windows | macOS / Linux |
| --- | --- | --- |
| Input/output directory | `-Dir` | `-d` |
| Root CA filename | `-RootName` | `-r` |
| Intermediate CA filename | `-IntermediateName` | `-t` |
| Remote-users CA filename | `-RemoteUsersName` | `-u` |
| Output filename | `-OutputName` | `-o` |

### Step 2 — deploy and configure

Package `netskope-cert-bundle.pem` **together with** the silent script and run the script on each endpoint. The script copies the bundle to the directory below (only when missing or different), then configures the tools.

| Item | Windows | macOS / Linux |
| --- | --- | --- |
| Bundle location on endpoint | `C:\netskope\netskope-cert-bundle.pem` | `/usr/local/netskope/netskope-cert-bundle.pem` |
| Log file | `%PUBLIC%\netskope-ssl-configure-tools.log` (`C:\Users\Public\...`) | macOS: `/Users/Shared/netskope-ssl-configure-tools.log`<br>Linux: `/var/tmp/netskope-ssl-configure-tools.log` |
| Run as | SYSTEM / admin (machine-wide + all profiles) or a normal user (that user only) | root (all local users) or a normal user (that user only) |
| Override location | `-CertDir`, `-CertName`, `-LogPath` | `-d`, `-n`, `-l` |
| Dry run (log only, change nothing) | `-DryRun` | `-x` |
| Always overwrite existing values | `-Force` | `-f` |
| Merged bundles (see below) | `C:\netskope\merged\` (elevated) · `%LOCALAPPDATA%\netskope\merged\` (user run) | `/usr/local/netskope/merged/` (root) · `~/.netskope/merged/` (user run) |

The macOS/Linux default differs from the interactive script's `~/netskope` because a per-user directory doesn't work for a root-run MDM job that serves every user. The Windows default is unchanged.

Deployment examples:

- **GPO (Windows)** — Computer Configuration → Windows Settings → Scripts → Startup → PowerShell Scripts; put the `.ps1` and the `.pem` in the same share/folder. Or Intune: Devices → Scripts, "Run this script using the logged on credentials" = **No** (runs as SYSTEM).
- **Jamf / Intune / Kandji (macOS)** — package the `.sh` and the `.pem` in the same directory (or a `.pkg` that drops them in one place) and run the script as root.

**Where files live on the device**

| What | Windows | macOS / Linux |
| --- | --- | --- |
| Certificate bundle (`netskope-cert-bundle.pem`) | `C:\netskope\` | `/usr/local/netskope/` |
| Silent script | Anywhere: the GPO/Intune/Jamf package folder or share. It does not need to be installed. | Anywhere (the MDM package location) |
| Bundle shipped with the script | **Same folder as the silent script**; the script copies it into the folder above | **Same folder as the silent script** |
| Merged bundles (only if a user had a custom CA bundle) | `C:\netskope\merged\` | `/usr/local/netskope/merged/` |
| macOS GUI env script | n/a | `/usr/local/netskope/netskope-gui-env.sh` |
| Log | `C:\Users\Public\netskope-ssl-configure-tools.log` | macOS `/Users/Shared/…`, Linux `/var/tmp/…` |

- **Windows:** `C:\netskope` is the same default as the interactive script. When run elevated, the script locks it to SYSTEM/Administrators full control and Users read-only.
- **macOS/Linux:** the interactive script used `~/netskope` (per user). The silent script uses one shared `/usr/local/netskope` so a root-run MDM job serves every account.
- **Do not deploy** the build inputs (`netskope-root-ca.pem`, `netskope-intermediate-ca.pem`, `netskope-remote-users-ca.pem`) or the `build_cert_bundle_*` scripts to devices; they stay on the admin machine. Only `netskope-cert-bundle.pem` and the `silent_configure_tools_*` script go out.
- To re-run the script later (scheduled task, login script), put the script and the bundle together in a permanent folder, e.g. `C:\netskope\` itself. Running it from the bundle's own folder is supported.
- Use `-CertDir` (Windows) or `-d` (macOS/Linux) to choose a different location.

**What gets configured**

- **Environment variables — configured even for tools that aren't installed yet**, so they work if the tool is installed later: `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `AWS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `npm_config_cafile`, `YARN_HTTPS_CA_FILE_PATH`, `PIP_CERT`, `GIT_SSL_CAINFO`, `CARGO_HTTP_CAINFO`, `OCI_CLI_CA_BUNDLE`, `CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE`, `GRPC_DEFAULT_SSL_ROOTS_FILE_PATH`, `COMPOSER_CAFILE`, `DENO_CERT`, `CONDA_SSL_VERIFY`, `NETSKOPE_CA_BUNDLE`. Together these cover Python (requests, pip, httpx, Poetry), Azure CLI, AWS CLI, Node.js/npm/Yarn/Bun/Deno, Claude CLI/Desktop, VS Code/Cursor, Git, Go, Ruby, Terraform, Cargo, gcloud, Oracle CLI, Composer, conda, cURL, OpenSSL and the Netskope CLI.
  - Windows: machine-scope variables when elevated (user-scope otherwise).
  - macOS/Linux: a marker-delimited managed block (`# >>> netskope-ssl-configure ... <<<`) in each user's shell rc files, replaced in place on re-runs, so existing content is never duplicated. On macOS a LaunchAgent (`com.netskope.ssl-trust-env`) also exports the variables to GUI apps at every login (Claude Desktop, VS Code launched from the Dock...), using each user's decided values from `~/.netskope/ssl-env`. On Linux a systemd `environment.d` file does the same for GUI sessions.
- **File/directory-based config — only when the tool is present, otherwise skipped and logged:** the Git `http.sslCAInfo` setting in each user's `~/.gitconfig` (same rules as the variables below), and the Azure Storage Explorer `certs` directory (bundle copy).

**Existing values are never overwritten blindly.** A developer may already point `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS` etc. at a custom bundle with internal/private CAs. Internal hosts are often not steered through Netskope, so replacing that bundle would break them. Each existing value is checked:

| Existing value | Action | Log |
| --- | --- | --- |
| unset, a missing file, or not a certificate file (e.g. `CONDA_SSL_VERIFY=false`) | set the Netskope bundle | `OK` |
| already the Netskope bundle | leave | `SKIP` |
| a previous Netskope bundle (path contains a `netskope` folder, or file named `netskope*` / `nscacert*` / `nstenantcert*`) | replace with the Netskope bundle | `OK` |
| a custom bundle that **already contains** the Netskope CA | leave | `SKIP` |
| a custom bundle **without** the Netskope CA | **merge**: write `merged-<hash>.pem` (the custom certs + the Netskope CA) and point the variable at it | `OK` |
| a directory, an unreadable file, or (Unix) a shell expression such as `$(python -m certifi)` | leave | `WARN` |

`-Force` / `-f` skips all of this and sets the Netskope bundle everywhere.

How the pieces fit:

- **Which certs count as "the Netskope CA"**: the build scripts write a `# netskope-cert-count: N` header; the first N certificates of the bundle are the Netskope CA. A bundle without the header (e.g. built by the interactive scripts) still deploys, but custom bundles are then left untouched (`WARN`) because there is nothing reliable to check or merge. Rebuild with `build_cert_bundle_*` to enable merging.
- **Merged bundles stay current**: each one records its source (`# netskope-merged-from: <path>`) and is regenerated on every run, so a rotated Netskope CA or the developer's own edits to their custom bundle carry through. If the source file is deleted, the variable falls back to the Netskope bundle. One merged file is shared by all variables that point at the same source.
- **Windows, elevated (GPO/Intune as SYSTEM)**: decides on the *machine* value, then loads every user profile's registry hive and checks *per-user* values of the same variables. A per-user value always beats the machine value at runtime, so leaving it unchecked would undo the deployment for that user. A stale per-user value is deleted when the machine value is correct (so future machine updates reach that user); a custom one is kept or merged as in the table. Per-user changes apply at that user's next logon. It also locks `C:\netskope` to SYSTEM/Administrators full control and Users read-only; by default, folders created under `C:\` let any authenticated user modify them, which would let one user swap the machine-wide trust bundle.
- **Windows, normal user**: decides on the value the user actually gets (user scope, else machine scope) and writes only user scope. If GPO already set the machine value correctly and the user has no override, nothing changes.
- **macOS/Linux**: the existing value is the user's own `export VAR=...` line in `.zshenv`, `.zprofile`, `.zshrc`, `.zlogin`, `.bash_profile`, `.bash_login`, `.profile` or `.bashrc`. When the decision changes it (replace or merge), that line would still override the managed block (it loads later), so it is **commented out** with a dated `# [disabled by netskope-ssl-configure YYYY-MM-DD]` prefix after the file is backed up once to `<file>.netskope-bak`. Lines whose value is kept are not touched, and the variable is left out of the managed block. As root every local account is processed; as a normal user, a value inherited from elsewhere (system profile, `launchctl`) is checked too.

**Log format** — one line per action, appended, rotated to `.old` at 2 MB. Each run writes:

1. **A diagnostic header**: host, OS version, PowerShell/bash version, account and elevation, flags, script and log paths.
2. **Bundle facts**: whether the shipped bundle was installed (first install / replaced, with SHA256 before → after) or was already identical; size, modification time and SHA256 of the deployed bundle; and for each Netskope CA certificate its subject, issuer, validity dates and SHA1 thumbprint. A `WARN` is logged when it is expired or expires within 30 days.
3. **The accounts/profiles in scope**, the tools found on the process PATH (with their paths), and per-user registry hive state on Windows.
4. **One line per decision**, always stating *what was found*, *where it was read from*, *why* it was kept or changed, and *the new value*:

```
[OK   ] Machine CURL_CA_BUNDLE: set to 'C:\netskope\netskope-cert-bundle.pem' - value is a previous Netskope bundle location (path contains a "netskope" folder); previous value 'C:\old\netskope\netskope-cert-bundle.pem' [cURL, Netskope CLI]
[OK   ] Machine SSL_CERT_FILE: set to 'C:\netskope\merged\merged-77792eeb7f74.pem' - custom bundle with 2 certificate(s) includes only 0 of 1 Netskope CA certificate(s); merged into a new bundle (2 from the source + 1 Netskope CA certificate(s)) so its other CAs keep working; previous value 'D:\certs\corp.pem' [OpenSSL, ...]
[SKIP ] Machine NODE_EXTRA_CA_CERTS: no change - value already points to the Netskope bundle: 'C:\netskope\netskope-cert-bundle.pem' [Node.js, ...]
[SKIP ] Machine REQUESTS_CA_BUNDLE: no change - kept existing value 'D:\certs\corp-with-ns.pem' - custom bundle with 2 certificate(s) that already includes all 1 Netskope CA certificate(s) [Python Requests, ...]
[SKIP ] Machine SSL_CERT_FILE: no change - merged bundle 'C:\netskope\merged\merged-77792eeb7f74.pem' is up to date with its source 'D:\certs\corp.pem' (2 from the source + 1 Netskope CA certificate(s)) [OpenSSL, ...]
[OK   ] User[jdoe] AWS_CA_BUNDLE: per-user override removed so the Machine value 'C:\netskope\netskope-cert-bundle.pem' applies at next logon - file does not exist; previous value 'C:\old.pem' (read from HKU\S-1-5-21-...\Environment) [AWS CLI]
[SKIP ] jdoe REQUESTS_CA_BUNDLE: no change - kept existing value '/Users/jdoe/corp.pem' (read from user's own line /Users/jdoe/.zshrc:12, written as '~/corp.pem') - custom bundle with ... [Python Requests, ...]
[WARN ] jdoe PIP_CERT: no change - kept existing value '$(python -m certifi)' (read from user's own line /Users/jdoe/.bashrc:5) - it is a shell expression that cannot be evaluated safely; use -f to replace [pip]
[OK   ] Commented out the user's own definitions of SSL_CERT_FILE (line 2), CURL_CA_BUNDLE (line 4) in /Users/jdoe/.bashrc - they load after the managed block and would override it (backup: /Users/jdoe/.bashrc.netskope-bak)
[SKIP ] Azure Storage Explorer: no change - C:\Users\jdoe\...\certs\netskope-cert-bundle.pem is identical to the bundle (SHA256 09557C357811A656...)
```

5. **A closing summary**: `Summary: 7 changed (OK), 16 unchanged (SKIP), 2 warning(s), 0 error(s) in 2.1s`.

Levels: `INFO` (context), `OK` (changed something), `SKIP` (nothing to change: already configured, value kept on purpose, or tool not installed), `WARN` (needs attention), `ERROR` (a step failed). Value sources you may see after "read from": a scope (`User scope`, `Machine scope; no User value`), a registry key (`HKU\<SID>\Environment`, with the raw `%USERPROFILE%` form if it differs), a file and line (`user's own line ~/.zshrc:12`), `managed block from a previous run`, or `inherited environment`.

**Exit codes** — `0` done (skips are not errors) · `2` done but at least one step failed (see `ERROR` lines) · `1` fatal (e.g. bundle missing or invalid).

**Troubleshooting**

- Read the log first; every run starts with a `start` line and the diagnostic header, and ends with a `Summary` and a `finished` line. `grep " SSL_CERT_FILE"` (or `Select-String`) across the log shows that variable's history across runs.
- Compare the bundle SHA256 and Netskope CA thumbprint in the header with the bundle you built to confirm which bundle an endpoint actually has.
- Env changes reach **new** processes/logins only; restart running terminals and apps.
- A tool still fails for one user? Search the log for that user and variable: `kept` lines (`SKIP`/`WARN`) show values left alone on purpose. `WARN` cases (directory, shell expression, missing bundle header) need a manual look, or a run with `-Force` / `-f`.
- Windows per-user values are checked only for profiles whose registry hive could be loaded; a `could not load registry hive` warning means that user was logged on in a way that locked it. The next run will retry.
- Undo a commented-out rc line on macOS/Linux: restore `<file>.netskope-bak`, or delete the `# [disabled by netskope-ssl-configure ...]` prefix.
- Under SYSTEM/root, the "Tools on PATH" log line only reflects the service account's PATH; it doesn't prove a tool is missing from a user's profile. Environment variables are set either way.
- Not covered by these scripts: Docker (use the interactive scripts' `docker/` assets), Java keystores, and VS Code `settings.json` edits (the inherited `NODE_EXTRA_CA_CERTS` makes them unnecessary).

## Original interactive scripts

The interactive tooling this fork started from is still in the repository: [configure_tools_unix.sh](configure_tools_unix.sh), [configure_tools_windows.cmd](configure_tools_windows.cmd) / [configure_tools_windows.ps1](configure_tools_windows.ps1) and [universal_configure_tools.py](universal_configure_tools.py). They prompt for the tenant, fetch the CA from the Netskope API or local client, and configure the invoking user, including generating Docker container assets. Their documentation (usage, tools configured, Docker, notes) is in the [README as of that version](https://github.com/Base4Security/netskope-ssl-configure-script/blob/60e8f5a/README.md).

[check_ssl.js](check_ssl.js) is a Node.js probe to verify a TLS endpoint after configuration: it prints the presented certificate chain and whether Node's trust store (system roots + `NODE_EXTRA_CA_CERTS`) validated it. Usage: `node check_ssl.js [host[:port]] [path]`.
