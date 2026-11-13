#!/bin/bash
## Silently configures developer CLIs/apps to trust the Netskope CA bundle. Built for MDM
## (Jamf, Intune, Kandji...) deployment on macOS; also works on Linux. Never prompts, never
## needs a token.
##
## Expects a ready-made bundle (see build_cert_bundle_unix.sh). If a copy of the bundle sits
## next to this script it is installed to CERT_DIR first, so a deployment package can simply
## be {this script + netskope-cert-bundle.pem}.
##
## Environment variables (SSL_CERT_FILE, REQUESTS_CA_BUNDLE, NODE_EXTRA_CA_CERTS, ...) are
## configured whether or not the tool is installed today, as a managed block in each user's
## shell rc files (+ a LaunchAgent on macOS / environment.d on Linux for GUI apps). When a user
## already defines a variable, the script decides per value instead of blindly overwriting:
##
##   unset / file missing / not a cert file      -> Netskope bundle
##   already the Netskope bundle                 -> leave
##   a previous Netskope bundle (other path)     -> replace with the Netskope bundle
##   a custom bundle that already has the CA     -> leave the user's line alone
##   a custom bundle WITHOUT the Netskope CA     -> merge: custom certs + Netskope CA in a
##                                                  merged file, and point there
##   a directory / unreadable / shell expression -> leave, log WARN
## When the user's own `export VAR=...` line would override the decided value (it loads after
## the managed block), that line is commented out; the file is backed up first (*.netskope-bak).
## -f skips the analysis and always sets the Netskope bundle.
##
## File/directory based configuration (git config, Azure Storage Explorer certs dir) is
## applied only when the tool is present; otherwise it is skipped and the skip is logged.
##
## Run as root (typical MDM): every local user account is configured. Run as a normal user:
## only that user.
##
## Usage: silent_configure_tools_unix.sh [-d CERT_DIR] [-n CERT_NAME] [-l LOG_FILE] [-f] [-x]
##   -d  where the bundle lives on the endpoint   (default /usr/local/netskope)
##   -n  bundle filename                          (default netskope-cert-bundle.pem)
##   -l  log file   (default /Users/Shared/netskope-ssl-configure-tools.log on macOS,
##                           /var/tmp/netskope-ssl-configure-tools.log on Linux)
##   -f  force: always set the Netskope bundle, replacing any existing value
##   -x  dry run: log what would change, change nothing
##
## Exit codes: 0 = done (skips are not errors), 2 = done but some step failed (see log),
##             1 = fatal (e.g. bundle missing).
set -uo pipefail   # deliberately no -e: one failing step must not stop the others

VERSION="1.2"
CERT_DIR="/usr/local/netskope"
CERT_NAME="netskope-cert-bundle.pem"
LOG_FILE=""
DRY_RUN=0
FORCE=0
ERROR_COUNT=0; OK_COUNT=0; SKIP_COUNT=0; WARN_COUNT=0
START_TS=$(date +%s)

while getopts "d:n:l:fxh" opt; do
  case "$opt" in
    d) CERT_DIR="$OPTARG" ;;
    n) CERT_NAME="$OPTARG" ;;
    l) LOG_FILE="$OPTARG" ;;
    f) FORCE=1 ;;
    x) DRY_RUN=1 ;;
    *) sed -n '2,42p' "$0"; exit 2 ;;
  esac
done

case "$(uname -s)" in
  Darwin) IS_MAC=1 ;;
  Linux)  IS_MAC=0 ;;
  *) echo "Unsupported OS: $(uname -s)" >&2; exit 1 ;;
esac
if [ -z "$LOG_FILE" ]; then
  if [ "$IS_MAC" = 1 ]; then LOG_FILE="/Users/Shared/netskope-ssl-configure-tools.log"
  else LOG_FILE="/var/tmp/netskope-ssl-configure-tools.log"; fi
fi
IS_ROOT=0; [ "$(id -u)" = 0 ] && IS_ROOT=1

# ============================================================
# Logging
# ============================================================
log() {   # log LEVEL message
  local level=$1; shift
  case "$level" in
    ERROR) ERROR_COUNT=$((ERROR_COUNT + 1)) ;; OK) OK_COUNT=$((OK_COUNT + 1)) ;;
    SKIP)  SKIP_COUNT=$((SKIP_COUNT + 1)) ;;   WARN) WARN_COUNT=$((WARN_COUNT + 1)) ;;
  esac
  local line
  line=$(printf '%s [%-5s] %s' "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$*")
  echo "$line"
  { echo "$line" >> "$LOG_FILE"; } 2>/dev/null || true   # logging must never break the run
}

init_log() {
  { mkdir -p "$(dirname "$LOG_FILE")" || true; } 2>/dev/null
  # Keep one previous generation once the log passes 2 MB.
  if [ -f "$LOG_FILE" ] && [ "$(wc -c < "$LOG_FILE" 2>/dev/null || echo 0)" -gt 2097152 ]; then
    mv -f "$LOG_FILE" "$LOG_FILE.old" 2>/dev/null || true
  fi
  if [ ! -e "$LOG_FILE" ]; then
    { : > "$LOG_FILE" && chmod 666 "$LOG_FILE"; } 2>/dev/null || true   # any user may append
  fi
}
init_log

# Paths end up inside double-quoted export lines and a sh script - refuse anything that
# could break out of the quotes.
case "$CERT_DIR$CERT_NAME" in *'"'*|*'$'*|*'`'*|*'\'*) echo "Error: CERT_DIR/CERT_NAME contain unsafe characters" >&2; exit 1 ;; esac

BUNDLE="$CERT_DIR/$CERT_NAME"
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP_DIR=$(mktemp -d) || { echo "mktemp failed" >&2; exit 1; }
trap 'rm -rf "$TMP_DIR"' EXIT

sha256() { if command -v shasum >/dev/null 2>&1; then shasum -a 256; else sha256sum; fi; }
file_hash() { sha256 < "$1" 2>/dev/null | cut -c1-64; }
file_size() { wc -c < "$1" 2>/dev/null | tr -d ' '; }
file_mtime() { if [ "$IS_MAC" = 1 ]; then stat -f '%Sm' -t '%Y-%m-%d %H:%M:%S' "$1" 2>/dev/null; else date -r "$1" '+%Y-%m-%d %H:%M:%S' 2>/dev/null; fi; }
fmt_val() { if [ -z "$1" ]; then printf '(unset)'; else printf "'%s'" "$1"; fi; }

if [ "$IS_MAC" = 1 ]; then OS_DESC="macOS $(sw_vers -productVersion 2>/dev/null) ($(sw_vers -buildVersion 2>/dev/null))"
else OS_DESC=$( . /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-Linux}" || echo Linux); fi

log INFO "===== netskope-ssl-configure-tools v$VERSION start ====="
log INFO "Host: $(hostname 2>/dev/null) | OS: $OS_DESC $(uname -m) | bash $BASH_VERSION"
log INFO "Run as: $(id -un) (uid $(id -u)) | root=$IS_ROOT | force=$FORCE | dryrun=$DRY_RUN"
log INFO "Script: $SELF_DIR/$(basename "${BASH_SOURCE[0]}") | log: $LOG_FILE"
log INFO "Bundle target: $BUNDLE"

# ============================================================
# Step 1: make sure the bundle is in place and sane
# ============================================================
fatal() { log ERROR "Fatal: $*"; log INFO "===== finished with FATAL error ====="; exit 1; }

log INFO "--- Bundle ---"
shipped="$SELF_DIR/$CERT_NAME"
if [ ! -f "$shipped" ]; then
  log INFO "No bundle shipped next to the script ($shipped); using the one already at $BUNDLE"
elif [ "$shipped" = "$BUNDLE" ]; then
  log INFO "Script runs from the bundle directory; nothing to install"
else
  new_hash=$(file_hash "$shipped"); old_hash=""; [ -f "$BUNDLE" ] && old_hash=$(file_hash "$BUNDLE")
  if [ "$old_hash" = "$new_hash" ]; then
    log SKIP "Bundle install: no change - installed bundle is identical to the shipped one (SHA256 ${new_hash:0:16}...)"
  elif [ "$DRY_RUN" = 1 ]; then
    log INFO "DRY-RUN would install bundle: $shipped -> $BUNDLE (SHA256 ${old_hash:+${old_hash:0:16}... -> }${new_hash:0:16}...)"
  elif mkdir -p "$CERT_DIR" && { chmod 755 "$CERT_DIR" 2>/dev/null; true; } \
       && cp "$shipped" "$BUNDLE.tmp" && chmod 644 "$BUNDLE.tmp" && mv -f "$BUNDLE.tmp" "$BUNDLE"; then
    if [ -n "$old_hash" ]; then why="replaced a different bundle (SHA256 ${old_hash:0:16}... -> ${new_hash:0:16}...)"
    else why="first install (SHA256 ${new_hash:0:16}...)"; fi
    log OK "Bundle installed: $shipped -> $BUNDLE - $why"
  else
    log ERROR "Could not install bundle to $BUNDLE (permissions? run as root)"
  fi
fi
if [ ! -f "$BUNDLE" ]; then
  if [ "$DRY_RUN" = 1 ] && [ -f "$shipped" ]; then BUNDLE="$shipped"
  else fatal "bundle not found: $BUNDLE (deploy $CERT_NAME next to this script or to $CERT_DIR)"; fi
fi
cert_count=$(grep -c 'BEGIN CERTIFICATE' "$BUNDLE" 2>/dev/null || true)
[ "${cert_count:-0}" -ge 2 ] || fatal "bundle looks invalid (${cert_count:-0} certificate(s)): $BUNDLE"
log INFO "Bundle OK: $cert_count certificate(s), $(file_size "$BUNDLE") bytes, modified $(file_mtime "$BUNDLE"), SHA256 $(file_hash "$BUNDLE")"

# One base64 body per line, whitespace/CR stripped - comparable regardless of wrapping.
cert_bodies() {
  tr -d '\r' < "$1" 2>/dev/null | awk '
    /-----BEGIN CERTIFICATE-----/ { b = ""; p = 1; next }
    /-----END CERTIFICATE-----/   { if (p) print b; p = 0; next }
    p { gsub(/[ \t]/, ""); b = b $0 }'
}

# The build script records how many leading certs are the Netskope CA. Without that we cannot
# tell which certs to look for / merge, so custom bundles are left untouched.
NS_PEM="$TMP_DIR/ns.pem"; NS_BODIES="$TMP_DIR/ns.bodies"; : > "$NS_PEM"; : > "$NS_BODIES"
NS_COUNT=$(sed -n 's/^# netskope-cert-count:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$BUNDLE" | head -1)
NS_COUNT=${NS_COUNT:-0}
if [ "$NS_COUNT" -gt 0 ]; then
  tr -d '\r' < "$BUNDLE" | awk -v n="$NS_COUNT" '
    /-----BEGIN CERTIFICATE-----/ { c++ }
    c >= 1 && c <= n { print }
    /-----END CERTIFICATE-----/ && c >= n { exit }' > "$NS_PEM"
  cert_bodies "$NS_PEM" > "$NS_BODIES"
  log INFO "Netskope CA = first $NS_COUNT certificate(s) of the bundle (from its netskope-cert-count header)"
  # Identity + expiry of each Netskope cert (needs openssl; LibreSSL on macOS is fine).
  if command -v openssl >/dev/null 2>&1; then
    awk -v d="$TMP_DIR" '/-----BEGIN CERTIFICATE-----/{n++; f=sprintf("%s/nscert.%d", d, n)} n{print > f}' "$NS_PEM"
    i=0
    while [ "$i" -lt "$NS_COUNT" ]; do
      i=$((i + 1)); c="$TMP_DIR/nscert.$i"; [ -f "$c" ] || break
      subj=$(openssl x509 -in "$c" -noout -subject 2>/dev/null | sed 's/^subject= *//')
      iss=$(openssl x509 -in "$c" -noout -issuer 2>/dev/null | sed 's/^issuer= *//')
      start=$(openssl x509 -in "$c" -noout -startdate 2>/dev/null | sed 's/^notBefore=//')
      end=$(openssl x509 -in "$c" -noout -enddate 2>/dev/null | sed 's/^notAfter=//')
      fp=$(openssl x509 -in "$c" -noout -fingerprint -sha1 2>/dev/null | sed 's/^.*=//; s/://g')
      log INFO "Netskope CA #$i: subject '$subj' | issuer '$iss' | valid $start to $end | SHA1 $fp"
      if ! openssl x509 -in "$c" -noout -checkend 0 >/dev/null 2>&1; then
        log WARN "Netskope CA #$i EXPIRED ($end) - rebuild the bundle with the current tenant CA"
      elif ! openssl x509 -in "$c" -noout -checkend 2592000 >/dev/null 2>&1; then
        log WARN "Netskope CA #$i expires within 30 days ($end) - plan a bundle rebuild"
      fi
    done
  else
    log INFO "openssl not found - Netskope CA details/expiry not checked"
  fi
else
  log WARN 'Bundle has no "# netskope-cert-count" header (not built by build_cert_bundle_*); existing custom CA bundles will be left as they are instead of being checked/merged. Rebuild the bundle to enable merging.'
fi

# ============================================================
# Decision logic for an existing value
# ============================================================
# decide VALUE -> sets D_ACTION (Skip|Keep|Set|Merge), D_LEVEL, D_SOURCE and D_REASON (a full
# sentence with the evidence, shown in the log).
decide() {
  local cur=$1 lc base src n present
  D_SOURCE=""; D_LEVEL=SKIP
  if [ -z "$cur" ]; then D_ACTION=Set; D_REASON="variable was not set"; return; fi
  if [ "$cur" = "$BUNDLE" ]; then D_ACTION=Skip; D_REASON="value already points to the Netskope bundle"; return; fi
  if [ "$FORCE" = 1 ]; then D_ACTION=Set; D_REASON="-f: replaced without inspecting the existing value"; return; fi
  if [ -f "$cur" ]; then
    if [ ! -r "$cur" ]; then D_ACTION=Keep; D_LEVEL=WARN; D_REASON="file exists but is not readable by $(id -un); use -f to replace"; return; fi
    # One of our merged bundles: re-merge from its source (picks up CA rotation and changes
    # the user made to their own bundle).
    src=$(sed -n 's/^# netskope-merged-from: //p' "$cur" | head -1)
    if [ -n "$src" ]; then
      if [ -f "$src" ]; then D_ACTION=Merge; D_SOURCE="$src"; D_REASON="value is a merged bundle created by this script; re-checked against its source '$src'"
      else D_ACTION=Set; D_REASON="value is a merged bundle created by this script, but its source '$src' no longer exists"; fi
      return
    fi
  fi
  # Earlier Netskope deployments (interactive script's ~/netskope, client folder, ...).
  lc=$(printf '%s' "$cur" | tr '[:upper:]' '[:lower:]'); base=${lc##*/}
  case "$lc" in */netskope/*) D_ACTION=Set; D_REASON='value is a previous Netskope bundle location (path contains a "netskope" folder)'; return ;; esac
  case "$base" in netskope*|nscacert*|nstenantcert*) D_ACTION=Set; D_REASON="value is a previous Netskope bundle (file name '${cur##*/}')"; return ;; esac
  if [ -d "$cur" ]; then D_ACTION=Keep; D_LEVEL=WARN; D_REASON="value is a directory - it cannot be inspected or merged; use -f to replace"; return; fi
  if [ ! -f "$cur" ]; then
    D_ACTION=Set
    case "$cur" in */*) D_REASON="file does not exist" ;; *) D_REASON="value is not a file path" ;; esac
    return
  fi
  n=$(grep -c 'BEGIN CERTIFICATE' "$cur" 2>/dev/null || true)
  if [ "${n:-0}" -eq 0 ]; then D_ACTION=Set; D_REASON="file contains no PEM certificates ($(file_size "$cur") bytes)"; return; fi
  if [ "$NS_COUNT" -eq 0 ]; then
    D_ACTION=Keep; D_LEVEL=WARN
    D_REASON="custom bundle with $n certificate(s); cannot check it for the Netskope CA because the deployed bundle has no netskope-cert-count header (use -f to replace)"; return
  fi
  cert_bodies "$cur" > "$TMP_DIR/cur.bodies"
  present=$(grep -Fxf "$TMP_DIR/cur.bodies" "$NS_BODIES" 2>/dev/null | wc -l | tr -d ' ')
  if [ "$present" -lt "$NS_COUNT" ]; then
    D_ACTION=Merge; D_SOURCE="$cur"; D_REASON="custom bundle with $n certificate(s) includes only $present of $NS_COUNT Netskope CA certificate(s)"
  else
    D_ACTION=Keep; D_REASON="custom bundle with $n certificate(s) that already includes all $NS_COUNT Netskope CA certificate(s)"
  fi
}

# Merged bundles must be readable by the user they serve: next to the bundle when root,
# in the user's own home otherwise (CERT_DIR is root-owned).
if [ "$IS_ROOT" = 1 ]; then MERGE_DIR="$CERT_DIR/merged"; else MERGE_DIR="$HOME/.netskope/merged"; fi
log INFO "Merged bundles (when needed) go to: $MERGE_DIR"

# update_merged SOURCE -> M_PATH, M_CHANGED, M_SUMMARY. One merged file per source path, so
# several variables pointing at the same custom bundle share it.
update_merged() {
  local src=$1 hash content
  hash=$(printf '%s' "$src" | sha256 | cut -c1-12)
  M_PATH="$MERGE_DIR/merged-$hash.pem"
  content=$(
    echo "# netskope-ssl-configure merged bundle - regenerated on every run, do not edit"
    echo "# netskope-merged-from: $src"
    tr -d '\r' < "$src"; echo
    cat "$NS_PEM"
  )
  M_SUMMARY="$(grep -c 'BEGIN CERTIFICATE' "$src" 2>/dev/null) from the source + $NS_COUNT Netskope CA"
  M_CHANGED=1
  [ -f "$M_PATH" ] && [ "$(cat "$M_PATH")" = "$content" ] && M_CHANGED=0
  if [ "$M_CHANGED" = 1 ] && [ "$DRY_RUN" = 0 ]; then
    mkdir -p "$MERGE_DIR" && chmod 755 "$MERGE_DIR" 2>/dev/null
    printf '%s\n' "$content" > "$M_PATH.tmp" && chmod 644 "$M_PATH.tmp" && mv -f "$M_PATH.tmp" "$M_PATH" \
      || log ERROR "Could not write merged bundle $M_PATH"
  fi
}

# resolve NAME TOOLS VALUE WHERE [FROM] -> R_VALUE ("" = leave the existing value), R_NOTE,
# R_CHANGED. Logs "no change" outcomes itself; the caller logs the change it makes.
#   WHERE: who/what is configured (user name, Git); FROM: where the current value was read.
resolve() {
  local name=$1 tools=$2 cur=$3 where=$4 from=${5:-} cv fromtxt=""
  R_VALUE=""; R_NOTE=""; R_CHANGED=0
  cv=$(fmt_val "$cur"); [ -n "$from" ] && fromtxt=" (read from $from)"
  decide "$cur"
  case "$D_ACTION" in
    Skip) R_VALUE="$BUNDLE"; log SKIP "$where $name: no change - $D_REASON: $cv$fromtxt [$tools]" ;;
    Keep) log "$D_LEVEL" "$where $name: no change - kept existing value $cv$fromtxt - $D_REASON [$tools]" ;;
    Set)
      R_VALUE="$BUNDLE"; R_CHANGED=1
      if [ -n "$cur" ]; then R_NOTE="$D_REASON; previous value $cv$fromtxt"; else R_NOTE="$D_REASON$fromtxt"; fi ;;
    Merge)
      update_merged "$D_SOURCE"
      R_VALUE="$M_PATH"
      if [ "$M_PATH" = "$cur" ]; then
        if [ "$M_CHANGED" = 1 ]; then
          log OK "$where $name: merged bundle $([ "$DRY_RUN" = 1 ] && echo 'DRY-RUN would be refreshed' || echo refreshed) '$M_PATH' because its source '$D_SOURCE' or the Netskope CA changed (now $M_SUMMARY certificate(s)) [$tools]"
        else
          log SKIP "$where $name: no change - merged bundle $cv is up to date with its source '$D_SOURCE' ($M_SUMMARY certificate(s)) [$tools]"
        fi
      else
        R_NOTE="$D_REASON; merged into a new bundle ($M_SUMMARY certificate(s)) so its other CAs keep working; previous value $cv$fromtxt"; R_CHANGED=1
      fi ;;
  esac
}

# ============================================================
# Users and rc files
# ============================================================
ENV_VARS=(
  'SSL_CERT_FILE|OpenSSL, Ruby, Go, Terraform, Python ssl/httpx, Netskope CLI'
  'CURL_CA_BUNDLE|cURL, Netskope CLI'
  'REQUESTS_CA_BUNDLE|Python Requests, Azure CLI, Poetry, Netskope CLI'
  'AWS_CA_BUNDLE|AWS CLI'
  'NODE_EXTRA_CA_CERTS|Node.js, Claude CLI/Desktop, Bun, VS Code/Cursor'
  'npm_config_cafile|npm, Yarn 1'
  'YARN_HTTPS_CA_FILE_PATH|Yarn 2+'
  'PIP_CERT|pip'
  'GIT_SSL_CAINFO|Git'
  'CARGO_HTTP_CAINFO|Cargo'
  'OCI_CLI_CA_BUNDLE|Oracle Cloud CLI'
  'CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE|Google Cloud CLI'
  'GRPC_DEFAULT_SSL_ROOTS_FILE_PATH|gRPC clients (gcloud, Python grpc)'
  'COMPOSER_CAFILE|PHP Composer'
  'DENO_CERT|Deno'
  'CONDA_SSL_VERIFY|conda'
  'NETSKOPE_CA_BUNDLE|Netskope CLI (ntsk)'
)
MARK_BEGIN='# >>> netskope-ssl-configure (managed block; do not edit) >>>'
MARK_END='# <<< netskope-ssl-configure <<<'
# Scanned in (approximate) load order; the last definition found is the effective one.
RC_FILES=(.zshenv .zprofile .zshrc .zlogin .bash_profile .bash_login .profile .bashrc)

give_to() { [ "$IS_ROOT" = 1 ] && chown "$1" "$2" 2>/dev/null; return 0; }

# Enumerate target accounts as "user|home|shell".
list_users() {
  if [ "$IS_ROOT" != 1 ]; then echo "$(id -un)|$HOME|${SHELL:-}"; return; fi
  if [ "$IS_MAC" = 1 ]; then
    dscl . -list /Users UniqueID 2>/dev/null | while read -r u uid; do
      [ "${uid:-0}" -ge 500 ] 2>/dev/null || continue
      h=$(dscl . -read "/Users/$u" NFSHomeDirectory 2>/dev/null | sed 's/^NFSHomeDirectory: //')
      s=$(dscl . -read "/Users/$u" UserShell 2>/dev/null | sed 's/^UserShell: //')
      [ -d "$h" ] && case "$h" in /Users/*) echo "$u|$h|$s" ;; esac
    done
  else
    getent passwd 2>/dev/null | awk -F: '$3>=1000 && $3<65534 {print $1"|"$6"|"$7}' | while IFS='|' read -r u h s; do
      [ -d "$h" ] && echo "$u|$h|$s"
    done
  fi
}

# user_defs HOME VAR -> "file<TAB>line<TAB>value" for each `[export] VAR=value` line OUTSIDE
# our block.
user_defs() {
  local home=$1 var=$2 f
  for f in "${RC_FILES[@]}"; do
    [ -f "$home/$f" ] || continue
    awk -v s="$MARK_BEGIN" -v e="$MARK_END" -v var="$var" -v fn="$home/$f" -v q="'" '
      $0 == s { k = 1; next } $0 == e { k = 0; next } k { next }
      match($0, "^[ \t]*(export[ \t]+)?" var "=") {
        v = substr($0, RSTART + RLENGTH); c = substr(v, 1, 1)
        if (c == "\"" || c == q) { v = substr(v, 2); i = index(v, c); if (i) v = substr(v, 1, i - 1) }
        else if (substr(v, 1, 2) != "$(" && c != "`") sub(/[ \t;#].*$/, "", v)   # keep $(...) whole
        print fn "\t" NR "\t" v
      }' "$home/$f"
  done
}

# block_value HOME VAR -> the value our managed block exported last run (any rc file).
block_value() {
  local home=$1 var=$2 f v
  for f in "${RC_FILES[@]}"; do
    [ -f "$home/$f" ] || continue
    v=$(awk -v s="$MARK_BEGIN" -v e="$MARK_END" -v var="$var" '
      $0 == s { k = 1; next } $0 == e { k = 0; next }
      k && index($0, "export " var "=\"") == 1 { v = substr($0, length("export " var "=\"") + 1); sub(/"$/, "", v); print v; exit }' "$home/$f")
    [ -n "$v" ] && { echo "$v"; return; }
  done
}

# Expand ~ and $HOME for that user; prints nothing (failure) if other shell syntax remains.
expand_for() {
  local home=$1 v=$2
  v="${v/#\~/$home}"; v="${v/#\$\{HOME\}/$home}"; v="${v/#\$HOME/$home}"
  case "$v" in *'$'*|*'`'*) return 1 ;; esac
  printf '%s' "$v"
}

# apply_block FILE USER BLOCK -> idempotent insert/replace of the managed block.
apply_block() {
  local file=$1 user=$2 block=$3 existed=0 current tmp nvars
  [ -f "$file" ] && existed=1
  nvars=$(printf '%s\n' "$block" | grep -c '^export ')
  current=""
  [ "$existed" = 1 ] && current=$(awk -v s="$MARK_BEGIN" -v e="$MARK_END" '$0==s{p=1} p{print} $0==e{p=0}' "$file" 2>/dev/null)
  if [ "$current" = "$block" ]; then log SKIP "$user shell rc: no change - managed block in $file already exports the decided values ($nvars variable(s))"; return; fi
  if [ "$DRY_RUN" = 1 ]; then log INFO "DRY-RUN would write the managed block ($nvars variable(s)) to $file"; return; fi
  tmp="$TMP_DIR/rc.tmp"; : > "$tmp"
  if [ "$existed" = 1 ]; then
    awk -v s="$MARK_BEGIN" -v e="$MARK_END" '$0==s{k=1;next} $0==e{k=0;next} !k' "$file" > "$tmp"
    [ -n "$(tail -c1 "$tmp")" ] && echo >> "$tmp"   # block must start on its own line
  fi
  echo "$block" >> "$tmp"
  # cat > keeps the file's owner/mode and follows symlinks (dotfile managers).
  if cat "$tmp" > "$file" 2>/dev/null; then
    [ "$existed" = 0 ] && give_to "$user" "$file"
    if [ -n "$current" ]; then log OK "$user shell rc: managed block updated in $file ($nvars variable(s))"
    elif [ "$existed" = 1 ]; then log OK "$user shell rc: managed block added to $file ($nvars variable(s))"
    else log OK "$user shell rc: created $file with the managed block ($nvars variable(s))"; fi
  else
    log ERROR "Could not write $file"
  fi
}

# disable_lines FILE "VAR1 VAR2..." "DESCRIPTION" -> comment out the user's own definitions.
disable_lines() {
  local file=$1 vars=$2 desc=$3 tmp="$TMP_DIR/dis.tmp"
  if [ "$DRY_RUN" = 1 ]; then log INFO "DRY-RUN would comment out the user's own definitions of $desc in $file (they would override the managed block)"; return; fi
  [ -e "$file.netskope-bak" ] || cp -p "$file" "$file.netskope-bak" 2>/dev/null
  awk -v s="$MARK_BEGIN" -v e="$MARK_END" -v vars="$vars" -v tag="# [disabled by netskope-ssl-configure $(date +%Y-%m-%d)] " '
    BEGIN { n = split(vars, a, " ") }
    $0 == s { k = 1 } $0 == e { k = 0; print; next } k { print; next }
    { for (i = 1; i <= n; i++) if (match($0, "^[ \t]*(export[ \t]+)?" a[i] "=")) { print tag $0; next } print }' "$file" > "$tmp"
  if cat "$tmp" > "$file" 2>/dev/null; then
    log OK "Commented out the user's own definitions of $desc in $file - they load after the managed block and would override it (backup: $file.netskope-bak)"
  else
    log ERROR "Could not update $file"
  fi
}

# write_if_changed PATH CONTENT MODE LABEL [USER]
write_if_changed() {
  if [ -f "$1" ] && [ "$(cat "$1")" = "$2" ]; then log SKIP "$4 already up to date: $1"; return 0; fi
  if [ "$DRY_RUN" = 1 ]; then log INFO "DRY-RUN would write $4: $1"; return 0; fi
  if mkdir -p "$(dirname "$1")" && printf '%s\n' "$2" > "$1" && chmod "$3" "$1"; then
    [ -n "${5:-}" ] && { give_to "$5" "$(dirname "$1")"; give_to "$5" "$1"; }
    log OK "$4 written: $1"; return 0
  fi
  log ERROR "Could not write $4: $1"; return 1
}

# ============================================================
# Step 2: environment variables, per user
# ============================================================
USERS=$(list_users)
if [ -n "$USERS" ]; then
  log INFO "Accounts in scope: $(printf '%s\n' "$USERS" | awk -F'|' '{ printf "%s%s (%s)", sep, $1, $2; sep = "; " }')"
else
  log WARN "No user accounts found to configure"
fi

while IFS='|' read -r user home shell; do
  [ -n "$user" ] || continue
  base="${shell##*/}"
  log INFO "--- User $user ($home, shell ${base:-unknown}) ---"

  # (macOS ships bash 3.2: no associative arrays, so "file<TAB>var" pairs go to a temp file)
  block_lines=(); gui_lines=(); dis_list="$TMP_DIR/disable.list"; : > "$dis_list"
  for e in "${ENV_VARS[@]}"; do
    name=${e%%|*}; tools=${e#*|}
    defs=$(user_defs "$home" "$name")
    eff=""; raw=""; from=""
    if [ -n "$defs" ]; then
      last=$(printf '%s\n' "$defs" | tail -n1)
      raw=$(printf '%s\n' "$last" | cut -f3-)
      ndefs=$(printf '%s\n' "$defs" | wc -l | tr -d ' ')
      from="user's own line $(printf '%s' "$last" | cut -f1):$(printf '%s' "$last" | cut -f2)"
      [ "$ndefs" -gt 1 ] && from="$from, the last of $ndefs definitions"
      if ! eff=$(expand_for "$home" "$raw"); then
        if [ "$FORCE" = 1 ]; then eff="$raw"
        else
          log WARN "$user $name: no change - kept existing value '$raw' (read from $from) - it is a shell expression that cannot be evaluated safely; use -f to replace [$tools]"
          continue
        fi
      fi
      [ "$raw" != "$eff" ] && from="$from, written as '$raw'"
    else
      eff=$(block_value "$home" "$name")
      if [ -n "$eff" ]; then from="managed block from a previous run"
      elif [ "$IS_ROOT" = 0 ] && [ -n "${!name:-}" ]; then
        # Non-root: a value inherited from elsewhere (system profile, launchctl, parent).
        eff="${!name}"; from="inherited environment, not set in the user's rc files"
      else from="not defined in any rc file"; fi
    fi

    resolve "$name" "$tools" "$eff" "$user" "$from"
    if [ -z "$R_VALUE" ]; then
      # Kept: the user's own value stays authoritative; GUI apps get it too.
      [ -n "$defs" ] && gui_lines+=("$name=$eff")
      continue
    fi
    block_lines+=("export $name=\"$R_VALUE\"")
    gui_lines+=("$name=$R_VALUE")
    if [ "$R_CHANGED" = 1 ]; then
      if [ "$DRY_RUN" = 1 ]; then log INFO "DRY-RUN would set $user $name = '$R_VALUE' - $R_NOTE [$tools]"
      else log OK "$user $name: set to '$R_VALUE' (managed block) - $R_NOTE [$tools]"; fi
    fi
    # The user's own line loads after our block and would override the decided value.
    if [ -n "$defs" ] && [ "$eff" != "$R_VALUE" ]; then
      while IFS=$'\t' read -r f ln _; do printf '%s\t%s\t%s\n' "$f" "$name" "$ln" >> "$dis_list"; done <<< "$defs"
    fi
  done

  while IFS= read -r f; do   # not a pipe: ERROR_COUNT must survive
    [ -n "$f" ] || continue
    vars=$(awk -F'\t' -v f="$f" '$1 == f { print $2 }' "$dis_list" | sort -u | tr '\n' ' ')
    where=$(awk -F'\t' -v f="$f" '$1 == f { printf "%s%s (line %s)", sep, $2, $3; sep = ", " }' "$dis_list")
    disable_lines "$f" "${vars% }" "$where"
  done < <(cut -f1 "$dis_list" | sort -u)

  block=$(echo "$MARK_BEGIN"; for l in "${block_lines[@]+"${block_lines[@]}"}"; do echo "$l"; done; echo "$MARK_END")

  if [ "$IS_MAC" = 1 ]; then
    apply_block "$home/.zshenv" "$user" "$block"   # zsh: default since Catalina; read by every invocation
    # bash reads only the FIRST of these on login - never create .bash_profile if .profile
    # already exists, or it would shadow it.
    bash_file=""
    for f in .bash_profile .bash_login .profile; do [ -f "$home/$f" ] && { bash_file="$home/$f"; break; }; done
    if [ -z "$bash_file" ] && [ "$base" = bash ]; then bash_file="$home/.bash_profile"; fi
    [ -n "$bash_file" ] && apply_block "$bash_file" "$user" "$block"
  else
    if [ "$base" = zsh ] || [ -f "$home/.zshenv" ] || [ -f "$home/.zshrc" ]; then apply_block "$home/.zshenv" "$user" "$block"; fi
    if [ "$base" = bash ] || [ -f "$home/.bashrc" ]; then apply_block "$home/.bashrc" "$user" "$block"; fi
    [ -f "$home/.profile" ] && apply_block "$home/.profile" "$user" "$block"
  fi

  # GUI apps don't read shell rc files. macOS: read at login by the LaunchAgent (step 3).
  # Linux: systemd user sessions read environment.d.
  gui=$(for l in "${gui_lines[@]+"${gui_lines[@]}"}"; do echo "$l"; done)
  if [ "$IS_MAC" = 1 ]; then
    write_if_changed "$home/.netskope/ssl-env" "$gui" 644 "GUI env values" "$user"
  else
    [ -d "$home/.config" ] || { [ "$DRY_RUN" = 0 ] && mkdir -p "$home/.config" && give_to "$user" "$home/.config"; }
    write_if_changed "$home/.config/environment.d/netskope-ssl.conf" "$gui" 644 "GUI session env" "$user"
  fi
done <<< "$USERS"
[ "$IS_ROOT" = 1 ] && [ -d "$MERGE_DIR" ] && chmod -R a+rX "$MERGE_DIR" 2>/dev/null

# Informational: which tools can this process see? (Under root this reflects root's PATH, so
# "not found" does not prove a tool is absent from a user's profile.)
found=(); missing=()
for t in python3 pip3 aws az node npm yarn git gcloud curl openssl cargo ruby composer oci claude ntsk docker; do
  if p=$(command -v "$t" 2>/dev/null); then found+=("$t=$p"); else missing+=("$t"); fi
done
log INFO "Tools on PATH of this process ($PATH): ${found[*]:-(none)}"
log INFO "Tools not on PATH (env vars are still configured for future installs): ${missing[*]:-(none)}"

# ============================================================
# Step 3 (macOS): export to GUI apps via launchctl at every login
# ============================================================
if [ "$IS_MAC" = 1 ]; then
  log INFO "--- GUI app environment (launchctl) ---"
  gui_script="$CERT_DIR/netskope-gui-env.sh"
  # Uses the per-user decisions (~/.netskope/ssl-env); accounts created after the last run
  # fall back to the plain bundle for every variable.
  gui_content=$({
    echo '#!/bin/sh'
    echo '# Generated by silent_configure_tools_unix.sh - exports the Netskope CA env vars to GUI apps.'
    echo 'f="$HOME/.netskope/ssl-env"'
    echo 'if [ -f "$f" ]; then'
    echo '  while IFS="=" read -r k v; do [ -n "$k" ] && /bin/launchctl setenv "$k" "$v"; done < "$f"'
    echo 'else'
    for e in "${ENV_VARS[@]}"; do echo "  /bin/launchctl setenv ${e%%|*} \"$BUNDLE\""; done
    echo 'fi'
  })
  if [ "$IS_ROOT" = 1 ]; then agent_dir="/Library/LaunchAgents"; else agent_dir="$HOME/Library/LaunchAgents"; fi
  agent_plist="$agent_dir/com.netskope.ssl-trust-env.plist"
  plist_content=$(cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.netskope.ssl-trust-env</string>
  <key>ProgramArguments</key>
  <array><string>/bin/sh</string><string>$gui_script</string></array>
  <key>RunAtLoad</key><true/>
</dict>
</plist>
EOF
)
  if [ "$IS_ROOT" = 0 ] && [ ! -w "$CERT_DIR" ]; then
    gui_script="$HOME/.netskope/netskope-gui-env.sh"   # CERT_DIR is root-owned
    plist_content=${plist_content//"$CERT_DIR/netskope-gui-env.sh"/$gui_script}
  fi
  if write_if_changed "$gui_script" "$gui_content" 755 "GUI env script" \
     && write_if_changed "$agent_plist" "$plist_content" 644 "LaunchAgent"; then
    # Apply to the user logged in right now (the agent covers future logins).
    if [ "$DRY_RUN" = 1 ]; then
      log INFO "DRY-RUN would apply GUI env to the logged-in user"
    elif [ "$IS_ROOT" = 1 ]; then
      console_user=$(stat -f%Su /dev/console 2>/dev/null)
      if [ -n "$console_user" ] && [ "$console_user" != root ] && [ "$console_user" != loginwindow ]; then
        console_home=$(dscl . -read "/Users/$console_user" NFSHomeDirectory 2>/dev/null | sed 's/^NFSHomeDirectory: //')
        if launchctl asuser "$(id -u "$console_user")" /usr/bin/env HOME="$console_home" /bin/sh "$gui_script" 2>/dev/null; then
          log OK "GUI env applied for logged-in user $console_user (restart open apps to pick it up)"
        else log WARN "Could not apply GUI env for $console_user now; takes effect at next login"; fi
      else
        log INFO "No console user logged in; GUI env applies at next login"
      fi
    else
      /bin/sh "$gui_script" 2>/dev/null && log OK "GUI env applied for $(id -un) (restart open apps to pick it up)" \
        || log WARN "Could not apply GUI env now; takes effect at next login"
    fi
  fi
fi

# ============================================================
# Step 4: file / directory based configuration (only when the tool is present)
# ============================================================
log INFO "--- File-based configuration ---"
if [ "$IS_MAC" = 1 ]; then SE_REL="Library/Application Support/StorageExplorer/certs"; else SE_REL=".config/StorageExplorer/certs"; fi

# Is this a real git? On macOS /usr/bin/git is a stub that pops up the Xcode CLT installer.
git_usable() {
  command -v git >/dev/null 2>&1 || return 1
  if [ "$IS_MAC" = 1 ] && [ "$(command -v git)" = /usr/bin/git ]; then
    xcode-select -p >/dev/null 2>&1 || return 1
  fi
  return 0
}
HAVE_GIT=0; git_usable && HAVE_GIT=1
if [ "$HAVE_GIT" = 1 ]; then
  log INFO "Git: using $(command -v git) ($(git --version 2>/dev/null))"
elif [ "$IS_MAC" = 1 ] && [ -x /usr/bin/git ]; then
  log SKIP "Git: only the /usr/bin/git stub is present (Xcode Command Line Tools not installed; running it would pop up an installer) - skipped .gitconfig update; GIT_SSL_CAINFO is still configured"
else
  log SKIP "Git: not installed (git not on PATH) - skipped .gitconfig update; GIT_SSL_CAINFO is still configured"
fi

while IFS='|' read -r user home shell; do
  [ -n "$user" ] || continue

  # --- Git: same decision rules as the env vars ---
  if [ "$HAVE_GIT" = 1 ]; then
    cfg="$home/.gitconfig"
    cur=$(git config --file "$cfg" --get http.sslCAInfo 2>/dev/null)
    [ -n "$cur" ] && cur=$(expand_for "$home" "$cur" || printf '%s' "$cur")
    if [ -f "$cfg" ]; then from="$cfg"; else from="$cfg - file does not exist yet"; fi
    resolve "http.sslCAInfo" "Git" "$cur" "$user Git" "$from"
    if [ "$R_CHANGED" = 1 ]; then
      if [ "$DRY_RUN" = 1 ]; then
        log INFO "DRY-RUN would set $user Git http.sslCAInfo = '$R_VALUE' in $cfg - $R_NOTE"
      else
        existed=0; [ -f "$cfg" ] && existed=1
        if git config --file "$cfg" http.sslCAInfo "$R_VALUE" 2>/dev/null; then
          [ "$existed" = 0 ] && give_to "$user" "$cfg"
          log OK "$user Git http.sslCAInfo: set to '$R_VALUE' in $cfg - $R_NOTE"
        else
          log ERROR "$user Git: could not update $cfg"
        fi
      fi
    fi
  fi

  # --- Azure Storage Explorer (reads extra certs from its own certs/ directory) ---
  se_dir="$home/$SE_REL"
  se_file="$se_dir/$CERT_NAME"
  if [ ! -d "$se_dir" ]; then
    log SKIP "$user Azure Storage Explorer: not installed (no $se_dir) - skipped"
  else
    bh=$(file_hash "$BUNDLE"); th=""; [ -f "$se_file" ] && th=$(file_hash "$se_file")
    if [ "$th" = "$bh" ]; then
      log SKIP "$user Azure Storage Explorer: no change - $se_file is identical to the bundle (SHA256 ${bh:0:16}...)"
    else
      if [ -n "$th" ]; then why="replacing an outdated copy (SHA256 ${th:0:16}... -> ${bh:0:16}...)"; else why="first copy"; fi
      if [ "$DRY_RUN" = 1 ]; then
        log INFO "DRY-RUN would copy bundle to $se_file ($why)"
      elif cp "$BUNDLE" "$se_file"; then
        give_to "$user" "$se_file"
        log OK "$user Azure Storage Explorer: bundle copied to $se_file ($why)"
      else
        log ERROR "$user Azure Storage Explorer: could not copy bundle to $se_dir"
      fi
    fi
  fi
done <<< "$USERS"

# ============================================================
# Done
# ============================================================
log INFO "Summary: $OK_COUNT changed (OK), $SKIP_COUNT unchanged (SKIP), $WARN_COUNT warning(s), $ERROR_COUNT error(s) in $(( $(date +%s) - START_TS ))s"
if [ "$ERROR_COUNT" -gt 0 ]; then
  log WARN "===== finished with $ERROR_COUNT error(s) - see lines marked ERROR ====="
  exit 2
fi
log INFO "===== finished OK (new shells/logins pick up env changes; running apps do not) ====="
exit 0
