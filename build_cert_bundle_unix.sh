#!/bin/bash
## Builds netskope-cert-bundle.pem (Netskope tenant CAs + Mozilla root bundle) from the
## Netskope certificates that sit next to this script. Non-interactive. macOS and Linux.
##
## Intended for the admin/packaging machine. Download the certificates from the tenant
## (Settings > Manage > Certificates > Netskope Certificates) and save them next to this script:
##   netskope-root-ca.pem          <- "Netskope root certificate.pem"                 (required)
##   netskope-intermediate-ca.pem  <- "Netskope intermediate certificate.pem"         (recommended)
##   netskope-remote-users-ca.pem  <- "Netskope root certificate (remote users).pem"  (recommended)
## The output, netskope-cert-bundle.pem, is what silent_configure_tools_unix.sh deploys to
## endpoints (default /usr/local/netskope).
##
## Usage: ./build_cert_bundle_unix.sh [-d DIR] [-r ROOT] [-t INTERMEDIATE] [-u REMOTE_USERS]
##                                    [-o OUTPUT] [-m MOZILLA_CACERT.PEM]
##   -d  directory with the inputs and receiving the output  (default: script directory)
##   -r  root CA filename                                    (default: netskope-root-ca.pem)
##   -t  intermediate CA filename                            (default: netskope-intermediate-ca.pem)
##   -u  remote-users CA filename                            (default: netskope-remote-users-ca.pem)
##   -o  bundle filename                                     (default: netskope-cert-bundle.pem)
##   -m  local Mozilla bundle to use instead of downloading  (offline packaging)
##
## Checks before writing: one valid certificate per file; root and remote-users self-signed;
## intermediate signed by the root; none expired (warn within 90 days); no duplicates.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_NAME="netskope-root-ca.pem"
INT_NAME="netskope-intermediate-ca.pem"
RU_NAME="netskope-remote-users-ca.pem"
OUTPUT_NAME="netskope-cert-bundle.pem"
MOZILLA_LOCAL=""
MOZILLA_URL="https://curl.se/ca/cacert.pem"
MOZILLA_MIN_CERTS=100   # cacert.pem carries ~140; far fewer means an error page / truncation
EXPIRY_WARN_DAYS=90

while getopts "d:r:t:u:o:m:h" opt; do
  case "$opt" in
    d) DIR="$OPTARG" ;;
    r) ROOT_NAME="$OPTARG" ;;
    t) INT_NAME="$OPTARG" ;;
    u) RU_NAME="$OPTARG" ;;
    o) OUTPUT_NAME="$OPTARG" ;;
    m) MOZILLA_LOCAL="$OPTARG" ;;
    *) sed -n '2,23p' "$0"; exit 2 ;;
  esac
done

die()  { echo "Error: $*" >&2; exit 1; }
warn() { echo "Warning: $*" >&2; }
command -v openssl >/dev/null 2>&1 || die "openssl is required"

tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

# normalize_pem SRC DEST LABEL
# Extracts every CERTIFICATE block (ignores any surrounding text), strips CR, validates each
# block with openssl, and writes them to DEST with a guaranteed trailing newline per block.
# Prints the number of certificates.
normalize_pem() {
  local src=$1 dest=$2 label=$3 n i
  : > "$dest"
  tr -d '\r' < "$src" | awk -v d="$tmp_dir" -v lbl="$label" '
    /-----BEGIN CERTIFICATE-----/ { n++; f = sprintf("%s/%s.%04d", d, lbl, n); inblk = 1 }
    inblk { print > f }
    /-----END CERTIFICATE-----/ { if (inblk) close(f); inblk = 0 }
    END { print n + 0 > (d "/" lbl ".count") }'
  n=$(cat "$tmp_dir/$label.count")
  [ "$n" -gt 0 ] || die "$label has no PEM certificates: $src"
  for ((i = 1; i <= n; i++)); do
    local part; part=$(printf '%s/%s.%04d' "$tmp_dir" "$label" "$i")
    openssl x509 -in "$part" -noout 2>/dev/null || die "$label: certificate #$i is not valid"
    cat "$part" >> "$dest"
    [ -z "$(tail -c1 "$part")" ] || echo >> "$dest"
  done
  echo "$n"
}

subject_of() { openssl x509 -in "$1" -noout -subject -nameopt RFC2253 2>/dev/null | sed 's/^subject= *//'; }
issuer_of()  { openssl x509 -in "$1" -noout -issuer  -nameopt RFC2253 2>/dev/null | sed 's/^issuer= *//'; }
sha1_of()    { openssl x509 -in "$1" -noout -fingerprint -sha1 2>/dev/null | sed 's/^.*=//'; }
is_self_signed() { [ "$(subject_of "$1")" = "$(issuer_of "$1")" ]; }

show_cert() {
  echo "    subject : $(subject_of "$1")"
  echo "    issuer  : $(issuer_of "$1")"
  echo "    valid   : $(openssl x509 -in "$1" -noout -startdate | sed 's/^notBefore=//') to $(openssl x509 -in "$1" -noout -enddate | sed 's/^notAfter=//')"
  echo "    SHA1    : $(sha1_of "$1")"
}

# Old single-input layout: explain how to migrate instead of a bare "not found".
if [ ! -f "$DIR/$ROOT_NAME" ] && [ -f "$DIR/netskope-cert.pem" ]; then
  die "Found the old input 'netskope-cert.pem' but not '$ROOT_NAME'. The build now takes the tenant certificates under standard names: download them from Settings > Manage > Certificates > Netskope Certificates and save them as $ROOT_NAME, $INT_NAME and $RU_NAME (see README). Note: 'netskope-cert.pem' usually holds the remote-users CA, which alone does NOT fix SSL inspection errors."
fi

# load_role KEY LABEL FILE REQUIRED DOWNLOAD -> $tmp_dir/role.KEY.pem when present
roles_found=()
load_role() {
  local key=$1 label=$2 file=$3 required=$4 download=$5 path n
  path="$DIR/$file"
  if [ ! -f "$path" ]; then
    [ "$required" = 1 ] && die "$label not found: $path (tenant download: '$download')"
    warn "$label not found: $path (tenant download: '$download') - building without it."
    return 0
  fi
  n=$(normalize_pem "$path" "$tmp_dir/role.$key.pem" "$key")
  [ "$n" -eq 1 ] || die "$label file must contain exactly one certificate, found $n: $path"
  echo "$label: $path"
  show_cert "$tmp_dir/role.$key.pem"
  roles_found+=("$key")
}
load_role root         "Netskope root CA"         "$ROOT_NAME" 1 "Netskope root certificate.pem"
load_role intermediate "Netskope intermediate CA" "$INT_NAME"  0 "Netskope intermediate certificate.pem"
load_role remote-users "Netskope remote-users CA" "$RU_NAME"   0 "Netskope root certificate (remote users).pem"

has_role() { local k; for k in "${roles_found[@]}"; do [ "$k" = "$1" ] && return 0; done; return 1; }

# ---- Sanity checks: catch wrong / swapped files before they are deployed ----
ROOT_PEM="$tmp_dir/role.root.pem"
is_self_signed "$ROOT_PEM" || die "$ROOT_NAME is not a self-signed root (issuer '$(issuer_of "$ROOT_PEM")'). Is it the intermediate certificate?"
if has_role intermediate; then
  INT_PEM="$tmp_dir/role.intermediate.pem"
  is_self_signed "$INT_PEM" && die "$INT_NAME is self-signed, so it is not the intermediate CA. Check that the files were not swapped."
  # -no_check_time: expiry is checked separately below (retried without it for LibreSSL builds
  # that lack the flag).
  { openssl verify -no_check_time -CAfile "$ROOT_PEM" "$INT_PEM" >/dev/null 2>&1 \
    || openssl verify -CAfile "$ROOT_PEM" "$INT_PEM" >/dev/null 2>&1; } \
    || die "$INT_NAME (issuer '$(issuer_of "$INT_PEM")') is not signed by $ROOT_NAME ('$(subject_of "$ROOT_PEM")'). The root and intermediate must come from the same tenant; re-download both."
  echo "Check: intermediate CA is signed by the root CA - OK"
fi
if has_role remote-users; then
  is_self_signed "$tmp_dir/role.remote-users.pem" || die "$RU_NAME is not a self-signed root (issuer '$(issuer_of "$tmp_dir/role.remote-users.pem")')."
fi
seen=""
for key in "${roles_found[@]}"; do
  pem="$tmp_dir/role.$key.pem"; fp=$(sha1_of "$pem")
  dup=$(printf '%s' "$seen" | tr '|' '\n' | sed -n "s/^$fp=//p")
  [ -z "$dup" ] || die "$key certificate is the same as the $dup certificate ($fp). Check the file names."
  seen="$seen|$fp=$key"
  end=$(openssl x509 -in "$pem" -noout -enddate | sed 's/^notAfter=//')
  openssl x509 -in "$pem" -noout -checkend 0 >/dev/null 2>&1 || die "$key certificate EXPIRED ($end). Download the current certificate from the tenant."
  openssl x509 -in "$pem" -noout -checkend $((EXPIRY_WARN_DAYS * 86400)) >/dev/null 2>&1 \
    || warn "$key certificate expires within $EXPIRY_WARN_DAYS days ($end) - plan a rebuild."
done

ns_count=${#roles_found[@]}
ns_keys=$(IFS=,; echo "${roles_found[*]}" | sed 's/,/, /g')
: > "$tmp_dir/ns.pem"
for key in "${roles_found[@]}"; do cat "$tmp_dir/role.$key.pem" >> "$tmp_dir/ns.pem"; done

# ---- Mozilla roots ----
if [ -n "$MOZILLA_LOCAL" ]; then
  [ -f "$MOZILLA_LOCAL" ] || die "Mozilla bundle not found: $MOZILLA_LOCAL"
  moz_src="$MOZILLA_LOCAL"
else
  moz_src="$tmp_dir/cacert.download"
  echo "Downloading Mozilla CA bundle: $MOZILLA_URL"
  # Most to least strict; the result is validated below either way:
  #   1. normal TLS verification (machine already trusts the tenant CA, or host not inspected)
  #   2. TLS verified against ONLY the Netskope CA certificates being bundled (behind SSL
  #      inspection on a machine that does not trust the tenant CA yet: the very thing being
  #      built). --cacert replaces the default trust store for this request.
  #   3. no verification (last resort, e.g. some other proxy re-signs the traffic)
  curl_opts=(--connect-timeout 30 --max-time 120 --fail --silent --show-error -o "$moz_src")
  if ! curl "${curl_opts[@]}" "$MOZILLA_URL" 2>/dev/null; then
    warn "verified download failed; retrying trusting only the Netskope CA certificates being bundled."
    if curl "${curl_opts[@]}" --cacert "$tmp_dir/ns.pem" "$MOZILLA_URL" 2>/dev/null; then
      echo "  Downloaded over TLS verified against the Netskope CA."
    else
      warn "download verified against the Netskope CA failed; retrying without certificate verification."
      curl "${curl_opts[@]}" -k "$MOZILLA_URL" \
        || die "could not download the Mozilla bundle (use -m with a local copy)"
    fi
  fi
fi
moz_count=$(normalize_pem "$moz_src" "$tmp_dir/moz.pem" moz)
[ "$moz_count" -ge "$MOZILLA_MIN_CERTS" ] || die "Mozilla bundle has only $moz_count certificates (expected >= $MOZILLA_MIN_CERTS)"
echo "Mozilla roots: $moz_count certificate(s)"

# Atomic write: build next to the target, then rename. The count header tells
# silent_configure_tools_* which leading certs are the Netskope CA (used to check/merge
# existing CA bundles); the netskope-certs line is informational only. PEM readers ignore
# text outside cert blocks.
output_path="$DIR/$OUTPUT_NAME"
{
  echo "# Netskope SSL inspection trust bundle: Netskope tenant CAs + Mozilla roots"
  echo "# Generated by build_cert_bundle_unix.sh on $(date '+%Y-%m-%d %H:%M:%S')"
  echo "# netskope-certs: $ns_keys"
  echo "# netskope-cert-count: $ns_count"
  cat "$tmp_dir/ns.pem" "$tmp_dir/moz.pem"
} > "$output_path.tmp"
chmod 644 "$output_path.tmp"
mv -f "$output_path.tmp" "$output_path"

echo
echo "Bundle written: $output_path ($((ns_count + moz_count)) certificates: $ns_count Netskope [$ns_keys] + $moz_count Mozilla)"
