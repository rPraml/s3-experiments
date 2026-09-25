#!/usr/bin/env bash
#
# s3curl.sh - minimal Amazon S3 REST client using curl + openssl only
#
# Supported:
#   put     LOCAL_FILE S3_KEY
#   get     S3_KEY LOCAL_FILE
#   delete  S3_KEY
#   rename  OLD_S3_KEY NEW_S3_KEY
#   mkdir    S3_PREFIX
#   mb       create bucket (S3_BUCKET)
#   ls       [S3_PREFIX]
#
# Credentials:
#   AWS_ACCESS_KEY_ID
#   AWS_SECRET_ACCESS_KEY
#   AWS_SESSION_TOKEN     (optional, for temporary credentials)
#   AWS_REGION             (default: eu-central-1; used for signing)
#   S3_ENDPOINT             complete S3 service URL; custom endpoints use path-style
#   S3_PATH_STYLE           1/0; defaults to 1 for custom endpoints, 0 for AWS
#   S3_BUCKET              (required)
#   S3CURL_DEBUG=1         log signing and HTTP-response diagnostics
#   S3CURL_CURL_VERBOSE=1  enable curl's raw verbose output (may expose credentials)
#
# Example:
#   export AWS_ACCESS_KEY_ID='AKIA...'
#   export AWS_SECRET_ACCESS_KEY='...'
#   export AWS_REGION='eu-central-1'
#   export S3_BUCKET='my-bucket'
#   # For RustFS/MinIO and other S3-compatible services:
#   # export S3_ENDPOINT='http://127.0.0.1:9000'
#   # export S3_PATH_STYLE=1
#
#   ./s3curl.sh put file.txt backup/file.txt
#   ./s3curl.sh get backup/file.txt downloaded.txt
#   ./s3curl.sh ls
#   ./s3curl.sh ls backup/
#   ./s3curl.sh mkdir backup/2026/
#   ./s3curl.sh rename backup/file.txt backup/old.txt
#   ./s3curl.sh delete backup/old.txt
#
# Notes:
# - S3 has object keys, not real directories. "mkdir" creates a zero-byte
#   directory marker object ending in "/".
# - rename is COPY + DELETE.
# - This script uses AWS Signature Version 4 with the Authorization header.
# - Put/get/rename are intended for normal single-object operations.
#   S3 CopyObject is limited to 5 GiB for a single copy operation; larger
#   objects require multipart copy.
#

set -u
set -o pipefail

SCRIPT_NAME="${0##*/}"

: "${AWS_REGION:=eu-central-1}"
_s3_endpoint_was_set="${S3_ENDPOINT+x}"
if [[ -z "${S3_ENDPOINT:-}" ]]; then
    S3_ENDPOINT="https://${S3_BUCKET:-}.s3.${AWS_REGION}.amazonaws.com"
fi
S3_ENDPOINT="${S3_ENDPOINT%/}"
if [[ -z "${S3_PATH_STYLE+x}" ]]; then
    if [[ -n "${_s3_endpoint_was_set}" ]]; then
        S3_PATH_STYLE=1
    else
        S3_PATH_STYLE=0
    fi
fi

die() {
    echo "ERROR: $*" >&2
    exit 1
}

debug() {
    [[ "${S3CURL_DEBUG:-0}" == "1" ]] || return 0
    printf 'DEBUG: %s\n' "$*" >&2
}

usage() {
    cat >&2 <<EOF
Usage:
  $SCRIPT_NAME put    LOCAL_FILE S3_KEY
  $SCRIPT_NAME get    S3_KEY LOCAL_FILE
  $SCRIPT_NAME delete S3_KEY
  $SCRIPT_NAME rename OLD_S3_KEY NEW_S3_KEY
  $SCRIPT_NAME mkdir  S3_PREFIX
  $SCRIPT_NAME mb
  $SCRIPT_NAME ls     [S3_PREFIX]

Environment:
  AWS_ACCESS_KEY_ID       AWS access key
  AWS_SECRET_ACCESS_KEY   AWS secret access key
  AWS_SESSION_TOKEN       optional temporary-session token
  AWS_REGION              signing region (default: eu-central-1)
  S3_BUCKET               bucket name
  S3_ENDPOINT              complete service URL; e.g. http://127.0.0.1:9000
  S3_PATH_STYLE            1 for /bucket/key URLs, 0 for virtual-hosted URLs
  S3CURL_DEBUG=1           log request/signing diagnostics (without secrets)
  S3CURL_CURL_VERBOSE=1    enable curl -v; may expose credentials, use only locally

Examples:
  export AWS_REGION=eu-central-1
  export S3_BUCKET=my-bucket

  $SCRIPT_NAME put test.txt backup/test.txt
  $SCRIPT_NAME get backup/test.txt test.txt
  $SCRIPT_NAME ls
  $SCRIPT_NAME ls backup/
  $SCRIPT_NAME mkdir backup/2026/
  $SCRIPT_NAME mb
  $SCRIPT_NAME rename backup/a.txt backup/b.txt
  $SCRIPT_NAME delete backup/b.txt
EOF
    exit 2
}

[[ -n "${AWS_ACCESS_KEY_ID:-}" ]] || die "AWS_ACCESS_KEY_ID is not set"
[[ -n "${AWS_SECRET_ACCESS_KEY:-}" ]] || die "AWS_SECRET_ACCESS_KEY is not set"
[[ -n "${S3_BUCKET:-}" ]] || die "S3_BUCKET is not set"

# ---------------------------------------------------------------------------
# RFC 3986 percent encoding.
#
# For S3 canonical URIs, "/" must remain "/" because it separates path
# components. For query-string names/values, "/" is encoded as %2F.
# ---------------------------------------------------------------------------
uri_encode() {
    local s="$1"
    local keep_slash="${2:-0}"
    local out="" c hex i
    LC_ALL=C

    # Iterate over bytes. With LC_ALL=C, ${s:i:1} addresses one byte.
    for ((i=0; i<${#s}; i++)); do
        c="${s:i:1}"
        case "$c" in
            [a-zA-Z0-9.~_-])
                out+="$c"
                ;;
            /)
                if [[ "$keep_slash" == 1 ]]; then
                    out+="/"
                else
                    out+="%2F"
                fi
                ;;
            *)
                printf -v hex '%02X' "'$c"
                out+="%${hex}"
                ;;
        esac
    done
    printf '%s' "$out"
}

# AWS canonical URI encoding must not normalize "."/".." or duplicate "/".
canonical_key_path() {
    local key="$1"
    [[ "$key" == /* ]] || key="/$key"
    uri_encode "$key" 1
}

# SHA256 of a file. For an empty string use the known SHA256.
sha256_file() {
    local file="$1"
    openssl dgst -sha256 -r "$file" | awk '{print $1}'
}

sha256_string() {
    printf '%s' "$1" | openssl dgst -sha256 -r | awk '{print $1}'
}

hmac_sha256_hex() {
    local key="$1"
    local data="$2"
    printf '%s' "$data" |
        openssl dgst -sha256 -mac HMAC -macopt "hexkey:$key" -binary |
        od -An -tx1 -v | tr -d ' \n'
}

# Convert an arbitrary binary key to hex for openssl -macopt hexkey:.
# xxd is deliberately not used.
hex_of_stdin() {
    od -An -tx1 -v | tr -d ' \n'
}

hmac_sha256_hex_binkey() {
    local key_hex="$1"
    local data="$2"
    printf '%s' "$data" |
        openssl dgst -sha256 -mac HMAC -macopt "hexkey:$key_hex" -binary |
        od -An -tx1 -v | tr -d ' \n'
}

# AWS SigV4 signing key:
# kDate    = HMAC("AWS4" + secret, YYYYMMDD)
# kRegion  = HMAC(kDate, region)
# kService = HMAC(kRegion, service)
# kSigning = HMAC(kService, "aws4_request")
derive_signing_key() {
    local date="$1"
    local k_date k_region k_service
    k_date="$(hmac_sha256_hex "$(printf '%s' "AWS4${AWS_SECRET_ACCESS_KEY}" | hex_of_stdin)" "$date")"
    k_region="$(hmac_sha256_hex "$k_date" "$AWS_REGION")"
    k_service="$(hmac_sha256_hex "$k_region" "s3")"
    hmac_sha256_hex "$k_service" "aws4_request"
}

# ---------------------------------------------------------------------------
# sign_and_curl
#
# Arguments:
#   method
#   canonical_uri
#   canonical_query
#   actual_url
#   payload_hash
#   extra_header_name
#   extra_header_value
#   curl_output_mode:
#       stdout      response body to stdout
#       file:<path> response body to file
#       discard     discard response body
#
# All headers included in the request and all x-amz-* headers are included
# in the canonical header set. We keep this deliberately small.
# ---------------------------------------------------------------------------
sign_and_curl() {
    local method="$1"
    local canonical_uri="$2"
    local canonical_query="$3"
    local actual_url="$4"
    local payload_hash="$5"
    local extra_name="${6:-}"
    local extra_value="${7:-}"
    local output_mode="${8:-stdout}"

    local amz_date date_stamp
    local host canonical_headers signed_headers
    local canonical_request canonical_request_hash
    local credential_scope string_to_sign signing_key signature
    local auth
    local tmp_headers tmp_body http_code curl_rc

    amz_date="$(date -u '+%Y%m%dT%H%M%SZ')" ||
        die "cannot determine UTC time"
    date_stamp="${amz_date:0:8}"

    host="${actual_url#*://}"
    host="${host%%/*}"

    # SigV4 requires every x-amz-* header sent to S3 to also be signed.
    # Canonical headers must furthermore be sorted lexicographically.
    canonical_headers="host:${host}"$'\n'
    signed_headers="host"
    canonical_headers+="x-amz-content-sha256:${payload_hash}"$'\n'
    signed_headers+=";x-amz-content-sha256"

    if [[ -n "$extra_name" ]]; then
        # Header names are lower-case in the canonical representation.
        local lower_name="${extra_name,,}"
        canonical_headers+="${lower_name}:${extra_value}"$'\n'
        signed_headers+=";${lower_name}"
    fi

    canonical_headers+="x-amz-date:${amz_date}"$'\n'
    signed_headers+=";x-amz-date"

    # Temporary session credentials require x-amz-security-token to be signed.
    if [[ -n "${AWS_SESSION_TOKEN:-}" ]]; then
        canonical_headers+="x-amz-security-token:${AWS_SESSION_TOKEN}"$'\n'
        signed_headers+=";x-amz-security-token"
    fi

    canonical_request="${method}"$'\n'
    canonical_request+="${canonical_uri}"$'\n'
    canonical_request+="${canonical_query}"$'\n'
    canonical_request+="${canonical_headers}"$'\n'
    canonical_request+="${signed_headers}"$'\n'
    canonical_request+="${payload_hash}"

    canonical_request_hash="$(sha256_string "$canonical_request")"

    credential_scope="${date_stamp}/${AWS_REGION}/s3/aws4_request"

    string_to_sign="AWS4-HMAC-SHA256"$'\n'
    string_to_sign+="${amz_date}"$'\n'
    string_to_sign+="${credential_scope}"$'\n'
    string_to_sign+="${canonical_request_hash}"

    signing_key="$(derive_signing_key "$date_stamp")"
    signature="$(hmac_sha256_hex "$signing_key" "$string_to_sign")"

    auth="AWS4-HMAC-SHA256 Credential=${AWS_ACCESS_KEY_ID}/${credential_scope}, SignedHeaders=${signed_headers}, Signature=${signature}"

    # Do not log the Authorization value, secret key, or session token.
    debug "request: ${method} ${actual_url}"
    debug "payload SHA256: ${payload_hash}"
    debug "signed headers: ${signed_headers}"
    debug "canonical request SHA256: ${canonical_request_hash}"
    debug "credential scope: ${credential_scope}"
    debug "signature: ${signature}"
    debug "endpoint mode: path-style=${S3_PATH_STYLE}, region=${AWS_REGION}"

    tmp_headers="$(mktemp)" || die "mktemp failed"
    tmp_body="$(mktemp)" || {
        rm -f "$tmp_headers"
        die "mktemp failed"
    }

    local -a curl_args
    curl_args=(
        --silent
        --show-error
        --request "$method"
        --url "$actual_url"
        --header "Host: ${host}"
        --header "x-amz-date: ${amz_date}"
        --header "x-amz-content-sha256: ${payload_hash}"
        --header "Authorization: ${auth}"
        --dump-header "$tmp_headers"
    )

    if [[ -n "${AWS_SESSION_TOKEN:-}" ]]; then
        curl_args+=(--header "x-amz-security-token: ${AWS_SESSION_TOKEN}")
    fi

    if [[ -n "$extra_name" ]]; then
        curl_args+=(--header "${extra_name}: ${extra_value}")
    fi

    case "$output_mode" in
        stdout)
            curl_args+=(--output "$tmp_body")
            ;;
        file:*)
            curl_args+=(--output "${output_mode#file:}")
            ;;
        discard)
            curl_args+=(--output "$tmp_body")
            ;;
        *)
            rm -f "$tmp_headers" "$tmp_body"
            die "invalid output mode: $output_mode"
            ;;
    esac

    # For PUT object, the caller adds --upload-file via S3_UPLOAD_FILE.
    if [[ -n "${S3_UPLOAD_FILE:-}" ]]; then
        curl_args+=(--upload-file "$S3_UPLOAD_FILE")
        debug "upload file: ${S3_UPLOAD_FILE} ($(wc -c < "$S3_UPLOAD_FILE") bytes)"
    elif [[ "$method" == "PUT" ]]; then
        # curl otherwise sends a PUT with no Content-Length at all. S3
        # rejects that for zero-byte directory markers and CopyObject bodies.
        curl_args+=(--header "Content-Length: 0")
        debug "upload body: empty (Content-Length: 0)"
    fi

    # curl -v includes the Authorization and possibly session-token headers.
    # Make it opt-in separately from the safe S3CURL_DEBUG diagnostics.
    if [[ "${S3CURL_CURL_VERBOSE:-0}" == "1" ]]; then
        debug "WARNING: curl verbose output can contain credentials"
        curl_args+=(--verbose)
    fi

    curl "${curl_args[@]}" 2>"${tmp_body}.err"
    curl_rc=$?

    http_code="$(awk 'NR==1 {print $2; exit}' "$tmp_headers" 2>/dev/null || true)"
    debug "response: curl exit=${curl_rc}, HTTP ${http_code:-unknown}"
    if [[ "${S3CURL_DEBUG:-0}" == "1" && -s "$tmp_headers" ]]; then
        debug "response headers:"
        sed 's/\r$//' "$tmp_headers" >&2
    fi

    if [[ $curl_rc -ne 0 ]]; then
        cat "${tmp_body}.err" >&2
        rm -f "$tmp_headers" "$tmp_body" "${tmp_body}.err"
        return "$curl_rc"
    fi

    if [[ ! "$http_code" =~ ^2[0-9][0-9]$ ]]; then
        echo "S3 request failed (HTTP ${http_code:-unknown}):" >&2
        if [[ -s "$tmp_body" ]]; then
            cat "$tmp_body" >&2
            echo >&2
        fi
        rm -f "$tmp_headers" "$tmp_body" "${tmp_body}.err"
        return 1
    fi

    if [[ "$output_mode" == stdout && -s "$tmp_body" ]]; then
        cat "$tmp_body"
    fi

    rm -f "$tmp_headers" "$tmp_body" "${tmp_body}.err"
    return 0
}

# Build bucket/object endpoints. AWS normally uses virtual-hosted style;
# custom S3-compatible endpoints default to path-style.
bucket_url() {
    if [[ "$S3_PATH_STYLE" == 1 ]]; then
        printf '%s/%s' "$S3_ENDPOINT" "$(uri_encode "$S3_BUCKET" 0)"
    else
        printf '%s' "$S3_ENDPOINT"
    fi
}

canonical_object_path() {
    local key="$1"
    if [[ "$S3_PATH_STYLE" == 1 ]]; then
        canonical_key_path "${S3_BUCKET}/${key}"
    else
        canonical_key_path "$key"
    fi
}

canonical_bucket_list_path() {
    if [[ "$S3_PATH_STYLE" == 1 ]]; then
        canonical_key_path "${S3_BUCKET}/"
    else
        printf '/'
    fi
}

object_url() {
    local key="$1"
    printf '%s%s' "$(bucket_url)" "$(canonical_key_path "$key")"
}

# ---------------------------------------------------------------------------
# put
# ---------------------------------------------------------------------------
cmd_put() {
    [[ $# -eq 2 ]] || die "usage: $SCRIPT_NAME put LOCAL_FILE S3_KEY"
    local file="$1"
    local key="$2"

    [[ -f "$file" ]] || die "local file not found: $file"
    [[ -r "$file" ]] || die "local file is not readable: $file"

    local payload_hash
    payload_hash="$(sha256_file "$file")" || die "cannot hash file"

    S3_UPLOAD_FILE="$file"
    export S3_UPLOAD_FILE

    sign_and_curl \
        "PUT" \
        "$(canonical_object_path "$key")" \
        "" \
        "$(object_url "$key")" \
        "$payload_hash" \
        "" \
        "" \
        "discard"
    local rc=$?

    unset S3_UPLOAD_FILE
    return "$rc"
}

# ---------------------------------------------------------------------------
# get
# ---------------------------------------------------------------------------
cmd_get() {
    [[ $# -eq 2 ]] || die "usage: $SCRIPT_NAME get S3_KEY LOCAL_FILE"
    local key="$1"
    local file="$2"

    [[ ! -e "$file" ]] ||
        die "local target already exists: $file (remove it first)"

    local tmp="${file}.s3curl.$$"

    sign_and_curl \
        "GET" \
        "$(canonical_object_path "$key")" \
        "" \
        "$(object_url "$key")" \
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" \
        "" \
        "" \
        "file:$tmp"
    local rc=$?
    if [[ $rc -ne 0 ]]; then
        rm -f -- "$tmp"
        return $rc
    fi

    mv -- "$tmp" "$file" || {
        rm -f -- "$tmp"
        die "cannot move downloaded file into place"
    }
}

# ---------------------------------------------------------------------------
# delete
# ---------------------------------------------------------------------------
cmd_delete() {
    [[ $# -eq 1 ]] || die "usage: $SCRIPT_NAME delete S3_KEY"
    local key="$1"

    sign_and_curl \
        "DELETE" \
        "$(canonical_object_path "$key")" \
        "" \
        "$(object_url "$key")" \
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" \
        "" \
        "" \
        "discard"
}

# ---------------------------------------------------------------------------
# rename = CopyObject + DeleteObject
#
# x-amz-copy-source is URL encoded. It is a signed x-amz-* header, therefore
# it must appear in canonical headers too.
# ---------------------------------------------------------------------------
cmd_rename() {
    [[ $# -eq 2 ]] || die "usage: $SCRIPT_NAME rename OLD_S3_KEY NEW_S3_KEY"
    local old_key="$1"
    local new_key="$2"

    [[ "$old_key" != "$new_key" ]] ||
        die "source and destination are identical"

    local copy_source
    copy_source="/${S3_BUCKET}$(canonical_key_path "$old_key")"

    # CopyObject is a PUT with an empty request body.
    sign_and_curl \
        "PUT" \
        "$(canonical_object_path "$new_key")" \
        "" \
        "$(object_url "$new_key")" \
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" \
        "x-amz-copy-source" \
        "$copy_source" \
        "discard" || return $?

    cmd_delete "$old_key"
}

# ---------------------------------------------------------------------------
# mb - create the configured bucket
# ---------------------------------------------------------------------------
cmd_mb() {
    [[ $# -eq 0 ]] || die "usage: $SCRIPT_NAME mb"
    local payload_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    sign_and_curl \
        "PUT" \
        "$(canonical_key_path "/${S3_BUCKET}")" \
        "" \
        "${S3_ENDPOINT}/$(uri_encode "$S3_BUCKET" 0)" \
        "$payload_hash" \
        "" \
        "" \
        "discard"
}

# ---------------------------------------------------------------------------
# mkdir
# ---------------------------------------------------------------------------
cmd_mkdir() {
    [[ $# -eq 1 ]] || die "usage: $SCRIPT_NAME mkdir S3_PREFIX"
    local prefix="$1"

    [[ "$prefix" == */ ]] || prefix="${prefix}/"

    # A zero-byte object named "prefix/" is a conventional directory marker.
    local payload_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    # Empty PUT body: no S3_UPLOAD_FILE.
    unset S3_UPLOAD_FILE 2>/dev/null || true

    sign_and_curl \
        "PUT" \
        "$(canonical_object_path "$prefix")" \
        "" \
        "$(object_url "$prefix")" \
        "$payload_hash" \
        "" \
        "" \
        "discard"
}

# ---------------------------------------------------------------------------
# ls
#
# Uses ListObjectsV2:
#   list-type=2
#   delimiter=/
#   prefix=<prefix>
#
# This gives a directory-like listing via Contents and CommonPrefixes.
# Pagination is handled automatically.
# ---------------------------------------------------------------------------
cmd_ls() {
    [[ $# -le 1 ]] || die "usage: $SCRIPT_NAME ls [S3_PREFIX]"
    local prefix="${1:-}"

    local token=""
    local xml
    local tmp
    tmp="$(mktemp)" || die "mktemp failed"

    while :; do
        local encoded_prefix=""
        local canonical_query
        local actual_query

        if [[ -n "$prefix" ]]; then
            encoded_prefix="$(uri_encode "$prefix" 0)"
            # Alphabetical order after URI encoding:
            # delimiter, list-type, prefix, continuation-token
            canonical_query="delimiter=%2F&list-type=2&prefix=${encoded_prefix}"
            actual_query="list-type=2&delimiter=%2F&prefix=${encoded_prefix}"
        else
            canonical_query="delimiter=%2F&list-type=2"
            actual_query="list-type=2&delimiter=%2F"
        fi

        if [[ -n "$token" ]]; then
            local encoded_token
            encoded_token="$(uri_encode "$token" 0)"
            # continuation-token sorts before delimiter in the canonical
            # query string, so rebuild it in the required order.
            canonical_query="continuation-token=${encoded_token}&${canonical_query}"
            actual_query+="&continuation-token=${encoded_token}"
        fi

        : >"$tmp"

        sign_and_curl \
            "GET" \
            "$(canonical_bucket_list_path)" \
            "$canonical_query" \
            "$(bucket_url)/?${actual_query}" \
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" \
            "" \
            "" \
            "file:$tmp" || return $?

        # Basic XML extraction using standard POSIX tools. S3 commonly sends
        # the XML as one line, so put one tag on each line first. In
        # particular, do not treat the top-level <Prefix> as a directory.
        # Object keys and CommonPrefixes already contain any trailing slash.
        sed 's/></>\
</g' "$tmp" |
            sed -n 's:^<Key>\(.*\)</Key>$:\1:p' |
            # Do not show the directory marker for the prefix being listed.
            awk -v directory_marker="$prefix" '$0 != directory_marker'

        sed 's/></>\
</g' "$tmp" |
            awk '
                $0 == "<CommonPrefixes>" { in_common_prefix=1; next }
                $0 == "</CommonPrefixes>" { in_common_prefix=0; next }
                in_common_prefix && /^<Prefix>.*<\/Prefix>$/ {
                    sub(/^<Prefix>/, "")
                    sub(/<\/Prefix>$/, "")
                    print
                }
            '

        # ListObjectsV2 pagination.
        if grep -q '<IsTruncated>true</IsTruncated>' "$tmp"; then
            token="$(sed -n 's:.*<NextContinuationToken>\(.*\)</NextContinuationToken>.*:\1:p' "$tmp" | head -n 1)"
            [[ -n "$token" ]] || die "S3 reported truncation but no continuation token was returned"
        else
            break
        fi
    done

    rm -f "$tmp"
}

main() {
    local command="${1:-}"
    shift || true

    case "$command" in
        put)    cmd_put "$@" ;;
        get)    cmd_get "$@" ;;
        delete) cmd_delete "$@" ;;
        rename) cmd_rename "$@" ;;
        mkdir)  cmd_mkdir "$@" ;;
        mb)     cmd_mb "$@" ;;
        ls)     cmd_ls "$@" ;;
        -h|--help|help|"") usage ;;
        *) die "unknown command: $command (use --help)" ;;
    esac
}

main "$@"
