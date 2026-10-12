#!/usr/bin/env bash
#
# check-dns.sh — verify DNS records for a domain across several public resolvers
# and flag propagation drift, missing mail records, and absent SPF/DKIM/DMARC.
#
#   ./check-dns.sh example.com [--dkim selector1] [--json] [--resolver 8.8.8.8,1.1.1.1]
#
# Uses dig when available, falls back to nslookup. Exit code 0 = all good,
# 1 = drift or hard failures found, 2 = usage/config error.
#
set -u

DOMAIN=""
DKIM_SELECTORS=""
JSON_OUT=0
RESOLVERS="8.8.8.8,1.1.1.1,9.9.9.9"

usage() {
	cat <<'EOF'
Usage: check-dns.sh DOMAIN [--dkim selector] [--resolver 8.8.8.8,1.1.1.1] [--json]

Checks A, AAAA, CNAME, MX and TXT records across multiple resolvers, detects
propagation drift, and reports on SPF / DKIM / DMARC presence.

Options:
  --dkim SELECTOR   also query SELECTOR._domainkey.DOMAIN (repeatable)
  --resolver LIST   comma-separated DNS servers to query (default: 8.8.8.8,1.1.1.1,9.9.9.9)
  --json            machine-readable output
EOF
}

while [ $# -gt 0 ]; do
	case "$1" in
		--dkim)
			[ $# -ge 2 ] || { echo "error: --dkim needs a selector" >&2; exit 2; }
			DKIM_SELECTORS="$DKIM_SELECTORS $2"; shift 2 ;;
		--resolver)
			[ $# -ge 2 ] || { echo "error: --resolver needs a list" >&2; exit 2; }
			RESOLVERS="$2"; shift 2 ;;
		--json) JSON_OUT=1; shift ;;
		-h|--help) usage; exit 0 ;;
		-*) echo "error: unknown option $1" >&2; usage >&2; exit 2 ;;
		*)
			if [ -z "$DOMAIN" ]; then DOMAIN="$1"; else echo "error: only one domain" >&2; exit 2; fi
			shift ;;
	esac
done

[ -z "$DOMAIN" ] && { usage >&2; exit 2; }

# ---- query primitives (dig preferred, nslookup fallback) ----
if command -v dig >/dev/null 2>&1; then
	QBIN=dig
elif command -v nslookup >/dev/null 2>&1; then
	QBIN=nslookup
else
	echo "error: neither dig nor nslookup is installed (dnsutils / bind-utils)" >&2
	exit 2
fi

query() { # query <resolver> <type> <name> -> one record per line, sorted, deduped
	local resolver="$1" type="$2" name="$3"
	if [ "$QBIN" = dig ]; then
		dig +short +time=3 +tries=2 @"$resolver" "$name" "$type" 2>/dev/null \
			| tr -d '\r' | sed 's/\.$//' | sort -u
	else
		nslookup -type="$type" "$name" "$resolver" 2>/dev/null \
			| awk -v t="$type" 'tolower($0) ~ "^" tolower(t) " " { sub(/^[^\t ]*[ \t]+/, ""); sub(/\.$/, ""); print }' \
			| sort -u
	fi
}

declare -A RESULTS   # key "resolver|type" -> newline-joined records
ISSUES=0
json_escape() { # minimal JSON string escape
	printf '%s' "$1" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))' 2>/dev/null \
		|| printf '"%s"' "$(printf '%s' "$1" | tr -d '"\')"
}

echo_line() { [ "$JSON_OUT" -eq 0 ] && printf '%s\n' "$*"; }

# ---- gather records ----
IFS=',' read -r -a RESARR <<< "$RESOLVERS"
TYPES=(A AAAA CNAME MX TXT)

for resolver in "${RESARR[@]}"; do
	for t in "${TYPES[@]}"; do
		RESULTS["$resolver|$t"]="$(query "$resolver" "$t" "$DOMAIN")"
	done
done

# ---- drift detection: compare A/AAAA/MX/CNAME sets across resolvers ----
json_records=""
check_drift() {
	local t="$1" first="${RESARR[0]}"
	local ref="${RESULTS[$first|$t]}"
	for r in "${RESARR[@]:1}"; do
		if [ "${RESULTS[$r|$t]}" != "$ref" ]; then
			ISSUES=1
			if [ "$JSON_OUT" -eq 0 ]; then
				echo "DRIFT: $t records differ between $first and $r"
				echo "  $first: ${ref:-<none>}"
				echo "  $r:     ${RESULTS[$r|$t]:-<none>}"
			fi
		fi
	done
}

if [ "$JSON_OUT" -eq 0 ]; then
	echo "== $DOMAIN =="
	for t in "${TYPES[@]}"; do
		echo "--- $t ---"
		for r in "${RESARR[@]}"; do
			v="${RESULTS[$r|$t]}"
			printf '  %-12s %s\n' "$r" "${v:-<no records>}"
		done
	done
fi

check_drift A
check_drift AAAA
check_drift CNAME
check_drift MX

# ---- mail hygiene: SPF / DMARC / DKIM from the first resolver ----
txt="${RESULTS[${RESARR[0]}|TXT]}"
spf_found=0; dmarc_found=0
if printf '%s\n' "$txt" | grep -qi 'v=spf1'; then spf_found=1; fi

dmarc_txt="$(query "${RESARR[0]}" TXT "_dmarc.$DOMAIN")"
if printf '%s\n' "$dmarc_txt" | grep -qi 'v=dmarc1'; then dmarc_found=1; fi

if [ "$JSON_OUT" -eq 0 ]; then
	echo "--- mail hygiene ---"
	[ "$spf_found" -eq 1 ] && echo "  SPF:   present" || { echo "  SPF:   MISSING"; ISSUES=1; }
	[ "$dmarc_found" -eq 1 ] && echo "  DMARC: present" || { echo "  DMARC: MISSING"; ISSUES=1; }
	for sel in $DKIM_SELECTORS; do
		dkim_txt="$(query "${RESARR[0]}" TXT "$sel._domainkey.$DOMAIN")"
		if printf '%s\n' "$dkim_txt" | grep -qi 'v=DKIM1\|k=rsa'; then
			echo "  DKIM($sel): present"
		else
			echo "  DKIM($sel): MISSING"; ISSUES=1
		fi
	done
	[ -z "${RESULTS[${RESARR[0]}|MX]}" ] && { echo "  MX:    MISSING (no mail servers)"; ISSUES=1; } || echo "  MX:    present"
	[ "$ISSUES" -eq 0 ] && echo "OK: no drift, mail records look complete" \
		|| echo "WARNING: issues found (exit 1)"
else
	dkim_json=""; first=1
	for sel in $DKIM_SELECTORS; do
		dkim_txt="$(query "${RESARR[0]}" TXT "$sel._domainkey.$DOMAIN")"
		present=0
		printf '%s\n' "$dkim_txt" | grep -qi 'v=DKIM1\|k=rsa' && present=1
		[ "$first" -eq 0 ] && dkim_json="$dkim_json,"
		dkim_json="$dkim_json{\"selector\":$(json_escape "$sel"),\"present\":$present}"
		first=0
	done
	printf '{"domain":%s,"drift":%s,"spf":%s,"dmarc":%s,"dkim":[%s],"mx_present":%s}\n' \
		"$(json_escape "$DOMAIN")" \
		"$ISSUES" "$spf_found" "$dmarc_found" "$dkim_json" \
		"$( [ -n "${RESULTS[${RESARR[0]}|MX]}" ] && echo 1 || echo 0 )"
fi

exit "$ISSUES"
