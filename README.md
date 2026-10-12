# DNS Record Checker

Verify a domain's DNS from multiple public resolvers at once and catch propagation drift, missing mail records, and absent SPF / DKIM / DMARC — before a broken MX or missing TXT costs you deliverability.

## What it checks

- **A / AAAA / CNAME / MX / TXT** across `8.8.8.8`, `1.1.1.1`, `9.9.9.9` (configurable)
- **Propagation drift** — flags when resolvers disagree on any record set
- **SPF** (`v=spf1` in TXT), **DMARC** (`_dmarc` TXT), **DKIM** (`--dkim selector` → `selector._domainkey` TXT)

## Usage

```bash
./check-dns.sh example.com
./check-dns.sh example.com --dkim default --dkim selector1
./check-dns.sh example.com --resolver 8.8.8.8,1.0.0.1 --json
```

Exit codes: `0` = all good, `1` = drift or missing records, `2` = usage error. CI-friendly — run it after every DNS change or mail setup.

```json
{"domain":"example.com","drift":0,"spf":1,"dmarc":1,"dkim":[{"selector":"default","present":1}],"mx_present":1}
```

Needs `dig` (dnsutils / bind-utils) or `nslookup`. No dependencies otherwise.
MIT licensed.
