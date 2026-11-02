# Policy cookbook
```yaml
rules:
  - {id: allow-read, effect: allow, tools: ["read_file"], where: {path: {prefix: "/data/"}}}
  - {id: deny-secrets, effect: deny, tools: ["*"], where: {path: {prefix: "/data/secrets"}}}
  - {id: approve-writes, effect: require_approval, tools: ["write_*", "delete_*"]}
  - {id: small-payments, effect: allow, tools: ["pay"], where: {amount: {max: 100}}, roles: [finance]}
```
Precedence: deny > require_approval > allow > default deny. Prefer exact tool names over globs (`read_*` also matches `read_secrets`; see corpus `po-09`). Use `toolpin policy diff old.yaml new.yaml probes.json` before shipping a change.
