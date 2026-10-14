# Sijil Operator Guide, Milestone 2: the guard and the HTTP tool adapter

How to run sijil-guard and its HTTP tool adapter next to the Sijil ledger, sign officers and approvers in through
Entra ID, adopt a rule pack, answer approvals, and hand an auditor what they need to verify the chain offline.

This guide adds to the [Milestone 1 operator guide](OPERATOR_GUIDE.html) (the ledger on its own: install,
policy, emergency stop, SIEM, HSM). Read that first; this one does not repeat it.

Contents

1. [How M2 sits in the network](#1-how-m2-sits-in-the-network)
2. [Get the images](#2-get-the-images)
3. [Before you start](#3-before-you-start)
4. [Entra ID setup](#4-entra-id-setup)
5. [Configure the ledger for M2](#5-configure-the-ledger-for-m2)
6. [Configure the guard](#6-configure-the-guard)
7. [Register the agent identity](#7-register-the-agent-identity)
8. [Deploy with Docker](#8-deploy-with-docker)
9. [Deploy with Helm (Kubernetes, OpenShift)](#9-deploy-with-helm-kubernetes-openshift)
10. [Point the agent at Sijil](#10-point-the-agent-at-sijil)
11. [Approvals](#11-approvals)
12. [Adopt or change a rule pack](#12-adopt-or-change-a-rule-pack)
13. [Verify, and the auditor kit](#13-verify-and-the-auditor-kit)
14. [Upgrades](#14-upgrades)
15. [Troubleshooting](#15-troubleshooting)
16. [Rehearse the M2 scenario without Entra](#16-rehearse-the-m2-scenario-without-entra)
17. [Configuration reference](#17-configuration-reference)

## 1. How M2 sits in the network

```
 officer (Entra sign-in)                                  supervisor (Entra sign-in, CaseClosure role)
        │ principal token                                         │ approves on /approval/<id>
        ▼                                                         ▼
 ┌─────────────── agent pod / host ───────────────┐      ┌──────────────────┐
 │ agent ──model calls──────────────────────────────────▶│  Sijil ledger    │──▶ model server
 │   │                                            │      │  policy, rule    │
 │   ├─tool calls─▶ sijil-adapter (127.0.0.1:8090)─seal─▶│  pack, records,  │
 │   │                    │                       │      │  approvals       │
 │   └─MCP─▶ sijil-guard serve (127.0.0.1:8091)───seal─▶│                  │
 └────────────────────────│───────────│───────────┘      └──────────────────┘
                          ▼           ▼
                 case system (REST)  MCP server (documents)
```

* The **ledger** (image `sijil`) is the M1 proxy plus the agent endpoints: it seals every record, validates
  principal tokens, holds approvals and budgets. One container, one worker.
* The **HTTP tool adapter** (`sijil-guard http`, image `sijil-guard`) is a reverse proxy in front of the agent's
  REST tools. Each request is matched to an OpenAPI operation, checked against the rule pack, sealed, and
  forwarded only if allowed.
* The **MCP guard** (`sijil-guard serve --server NAME`) does the same for one MCP server.
* The guard is Apache-2.0 and never imports the ledger code; it talks to the ledger only over HTTP.

**The adapter must run next to the agent, on the same host or in the same pod.** The adapter opens the agent
session; the agent then sends that session on its model calls. The ledger binds a session to the address that
opened it (spec §12 item 47), so the agent and the adapter must reach the ledger from the same address, and
directly: no Route, Ingress or NAT in between, which would rewrite the source address.

## 2. Get the images

Each release tag (`v*`) publishes, from `.github/workflows/release.yml`:

| Image | Holds |
| --- | --- |
| `ghcr.io/devinwarp/sijil:<tag>` | the ledger (BSL-1.1, `/app/LICENSE`); the verifier, trace tool and guard rule engine (Apache-2.0, each with its LICENSE); the report |
| `ghcr.io/devinwarp/sijil-guard:<tag>` | the guard and adapter (Apache-2.0) and the starter rule pack, nothing else |

Both are signed with cosign keyless (GitHub OIDC) and carry an SPDX SBOM attestation. The GitHub release holds,
per image, the SBOM (`<image>-<tag>.spdx.json`) and the exact pushed reference (`<image>-<tag>.digest`,
`ghcr.io/...@sha256:...`). Verify and deploy **by digest**, not by tag: a tag can be moved, a digest cannot. The
release signs with cosign v3.0.6: verify with cosign v3. Check before you load them (`TAG` is the release tag; without
`gh`, download the `.digest` files from the release page):

```bash
TAG=v1.2.0
ID="^https://github.com/devinwarp/sijil-foundationflow/\.github/workflows/release\.yml@refs/tags/${TAG//./\\.}\$"
for img in sijil sijil-guard; do
  gh release download "$TAG" -R devinwarp/sijil-foundationflow -p "$img-$TAG.digest" --clobber
  REF=$(cat "$img-$TAG.digest")
  cosign verify "$REF" --certificate-identity-regexp "$ID" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com > /dev/null && echo "$img signed"
  cosign verify-attestation --type spdxjson "$REF" --certificate-identity-regexp "$ID" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com > /dev/null && echo "$img SBOM attested"
done
```

Both checks accept only a signature made by `release.yml` running for that tag, not by another workflow or branch.

Offline sites: `docker pull` both on a connected machine, `docker save` them, carry the tarballs in, `docker load`.

To build from a checkout instead: `docker build -t sijil:<tag> .` and `docker build -f Dockerfile.guard -t
sijil-guard:<tag> .`, then `scripts/smoke_container.sh sijil:<tag>` and `scripts/smoke_guard.sh sijil-guard:<tag>
sijil:<tag>`.

Below, `$SIJIL_IMAGE` and `$GUARD_IMAGE` are the two image references you use (the `REF`s above).

## 3. Before you start

* The M1 ledger prerequisites (a host or cluster, the model server, the model weights, a reverse proxy with SSO
  for the read pages).
* **Three random secrets** of 32+ characters, kept in the entity's secret store:

  | Secret | Ledger reads it as | Guard reads it as | Who else holds it |
  | --- | --- | --- | --- |
  | admin token | `SIJILL_ADMIN_TOKEN` | `SIJILL_ADMIN_TOKEN`, only for `identity init` | operators |
  | agent token | `SIJILL_TOKEN` | `SIJIL_TOKEN` (note: one L) | nobody else |
  | tools token | not used | `SIJIL_TOOLS_TOKEN` | the agent, sent as `X-Sijil-Tools-Token` |

* The agent's **OpenAPI document** for each REST tool system it calls (JSON or YAML, OpenAPI 3.0/3.1). Every
  operation the agent may call needs an `operationId`; rules name tools as `http:<server>:<operationId>`.
* For MCP tools: the URL of each MCP server (streamable HTTP), or its command for stdio.
* An **Entra ID tenant** where you can register two applications and create an app role (section 4).

## 4. Entra ID setup

Sijil validates Entra **v2.0 access tokens** itself (RS256, issuer, tenant, audience, expiry, assurance). It never
sees passwords and never calls Microsoft Graph.

1. **Register the agent API app** (for example `Sijil MoI pilot`). Under *Expose an API* set the Application ID URI
   (for example `api://sijil-moi-pilot`) and add a delegated scope (for example `Case.ReadWrite`). In the manifest
   set `"accessTokenAcceptedVersion": 2` (Sijil refuses v1.0 tokens). This URI is the **audience** of the
   officer's token.
2. **Register the approvals app** (for example `Sijil approvals`), Application ID URI `api://sijil-approvals`, a
   delegated scope `Approvals.Decide`, `accessTokenAcceptedVersion: 2`. Under *App roles* create
   `Sijil.Approver.CaseClosure` (allowed member types: users/groups) and assign it, under *Enterprise
   applications → Users and groups*, to the supervisors who may close cases. Add a redirect URI
   `<SIJILL_PUBLIC_URL>/approval/` (platform *Single-page application*) so a sign-in can land on the approval page.
3. **Assurance.** Sijil grades a token from its `acrs` and `amr` claims (rules in the policy, section 5). For
   `high` (what a case closure needs below) create a Conditional Access *authentication context* (for example
   `c3`) that requires phishing-resistant MFA, and request it at sign-in on the approvals app.
4. **Note** the tenant id (a GUID) and the issuer `https://login.microsoftonline.com/<tenant-id>/v2.0`.
5. **Signing keys (JWKS).** By default the ledger fetches the tenant's keys through discovery
   (`<issuer>/.well-known/openid-configuration`), so it needs HTTPS egress to `login.microsoftonline.com`. A ledger
   with no egress uses a **pinned** key set instead: download `https://login.microsoftonline.com/<tenant-id>/discovery/v2.0/keys`
   on a connected machine, put it next to `policy.yaml` as `jwks.json`, and pin it by its SHA-256 (section 5).
   Microsoft rolls these keys; a pinned set must be refreshed before a rolled key is used, or sign-ins fail with
   `kid`. Either way every key set the ledger uses is written to `SIJILL_JWKS_DIR` (`/data/jwks` in the image),
   named by its hash: keep that directory, auditors need it.

Officers need nothing beyond a normal sign-in to the agent's front end, which must pass their access token for the
agent API app to the agent; the agent forwards it as `X-Sijil-Principal-Token`.

## 5. Configure the ledger for M2

Keep the M1 policy and add three things.

**`policy.yaml`**

```yaml
agents:
  register_policy: closed       # registrations need the admin token (also the default when agents: is absent)
  session_ttl_s: 28800          # agent sessions, 60 to 86400 seconds
principals:
  require: true                 # every agent call must carry an officer's token
  min_assurance: substantial
  issuers:
    - id: entra-moi             # [a-z0-9-]; principals are sealed as human:entra-moi:<hash>
      profile: entra
      issuer: https://login.microsoftonline.com/<tenant-id>/v2.0
      tenant: <tenant-id>
      audience: api://sijil-moi-pilot
      # jwks: {mode: pinned, path: /config/jwks.json, sha256: <sha256 of jwks.json>}   # no egress: pin the keys
      assurance:                # the first rule that matches wins
        - {when: {acrs_any: [c3]}, level: high}
        - {when: {amr_any: [mfa, ngcmfa]}, level: substantial}
        - {level: low}
      display_claim: preferred_username
```

Other `principals` keys: `header` (default `X-Sijil-Principal-Token`), `accept_authorization` (also take
`Authorization: Bearer`; default false). Other issuer keys: `algs` (default `[RS256]`), `subject_claim` (default
`oid` for Entra), `require_delegated` (default true for Entra: app-only tokens are refused), `jwks.refresh_s` and
`jwks.max_stale_s` (fetch mode, defaults 3600 and 86400).

**The rule pack** (`rulepack.yaml`). Start from `rulepacks/starter.yaml` (also at
`/app/rulepacks/starter.yaml` in the guard image), give it your own `rulepack_id`, and add the case rules, the
approval route and the budget:

```yaml
  - id: no-export-after-citizen-upload
    description: No bulk export once the context holds a citizen-uploaded document
    on: tool_call
    match: { tool: ["http:case-api:exportCases"], context_labels_any: ["mcp:document-intake"] }
    action: block
  - id: case-closure-needs-approval
    description: Closing a case is a consequential action and needs a named approver
    on: tool_call
    match: { tool: ["http:case-api:closeCase"] }
    action: confirm
hitl:
  channel: entra
  entra: {issuer_id: entra-moi, audience: "api://sijil-approvals"}
  separation_of_duties: true            # the officer who asked cannot approve
  routes:
    - id: case-closure
      rules: ["case-closure-*"]
      approvers: {role: Sijil.Approver.CaseClosure}   # or {oids: [<object id>, ...]}
      min_assurance: high
      timeout_seconds: 900              # then the call is refused and sealed approval-timeout
  notify: {teams_webhook_env: SIJIL_TEAMS_WEBHOOK}   # optional: the env var holding a Teams incoming webhook
budgets:
  - id: case-agent
    match: {harness: [http-agent]}
    limits: {tool_calls: 40, tool_calls_by: {"http:case-api:addCaseNote": 1}, egress_hosts: 4,
             model_spend_micro: 3000000}
    currency: AED
    on_exceed: block
pricing:
  - {id: local-metered, model: "sha256:*", input_per_mtok_micro: 1000, output_per_mtok_micro: 1000,
     missing_usage_cost_micro: 0}
```

(The first two entries go under `rules:`; `hitl`, `budgets` and `pricing` are top-level.) The ledger hashes the
file's bytes: any edit, comments included, is a new rule pack, sealed as a `rulepack_change`.

**Ledger environment, added to M1's:**

| Variable | Value |
| --- | --- |
| `SIJILL_TOKEN` | the agent token. Unset disables `/api/agent/*` (503) |
| `SIJILL_RULEPACK_PATH` | the rule pack file, e.g. `/rulepack/rulepack.yaml` |
| `SIJILL_PUBLIC_URL` | the ledger's URL as approvers reach it, e.g. `https://sijil.moi.gov.ae`. Approval links and notifications need it |
| `SIJILL_JWKS_DIR` | `/data/jwks` in the image: keep the default |
| the variable named by `hitl.notify.teams_webhook_env` | the Teams incoming webhook URL (optional) |

## 6. Configure the guard

One `guard.yaml` per agent. In the image it is `/config/guard.yaml`; paths in it are relative to its directory.
Keep it, its OpenAPI documents and the agent key in an operator directory **outside the repository checkout**
(the commands below use `OPS=~/sijil-ops`: `$OPS/guard/guard.yaml`, `$OPS/guard/case-api.json`), so a key never
lands in a source tree or an image build context.
The guard refuses unknown keys, so a setting it does not honour is never silently ignored. The case agent's file:

```yaml
version: 1
sijil:
  url: http://sijil:8000                 # the ledger, reached directly (no Route/Ingress)
identity:
  agent_id: spiffe://moi.gov.ae/agent/case-agent
  key_path: /state/agent.key             # outside the repo; 0600 and owned by the guard's UID
  registered_by: human:entra-moi:<hash>  # REQUIRED in containers: the operator who registers the agent (below)
  display_name: Case agent
state_path: /state/session.json          # the session and open tasks, shared by the adapter and MCP guards
rulepack: /rulepack/rulepack.yaml        # the same bytes as the ledger's SIJILL_RULEPACK_PATH
task:
  harness: http-agent
servers:                                 # MCP servers the MCP guard wraps
  - name: document-intake
    transport: http
    url: http://document-intake:9002/mcp
http_tools:
  listen: 127.0.0.1:8090                 # loopback: pod-local. Off loopback needs tls and inbound_auth
  inbound_auth: {mode: bearer_env}       # the agent sends SIJIL_TOOLS_TOKEN as X-Sijil-Tools-Token
  servers:
    - name: case-api                     # the agent calls http://127.0.0.1:8090/case-api/<path>
      upstream: https://case.moi.internal/api/v2
      spec: case-api.json                # OpenAPI, next to guard.yaml
```

`registered_by` must be a principal: `human:<issuer-id>:<sha256>`, `oidc:<issuer>:<subject>`,
`email:<sha256 of the address>` or `local:<sha256>`. Set it explicitly: the default (`local:` of `user@host`) does
not work for a container running as a UID with no passwd entry, as OpenShift does (section 15).

Every key and environment variable is in [section 17](#17-configuration-reference).

## 7. Register the agent identity

Once per agent, by an operator: create the agent's Ed25519 key and seal an `agent_register` record. Under
`register_policy: closed` this needs the admin token. Registration is not address-bound, so it can run from an
operator workstation that reaches the ledger (for Kubernetes, through `kubectl port-forward`).

```bash
OPS=~/sijil-ops && mkdir -p "$OPS/agent-key" && chmod 700 "$OPS/agent-key"
docker run --rm --user "$(id -u):0" --network sijil-net \
  -v "$OPS/guard:/config:ro" -v "$OPS/agent-key:/state" \
  -e SIJIL_TOKEN="$AGENT_TOKEN" -e SIJILL_ADMIN_TOKEN="$ADMIN_TOKEN" -e SIJIL_TOOLS_TOKEN="$TOOLS_TOKEN" \
  "$GUARD_IMAGE" identity init
# registered spiffe://moi.gov.ae/agent/case-agent pubkey=<hex> seq=<n>
```

Every command loads the whole guard.yaml, so the variables it names (here `SIJIL_TOOLS_TOKEN`, for
`inbound_auth: bearer_env`) must be set for `identity init` too.

`$OPS/agent-key/agent.key` is now the agent's identity: store it in the secret store. `identity init` is safe to
repeat (it never overwrites a key), but each run seals another registration. To retire a key (a compromised
agent, say), name the operator who revokes it as a principal, as for `registered_by`:

```bash
curl -s -X POST "$S/api/agent/revoke" -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"agent_id": "spiffe://moi.gov.ae/agent/case-agent", "revoked_by": "human:entra-moi:<hash>", "reason": "key exposed"}'
# {"seq": N, "record_hash": "..."}: an agent_revoke record; the guard's next session answers 401 agent revoked
```

`identity.auth: oidc` instead of a key: the guard presents a workload token (from the variable named by
`identity.oidc_token_env`, default `SIJIL_OIDC_TOKEN`, or GitHub Actions OIDC) and the ledger checks it against
`agents.oidc_issuers`; no `identity init` is needed.

## 8. Deploy with Docker

On one host: the ledger, and the agent with its sidecars sharing the agent container's network namespace
(`--network container:<agent>`), the Docker form of a pod.

```bash
docker network create sijil-net
docker run -d --name sijil --network sijil-net --restart unless-stopped -p 8000:8000 \
  -v /etc/sijil:/config:ro -v /etc/sijil-rulepack:/rulepack:ro -v /srv/models:/models:ro -v sijil-data:/data \
  -e SIJILL_ADMIN_TOKEN="$ADMIN_TOKEN" -e SIJILL_TOKEN="$AGENT_TOKEN" \
  -e SIJILL_RULEPACK_PATH=/rulepack/rulepack.yaml -e SIJILL_PUBLIC_URL=https://sijil.moi.gov.ae \
  -e LMSTUDIO_BASE_URL=http://<model-server>:<port>/v1 -e SIJILL_MODEL=<model> \
  "$SIJIL_IMAGE"

# the agent (your image), on the network
docker run -d --name case-agent --network sijil-net -e SIJIL_TOOLS_TOKEN="$TOOLS_TOKEN" \
  -e OPENAI_BASE_URL=http://sijil:8000/v1 -e SIJIL_ADAPTER_URL=http://127.0.0.1:8090 <agent-image>

# its sidecars: same network namespace, same state directory (the registered key from section 7)
G=(--restart unless-stopped --network container:case-agent --user "$(id -u):0"
   --read-only --cap-drop ALL --security-opt no-new-privileges
   -v "$OPS/guard:/config:ro" -v /etc/sijil-rulepack:/rulepack:ro -v "$OPS/agent-key:/state"
   -e SIJIL_TOKEN="$AGENT_TOKEN" -e SIJIL_TOOLS_TOKEN="$TOOLS_TOKEN")
docker run -d --name case-agent-adapter "${G[@]}" "$GUARD_IMAGE"                       # http (the default)
docker run -d --name case-agent-mcp "${G[@]}" "$GUARD_IMAGE" serve --server document-intake --http 127.0.0.1:8091
```

* The sidecars' UID must own `agent.key` (the guard refuses a key it does not own or that others can read);
  `--user "$(id -u):0"` matches the operator who ran `identity init`.
* If the agent container restarts, restart its sidecars too (they share its network namespace).
* The ledger and the guard must load the **same rule pack bytes**: mount one file into both.

## 9. Deploy with Helm (Kubernetes, OpenShift)

The chart is `deploy/helm/sijil`. It runs the ledger as a one-replica StatefulSet with a PVC, the policy and rule
pack from ConfigMaps, the tokens from a Secret; and it renders the guard's config and, optionally, an agent
Deployment with the adapter and MCP guards as sidecars. Pods set no `runAsUser` (OpenShift assigns one), run
non-root with a read-only root filesystem, drop all capabilities, and mount no service account token.

Resource names start with the chart's full name: the release name if it contains `sijil`, else `<release>-sijil`.
For `helm install sijil` below that is `sijil`: Service `sijil-ledger`, pod `sijil-ledger-0`, ConfigMaps
`sijil-guard` and `sijil-rulepack`.

```bash
kubectl create namespace sijil
kubectl -n sijil create secret generic sijil-tokens \
  --from-literal=admin-token="$ADMIN_TOKEN" --from-literal=agent-token="$AGENT_TOKEN" \
  --from-literal=tools-token="$TOOLS_TOKEN"
helm install sijil deploy/helm/sijil -n sijil -f my-values.yaml
```

`my-values.yaml`:

```yaml
image:                                # required: a tag or, better, the digest from the release's .digest asset
  ledger: {repository: ghcr.io/devinwarp/sijil, digest: "sha256:<from sijil-<tag>.digest>"}
  guard: {repository: ghcr.io/devinwarp/sijil-guard, digest: "sha256:<from sijil-guard-<tag>.digest>"}
secrets: {existingSecret: sijil-tokens}
ledger:
  policy: |
    <policy.yaml from section 5>
  configFiles: {}                     # e.g. jwks.json: '<pinned key set>' -> /config/jwks.json
  publicUrl: https://sijil.moi.gov.ae
  env: {LMSTUDIO_BASE_URL: "http://vllm.models:8000/v1", SIJILL_MODEL: "<model>"}
  models: {existingClaim: model-weights}
rulepack: |
  <rulepack.yaml from section 5>
guard:
  config: |
    <guard.yaml from section 6, with sijil.url: "{{ include "sijil.ledgerUrl" . }}">
  files:
    case-api.json: |
      <the OpenAPI document>
  agentKeySecret: sijil-agent-key
```

Then register the agent (section 7) through a port-forward, and store its key:

```bash
kubectl -n sijil port-forward svc/sijil-ledger 8000:8000 &      # any free local port
OPS=~/sijil-ops && mkdir -p "$OPS/reg" "$OPS/agent-key" && chmod 700 "$OPS/agent-key" && cp "$OPS/guard/case-api.json" "$OPS/reg/"
# guard.yaml with the forwarded URL: host.docker.internal on Docker Desktop; on Linux add --network host
# to the docker run below and use http://127.0.0.1:8000
sed 's|^sijil:.*|sijil: {url: "http://host.docker.internal:8000"}|' "$OPS/guard/guard.yaml" > "$OPS/reg/guard.yaml"
docker run --rm --user "$(id -u):0" -v "$OPS/reg:/config:ro" -v "$OPS/agent-key:/state" \
  -e SIJIL_TOKEN="$AGENT_TOKEN" -e SIJILL_ADMIN_TOKEN="$ADMIN_TOKEN" -e SIJIL_TOOLS_TOKEN="$TOOLS_TOKEN" \
  "$GUARD_IMAGE" identity init
kubectl -n sijil create secret generic sijil-agent-key --from-file=agent.key="$OPS/agent-key/agent.key"
```

(`$OPS/guard/guard.yaml` and `case-api.json` are your local copies of `guard.config` and `guard.files`, with `sijil:`
on one line.) The agent pod starts once the Secret exists.

**The adapter as a sidecar of your agent.** Either set `agent.enabled: true` with your agent's `image` (and
`agent.mcpGuards: [{server: document-intake, port: 8091}]`), or merge `deploy/helm/sijil/examples/agent-sidecar.yaml`
into your agent's own Deployment. An init container copies the key from the Secret into a memory `emptyDir` with
mode 0600 and the pod's UID. Agents must reach the ledger through its Service (`http://<fullname>-ledger:8000`,
`http://sijil-ledger:8000` for `helm install sijil`; from another namespace `http://sijil-ledger.sijil:8000`),
never a Route: the router rewrites the source address and the ledger answers `401 agent session bound to another
address`.

Key Secrets (`agentKeySecret`, `nodeKeySecret`) mount with mode 0440: owned by root, read through the pod's group.
That is GID 0 when `runAsGroup` is unset (the images' convention), and the injected `fsGroup` on OpenShift. If you
set `runAsGroup` to a non-zero GID, set `fsGroup` to it as well, or the init container cannot read the key.

Other values:

* `networkPolicy.enabled` (off by default) admits only pods labelled `sijil.io/agent: "true"` **in the release
  namespace**, plus `networkPolicy.from`. Agents in other namespaces need a `from` entry with a `namespaceSelector`
  (and the `podSelector`); on OpenShift, approvers coming through the Router need
  `{namespaceSelector: {matchLabels: {policy-group.network.openshift.io/ingress: ""}}}`. `values.yaml` has both.
* `guard.probes.enabled` (off by default) adds exec readiness and liveness probes to the adapter sidecar: they call
  `http://127.0.0.1:8090/_sijil/healthz` from inside the container, since the adapter listens on loopback only.
  Turn it on only with a guard release whose adapter serves that path; MCP guard sidecars have no probe.
* Resources: requests and memory limits are set, CPU limits are not. If a namespace ResourceQuota requires CPU
  limits, add `cpu` under `ledger.resources.limits` and `guard.resources.limits` (the latter also covers the
  key-copy init container) and `agent.resources`.
* Tokens are read at pod start. After changing them in the Secret, `kubectl -n sijil rollout restart
  statefulset/sijil-ledger deployment/<agent>`.
* `ledger.nodeKeySecret` (a Secret with `node.key`, instead of a key created on the volume),
`ledger.extraEnv`/`extraVolumes` (HSM settings), `podSecurityContext` (add `fsGroup` on clusters whose volumes are
not group-writable; OpenShift sets it).

`helm lint deploy/helm/sijil -f deploy/helm/sijil/ci/lint-values.yaml` renders every template.

## 10. Point the agent at Sijil

The agent changes two base URLs and sends a few headers. Per conversation:

1. `POST http://127.0.0.1:8090/_sijil/task/start` with `X-Sijil-Tools-Token` and the officer's token in
   `X-Sijil-Principal-Token`, body `{"intent": "...", "session_id": "<conversation id>"}`. Answer:
   `{"task_seq": N, "agent_session": "as_..."}`.
2. Model calls go to the ledger, `POST <ledger>/v1/chat/completions`, with `X-Sijil-Agent-Session`,
   `X-Sijil-Task-Seq: N` and `X-Sijil-Principal-Token`.
3. REST tool calls go to `http://127.0.0.1:8090/<server name>/<path>` instead of the tool's base URL, with
   `X-Sijil-Tools-Token`, `X-Sijil-Task-Seq: N` and `X-Sijil-Tool-Use-Id: <the model's tool call id>`. Optional:
   `X-Sijil-Harness` (`http-agent` default), `X-Sijil-Session-Id`. Credentials for the upstream pass only if named in
   `forward_headers`.
4. MCP calls go to `http://127.0.0.1:8091/mcp` (streamable HTTP) with `X-Sijil-Task-Seq: N` on `initialize`.
5. `POST http://127.0.0.1:8090/_sijil/task/end` with `{"task_seq": N, "outcome": "completed"}`.

A blocked call answers `403 {"error": {"type": "sijil_blocked", "rule_hits": [...], "seq": N}}`. The ledger being
unreachable answers 503: the call does not proceed (fail closed). `deploy/rehearsal/case_agent.py` is a complete
example.

Each tool call must follow the model call that asked for it, with the same name and arguments
(`correlation.require_parent: true`, the default); otherwise it is refused as an orphan.

## 11. Approvals

A call matching a `confirm` rule (or a budget with `on_exceed: confirm`) is held, not refused: the adapter keeps the
request open and the ledger seals an `approval` request record.

1. If `hitl.notify.teams_webhook_env` and `SIJILL_PUBLIC_URL` are set, the channel gets a message with the link
   `<SIJILL_PUBLIC_URL>/approval/<approval_id>`. Otherwise find pending approvals in the records:
   ```bash
   curl -s "$S/api/records?since=0" | python3 -c 'import json,sys
   for r in json.load(sys.stdin)["records"]:
       if r["type"] == "approval": print(r["seq"], json.loads(r["ext"]).get("approval_id"))'
   ```
2. The supervisor opens the link. The page shows the tool, server, rule and argument names (never values). They
   sign in to the approvals app (the token arrives in the URL fragment) or paste their access token, and grant or
   refuse with a reason. Equivalent API call:
   ```bash
   curl -s -X POST "$S/api/approval/$AID/decide" -H 'Content-Type: application/json' \
     -d "{\"decision\": \"grant\", \"token\": \"$SUPERVISOR_TOKEN\", \"reason\": \"Certificate checked.\"}"
   ```
3. The ledger checks the token (audience `hitl.entra.audience`), the route's role or object ids, `min_assurance`,
   separation of duties and the deadline before sealing the decision. A failed check seals nothing and answers
   401/403 with `{"detail": {"approval_error": "<code>"}}` (`audience`: a token for another app, such as the
   officer's; `assurance`, `role`, ...). The held call then proceeds (grant) or is refused (refuse, timeout).

## 12. Adopt or change a rule pack

The ledger and every guard must hold the same bytes; a guard whose pack differs gets `409 rulepack mismatch`,
re-reads its file once, and refuses the call if it still differs.

1. Edit the file the ledger reads (Docker: the mounted file; Helm: `rulepack` in your values, then
   `helm upgrade`, and wait about a minute for the ConfigMap to reach the pods).
2. Tell the ledger: `curl -X POST $S/api/admin/rulepack/reload -H "Authorization: Bearer $ADMIN_TOKEN"`. It seals a
   `rulepack_change` naming the new hash; a malformed pack is refused and the old one stays in force.
3. The guards pick the new file up on their next call (in Docker and Helm they mount the same file).

Between steps 1 and 2 a guard may already hold the new pack while the ledger holds the old: its calls are refused
(fail closed). Change packs in a quiet period. Policy changes are the M1 procedure
(`POST /api/admin/policy/reload`).

## 13. Verify, and the auditor kit

Daily: `curl -s $S/api/verify` (`"ok": true`). It runs the verifier with no M2 inputs, so it checks hashes,
signatures and links, not principal tokens.

**The auditor kit** is everything an auditor needs to verify offline, with no access to the running system:

| Item | Where |
| --- | --- |
| a consistent copy of the records | `docker exec sijil sqlite3 /data/sijill.db ".backup /data/export.db"` (Helm: `kubectl exec <fullname>-ledger-0 -- ...`, `sijil-ledger-0` for `helm install sijil`), then copy `/data/export.db` out |
| the node public key | `/data/node.pub` |
| the JWKS snapshots | `/data/jwks/` (every key set any sealed token was checked against, by hash) |
| the rule pack(s) in force | your `rulepack.yaml`, each version that was adopted |
| the kept principal tokens | `<sha256 of the token>.jwt`, kept by the entity (the ledger seals only the hash) |
| the verifier | `verifier/` from the repo (Apache-2.0), or the ledger image |

```bash
docker run --rm --network none -v "$PWD/kit:/kit:ro" --entrypoint python "$SIJIL_IMAGE" \
  verifier/sijill_verify.py --db /kit/export.db --pubkey /kit/node.pub \
  --token-dir /kit/kept-tokens --jwks-dir /kit/jwks --rulepack /kit/rulepack.yaml --min-principal-assurance substantial
# PASS records=... principals=human:1,... principal_tokens=verified:1,... approvals=granted:1,... budgets=hits:1
docker run --rm --network none -v "$PWD/kit:/kit:ro" --entrypoint python "$SIJIL_IMAGE" \
  verifier/sijill_trace.py --db /kit/export.db --pubkey /kit/node.pub <seq>   # why was record <seq> decided so
```

Without `--token-dir` the tokens are counted as unverified; without `--rulepack` budgets are not recomputed.

## 14. Upgrades

**Upgrade the ledger before the guard.** A guard speaks the ledger's agent endpoints; a newer guard may send what
an older ledger refuses, while a newer ledger keeps serving older guards.

1. Read the release notes for record-format or policy changes; back up the data volume (M1 guide).
2. Ledger: `docker pull`, `docker rm -f sijil`, `docker run` as before (Helm: set `image.ledger` to the new digest or tag, `helm upgrade`).
   Check `/api/verify`.
3. Guards: replace the sidecars (Helm: set `image.guard` to the new digest or tag, `helm upgrade`; the agent pods
   roll). The two images are pinned separately so these are two upgrades.
4. Agent keys and the chain survive both: keys are in the Secret/state directory, records in `/data`.

## 15. Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| Ledger exits `ModuleNotFoundError: No module named 'guard'` | An image built from a Dockerfile before this release. Rebuild: the ledger image copies `guard/` (the Foundry relay uses its rule engine) |
| `sijil-guard: Sijil ledger unreachable: ... Name or service not known` | `sijil.url` is wrong, or the ledger is not on the container's network |
| `identity init` prints `unexpected reply from the Sijil ledger: KeyError('getpwuid(): uid not found: ...')` | The container's UID has no passwd entry and `identity.registered_by` is unset. Set `registered_by` |
| `... the agent key is not owned by you` / `readable by other users` | Run the sidecar as the UID that owns `agent.key` (Docker `--user`), or copy it in with mode 0600 (the chart's init container does) |
| Agent pod init container `cp: cannot open '/agent-key/agent.key': Permission denied` | The key Secret mounts 0440 (read through the group); the pod set a non-zero `runAsGroup` without `fsGroup`. Set `fsGroup` to the same GID |
| Adapter answers `401 X-Sijil-Tools-Token required` | The agent did not send `SIJIL_TOOLS_TOKEN`, or the values differ |
| Agent's model call answers `401 agent session bound to another address` | The agent and the adapter reach the ledger from different addresses: run the adapter as a sidecar, and call the ledger's Service directly (no Route/Ingress/NAT) |
| Tool call `403 ... no parent inference requested this call` | The tool call's name or arguments differ from the model call that asked for it, or the model call lacked `X-Sijil-Agent-Session`/`X-Sijil-Task-Seq`. Send exactly the model's arguments |
| `409 rulepack mismatch` / `Sijil ledger refused the record: rulepack mismatch` | Guard and ledger hold different pack bytes: section 12 |
| `principal_error` `kid` (in the 401 `detail` of an `/api/agent/*` answer, or the `ext` of a sealed block) | The token's signing key is not in the key set: pinned JWKS out of date (Microsoft rolled keys), or no egress to fetch it |
| `principal_error` `issuer`, `tenant`, `audience` | v1.0 token (set `accessTokenAcceptedVersion: 2`), another tenant, or a token for another app |
| `principal_error` `assurance` (403) | The sign-in did not meet `min_assurance` (MFA, or the `c3` authentication context for approvals) |
| Every tool call refused `no parent inference` although the model asked for it | The model server repeats tool call ids (e.g. `call_0`) across conversations: the ledger keys ids globally and keeps the first. Use a server that issues unique ids |
| Approval never notified | `SIJILL_PUBLIC_URL` empty (logged at startup) or the webhook variable unset |
| Off-loopback adapter refuses to start | `http_tools off loopback needs tls.cert, tls.key and inbound_auth`: keep it on loopback in a sidecar |
| Verifier `FAIL seq=N tool_call without parent inference` | A guard ran with `correlation.require_parent: false`; pass `--allow-orphan-tool-calls` if that was intended |

## 16. Rehearse the M2 scenario without Entra

The whole scenario on one Docker host, with stand-ins for the entity's systems: a scripted model, a mock case API,
an MCP document server whose document carries a prompt injection, and a **test Entra issuer** (a local RSA key
whose tokens carry Entra's claims). The ledger, guard, adapter, rules, budgets, approvals and verifier are the
real images. Never put the test issuer in a live ledger's policy.

You need Docker, the two images, and a checkout of the repository (for `deploy/rehearsal/` and the starter pack).

```bash
export SIJIL_IMAGE=<ledger image> GUARD_IMAGE=<guard image> REPO=<path to the checkout>
export ADMIN_TOKEN=rehearsal-admin AGENT_TOKEN=rehearsal-agent TOOLS_TOKEN=rehearsal-tools
PORT=8000                     # the ledger's port on this host: pick a free one
R=$(mktemp -d) && cd "$R" && mkdir config rulepack guard agent-key models kit && chmod 700 agent-key
cp "$REPO"/deploy/rehearsal/*.py .
RUN=(docker run --rm --user "$(id -u):0" -v "$R:/w" -w /w --entrypoint python "$GUARD_IMAGE")
```

**1. Test issuer.** Creates its key and key set, and prints the `principals:` block for the policy:

```bash
"${RUN[@]}" test_issuer.py init issuer > principals.yaml && cp issuer/jwks.json config/jwks.json
```

**2. Model weights stand-in and policy.**

```bash
head -c 1048576 /dev/urandom > models/case-model.gguf
DIGEST=$(openssl dgst -sha256 -r models/case-model.gguf | cut -c1-64)
cat > config/policy.yaml <<EOF
policy_id: moi-case-rehearsal
version_label: "rehearsal.1"
approval_ref: "REHEARSAL"
node: {id: "auh-node-01", region: "AE-AZ"}
rules:
  - {id: residency, type: region_allowlist, allow: ["AE-AZ", "AE-DU"], mode: enforce}
  - {id: approved_models, type: model_allowlist, allow_digests: ["sha256:$DIGEST"], mode: enforce}
  - {id: sensitive_terms, type: keyword_flag, terms: ["emirates id", "passport number"], mode: record}
agents:
  register_policy: closed
EOF
cat principals.yaml >> config/policy.yaml
```

**3. Rule pack**: the starter pack, renamed, plus the section 5 rules, approval route, budget and pricing:

```bash
sed 's/^rulepack_id: sijil-starter$/rulepack_id: moi-case-gate/' "$REPO/rulepacks/starter.yaml" > rulepack/rulepack.yaml
cat >> rulepack/rulepack.yaml <<'EOF'
  - id: no-export-after-citizen-upload
    description: No bulk export once the context holds a citizen-uploaded document
    on: tool_call
    match: { tool: ["http:case-api:exportCases"], context_labels_any: ["mcp:document-intake"] }
    action: block
  - id: case-closure-needs-approval
    description: Closing a case is a consequential action and needs a named approver
    on: tool_call
    match: { tool: ["http:case-api:closeCase"] }
    action: confirm
hitl:
  channel: entra
  entra: {issuer_id: entra-moi, audience: "api://sijil-approvals"}
  separation_of_duties: true
  routes:
    - id: case-closure
      rules: ["case-closure-*"]
      approvers: {role: Sijil.Approver.CaseClosure}
      min_assurance: high
      timeout_seconds: 900
budgets:
  - id: case-agent
    match: {harness: [http-agent]}
    limits: {tool_calls: 40, tool_calls_by: {"http:case-api:addCaseNote": 1}, egress_hosts: 4,
             model_spend_micro: 3000000}
    currency: AED
    on_exceed: block
pricing:
  - {id: local-metered, model: "sha256:*", input_per_mtok_micro: 1000, output_per_mtok_micro: 1000,
     missing_usage_cost_micro: 0}
EOF
```

**4. The ledger and the stand-ins.**

```bash
docker network create sijil-net
docker run -d --name sijil --network sijil-net -p "127.0.0.1:$PORT:8000" \
  -v "$R/config:/config:ro" -v "$R/rulepack:/rulepack:ro" -v "$R/models:/models:ro" -v sijil-rehearsal-data:/data \
  -e SIJILL_ADMIN_TOKEN="$ADMIN_TOKEN" -e SIJILL_TOKEN="$AGENT_TOKEN" -e SIJILL_RULEPACK_PATH=/rulepack/rulepack.yaml \
  -e SIJILL_PUBLIC_URL="http://localhost:$PORT" -e LMSTUDIO_BASE_URL=http://model:9001/v1 -e SIJILL_MODEL=case-model \
  "$SIJIL_IMAGE"
S=(--network sijil-net -v "$R:/w:ro" --entrypoint python "$GUARD_IMAGE" /w/standins.py)
docker run -d --name model "${S[@]}" model 9001
docker run -d --name case-api "${S[@]}" case-api 9000
docker run -d --name document-intake "${S[@]}" docs 9002
sleep 3 && curl -s localhost:$PORT/api/policy | python3 -m json.tool | head -5     # "policy_id": "moi-case-rehearsal"
```

**5. Guard config.**

```bash
"${RUN[@]}" standins.py spec 0 > guard/case-api.json
cat > guard/guard.yaml <<EOF
version: 1
sijil: {url: "http://sijil:8000"}
identity:
  agent_id: spiffe://moi.gov.ae/agent/case-agent
  key_path: /state/agent.key
  registered_by: local:$(printf 'rehearsal-operator' | openssl dgst -sha256 -r | cut -c1-64)
  display_name: Case agent
state_path: /state/session.json
rulepack: /rulepack/rulepack.yaml
task: {harness: http-agent}
servers:
  - {name: document-intake, transport: http, url: "http://document-intake:9002/mcp"}
http_tools:
  listen: 127.0.0.1:8090
  inbound_auth: {mode: bearer_env}
  servers:
    - {name: case-api, upstream: "http://case-api:9000/api/v2", spec: case-api.json}
EOF
```

**6. Register the agent** (section 7):

```bash
docker run --rm --user "$(id -u):0" --network sijil-net -v "$R/guard:/config:ro" -v "$R/agent-key:/state" \
  -e SIJIL_TOKEN="$AGENT_TOKEN" -e SIJILL_ADMIN_TOKEN="$ADMIN_TOKEN" -e SIJIL_TOOLS_TOKEN="$TOOLS_TOKEN" \
  "$GUARD_IMAGE" identity init
```

**7. The agent and its sidecars** (section 8; the agent stand-in is the guard image, idle):

```bash
docker run -d --name case-agent --network sijil-net -v "$R:/w:ro" --entrypoint sleep "$GUARD_IMAGE" infinity
G=(--network container:case-agent --user "$(id -u):0" -v "$R/guard:/config:ro" -v "$R/rulepack:/rulepack:ro"
   -v "$R/agent-key:/state" -e SIJIL_TOKEN="$AGENT_TOKEN" -e SIJIL_TOOLS_TOKEN="$TOOLS_TOKEN")
docker run -d --name case-agent-adapter "${G[@]}" "$GUARD_IMAGE"
docker run -d --name case-agent-mcp "${G[@]}" "$GUARD_IMAGE" serve --server document-intake --http 127.0.0.1:8091
```

**8. Run the scenario.** In terminal A, the agent:

```bash
OFFICER=$("${RUN[@]}" test_issuer.py officer issuer) && printf %s "$OFFICER" > officer.jwt
docker exec -e OFFICER_TOKEN="$OFFICER" -e SIJIL_TOOLS_TOKEN="$TOOLS_TOKEN" case-agent python /w/case_agent.py
```

Expected: the export `403` with `no-export-after-citizen-upload`; the first note `201`, the second `403` with
`budget:case-agent:tool_calls_by:http:case-api:addCaseNote`; then it waits on `closeCase`. In terminal B (same
`R`, `RUN`, `PORT` and `cd`), the supervisor grants it (section 11):

```bash
AID=$(curl -s "localhost:$PORT/api/records?since=0" | python3 -c 'import json,sys
print([json.loads(r["ext"])["approval_id"] for r in json.load(sys.stdin)["records"] if r["type"] == "approval"][0])')
SUP=$("${RUN[@]}" test_issuer.py supervisor issuer)
curl -s -X POST "localhost:$PORT/api/approval/$AID/decide" -H 'Content-Type: application/json' \
  -d "{\"decision\": \"grant\", \"token\": \"$SUP\", \"reason\": \"Certificate checked.\"}"
```

Terminal A then shows `closeCase` `200` and the task end (`tool_calls 5, blocked 2, confirmed 1`).
`docker exec case-api python -c "import httpx; print(httpx.get('http://localhost:9000/_seen').json())"` shows the
case system saw the note and the closure, never the export.

**9. Auditor kit and offline verification** (section 13):

```bash
docker exec sijil sqlite3 /data/sijill.db ".backup /data/export.db"
docker cp sijil:/data/export.db kit/ && docker cp sijil:/data/node.pub kit/ && docker cp sijil:/data/jwks kit/
cp rulepack/rulepack.yaml kit/ && mkdir kit/kept-tokens
cp officer.jwt "kit/kept-tokens/$(openssl dgst -sha256 -r officer.jwt | cut -c1-64).jwt"   # no trailing newline
docker run --rm --network none -v "$R/kit:/kit:ro" --entrypoint python "$SIJIL_IMAGE" verifier/sijill_verify.py \
  --db /kit/export.db --pubkey /kit/node.pub --token-dir /kit/kept-tokens --jwks-dir /kit/jwks \
  --rulepack /kit/rulepack.yaml --min-principal-assurance substantial
```

Expected: `PASS ... principals=human:1,... principal_tokens=verified:1,... approvals=granted:1,refused:0,timeout:0
budgets=hits:1 ...`. Trace the export (its `seq` is in terminal A's 403):
`docker run --rm --network none -v "$R/kit:/kit:ro" --entrypoint python "$SIJIL_IMAGE" verifier/sijill_trace.py
--db /kit/export.db --pubkey /kit/node.pub <seq>`. Tamper with a copy and verify again to watch it name the record:
`cp kit/export.db kit/t.db && sqlite3 kit/t.db "update records set decision='allow' where seq=<seq>"`.

**10. Clean up.**

```bash
docker rm -f case-agent-mcp case-agent-adapter case-agent model case-api document-intake sijil
docker volume rm sijil-rehearsal-data && docker network rm sijil-net && rm -rf "$R"
```

## 17. Configuration reference

### Commands

`python -m guard --config <guard.yaml> <command>`; in the image the entrypoint is
`python -m guard --config /config/guard.yaml` and the default command `http`.

| Command | Does |
| --- | --- |
| `identity init [--repo DIR]` | create the agent key (never overwrites; must be outside the repo) and register it. `--admin-token-env` (default `SIJILL_ADMIN_TOKEN`) names the admin token's variable |
| `session open` | prove the key (or present the OIDC token) and write the state file |
| `task start --intent TEXT [--delegate] [--session-id ID]` | open a task; prints its `task_seq`. `--principal-token-env` (default `SIJIL_PRINCIPAL_TOKEN`) |
| `task end [--outcome completed\|aborted\|blocked\|error]` | close the current task |
| `serve --server NAME [--http HOST:PORT]` | the MCP guard for one server of `servers:`; stdio unless `--http` |
| `tools pin --server NAME` | pin the server's tool definitions in `lockfile` and seal the baseline |
| `http` | the HTTP tool adapter (`http_tools:`) |

Exit codes: 0 ok, 1 refused or invalid (message on stderr), 3 ledger unreachable or an unexpected reply.

### guard.yaml keys

Unknown sections and keys are refused. Paths take `~` and `${VAR}` and are relative to guard.yaml's directory.

| Key | Default | Meaning |
| --- | --- | --- |
| `version` | required | `1` |
| `sijil.url` | required | the ledger's base URL |
| `sijil.token_env` | `SIJIL_TOKEN` | variable holding the agent token (`X-Sijil-Token`); if named, it must be set |
| `sijil.on_unreachable` | `closed` | only `closed` is built: no ledger, no call |
| `identity.agent_id` | required | e.g. `spiffe://moi.gov.ae/agent/case-agent` |
| `identity.auth` | `key` | `key` or `oidc` |
| `identity.key_path` | required for `key` | Ed25519 key, outside `repo`, 0600, owned by the guard's UID |
| `identity.registered_by` | `local:<sha256 of user@host>` | the registering principal; set it in containers |
| `identity.display_name` | none | shown with the registration |
| `identity.oidc_token_env` | `SIJIL_OIDC_TOKEN` | `auth: oidc`: the workload token's variable |
| `state_path` | `$XDG_RUNTIME_DIR/sijil/<hash>-<name>.json`, else `~/.sijil/run/...` | the session and task stack, 0600; shared by every guard process of the agent |
| `repo` | the working directory | the agent's repository root (commands are shown relative to it; keys must be outside it) |
| `rulepack` | none; required by `serve` and `http` | the rule pack file, the ledger's bytes |
| `task.intent` | none | default intent when a task start names none |
| `task.harness` | `other` | `foundry`, `http-agent` or `other` |
| `task.principal_header` | `X-Sijil-Principal-Token` | header carrying the officer's token |
| `egress.pins` | none | YAML file `hosts: [...]` of pinned hosts (`*.` prefix allowed); the adapter's upstreams are always pinned |
| `context_window` | `session` | `session` or `turn`: how far back context labels reach |
| `correlation.require_parent` | `true` | `false` seals tool calls with no model call as orphans (the verifier then needs `--allow-orphan-tool-calls`) |
| `results.max_result_bytes` | `262144` | at least 1024; larger text results are cut, JSON/binary withheld |
| `results.invisible_unicode` | `strip` | `strip`, `block` or `record` |
| `servers[]` | none | MCP servers: `name` (`[a-z0-9_-]{1,32}`), `transport` (`stdio` default, or `http`), `command`/`args`/`env` (stdio), `url`/`headers` (http), `label` (`telemetry`, `web`, `memory`, `repo`; default `mcp:<name>`), `tools: {allow, deny}` (globs), `command_arg` (default `command`). `${VAR}` in `env` and `headers` must be set |
| `allowed_command_dirs` | `/usr/bin`, `/usr/local/bin`, `/opt/homebrew/bin`, `~/.nvm/versions/*/bin`, `node_modules/.bin` | where a stdio server's command may live (besides `repo`) |
| `mcp.allowed_origins` | none | Origins besides loopback the MCP HTTP door accepts |
| `mcp.tools_token_env` | none | variable holding the token the MCP HTTP door requires; required off loopback |
| `mcp.tls_cert`, `mcp.tls_key` | none | required for `serve --http` off loopback |
| `lockfile` | none | pinned MCP tool definitions (`tools pin`) |
| `integrity.recheck_seconds` | `30` | 0 to 86400: re-check the wrapped server's tools when older |
| `http_tools.listen` | `127.0.0.1:8090` | off loopback requires `tls` and `inbound_auth` |
| `http_tools.tls.cert`, `.key` | none | serve HTTPS |
| `http_tools.inbound_auth.mode` | `none` | `bearer_env`, `mtls` or `none` (loopback only) |
| `http_tools.inbound_auth.token_env` | `SIJIL_TOOLS_TOKEN` | `bearer_env`: the variable holding the token; must be set |
| `http_tools.inbound_auth.client_ca` | none | `mtls`: the CA client certificates must chain to |
| `http_tools.servers[].name` | required | `[a-z0-9_-]`; the path prefix and `http:<name>:<operationId>` |
| `http_tools.servers[].upstream` | required | `http(s)://host[:port]/base`, no credentials, query or fragment |
| `http_tools.servers[].spec` | required | the OpenAPI 3.0/3.1 document |
| `http_tools.servers[].label` | `http:<name>` | or `telemetry`, `web`, `memory`, `repo` |
| `http_tools.servers[].forward_headers` | none | request headers passed upstream (values never sealed); not `X-Sijil-*`, hop-by-hop or `proxy-authorization`. `Content-Type` and `Accept` always pass |
| `http_tools.servers[].operations` | all allowed | `{allow, deny}` operationId globs; others are blocked `not-allowlisted` |
| `http_tools.servers[].max_body_bytes` | `1048576` | larger request bodies get 413 |
| `http_tools.servers[].command_arg` | none | an argument that carries a shell command, parsed by the command rules |

### Guard environment

| Variable | Read by | Meaning |
| --- | --- | --- |
| `SIJIL_TOKEN` (or `sijil.token_env`) | all | the agent token, sent to the ledger as `X-Sijil-Token` |
| `SIJIL_TOOLS_TOKEN` (or `inbound_auth.token_env`) | `http` | the token the agent must send as `X-Sijil-Tools-Token` |
| the variable named by `mcp.tools_token_env` | `serve --http` | the MCP door's token |
| `SIJILL_ADMIN_TOKEN` | `identity init` | the ledger's admin token, when `register_policy: closed` |
| `SIJIL_PRINCIPAL_TOKEN` | `task start`, stdio `serve` | the officer's token when no header carries it |
| `SIJIL_OIDC_TOKEN` (or `identity.oidc_token_env`) | `auth: oidc` | the workload token |
| `ACTIONS_ID_TOKEN_REQUEST_URL`, `ACTIONS_ID_TOKEN_REQUEST_TOKEN` | `auth: oidc` | GitHub Actions OIDC, when no token variable is set |
| `XDG_RUNTIME_DIR`, `HOME` | all | default `state_path` (the image sets both to `/state`) |
| `PATH`, `HOME`, `USER`, `LOGNAME`, `SHELL`, `LANG`, `LC_ALL`, `LC_CTYPE`, `TERM`, `TMPDIR`, `TZ` | stdio `serve` | the only variables a wrapped stdio server inherits, plus its `env` |

### Image layout

| | Ledger (`sijil`) | Guard (`sijil-guard`) |
| --- | --- | --- |
| User | 1001; any UID in group 0 works | 1001; any UID in group 0 works |
| Writable | `/data` (records, node key, JWKS snapshots, digest cache, halt flag) | `/state` (agent key copy, session state) |
| Read-only mounts | `/config` (policy, pinned JWKS), `/models`, the rule pack | `/config` (guard.yaml, OpenAPI specs), the rule pack |
| Port | 8000 | 8090 (adapter), the `--http` port of each MCP guard |
| Secrets in the image | none | none |
