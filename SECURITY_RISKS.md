# Common Security Risks When Using Git

Reference document for `git-safe-publish`. Each risk category maps to one or more detection/prevention features in the toolchain.

---

## 1. Secrets & Credentials Committed to Source

The most prevalent and damaging class of git security incident.

### 1.1 Hardcoded secrets in source files
- **API keys & tokens** — AWS (`AKIA…`), GitHub (`ghp_`, `github_pat_`), GitLab (`glpat-`), OpenAI (`sk-`), Anthropic (`sk-ant-`), Stripe (`sk_live_`, `rk_live_`), Slack (`xox[baprs]-`), Twilio (`SK…`), SendGrid (`SG.`)
- **Cloud credentials** — GCP service account JSON, Azure SAS tokens / connection strings, DigitalOcean tokens
- **Database connection strings** — `postgresql://user:password@host`, `mongodb+srv://…`, `mysql://…`, Redis URLs with passwords
- **Private cryptographic keys** — RSA/EC/Ed25519 PEM blocks (`-----BEGIN … PRIVATE KEY-----`), PKCS#12 (`.p12`, `.pfx`), Java keystores (`.jks`, `.keystore`)
- **OAuth / JWT secrets** — client_secret, JWT signing keys, cookie signing secrets
- **SMTP / messaging credentials** — email server passwords, SNS/SQS keys
- **Generic high-entropy strings** — base64-encoded keys, 32–64-char hex strings assigned to `password`, `secret`, `token`, `api_key`, `private_key`, `client_secret`

### 1.2 Sensitive files accidentally tracked
Files that should be in `.gitignore` but often are not:

| File / Pattern | Risk |
|---|---|
| `.env`, `.env.local`, `.env.production` | All app secrets in one file |
| `*.pem`, `*.key`, `*.p12`, `*.pfx` | Cryptographic private keys |
| `id_rsa`, `id_ed25519`, `*.ppk` | SSH private keys |
| `credentials.json`, `service-account.json` | GCP / Firebase service accounts |
| `~/.aws/credentials` (or local copy) | AWS root/IAM credentials |
| `terraform.tfvars`, `*.tfstate` | Infrastructure secrets and live state |
| `kubeconfig`, `*.kubeconfig` | Kubernetes cluster access |
| `docker-compose.override.yml` | Local overrides with injected secrets |
| `*.sql`, `*.dump`, `*.bak` | Database dumps — may contain PII/data |
| `config/secrets.yml`, `config/master.key` | Rails credentials |
| `*.log` (large/prod logs) | Tokens, PII, internal stack traces |

### 1.3 Secrets buried in git history
A secret deleted in the latest commit **still exists** in every prior commit, branch, tag, reflog entry, and stash. This is the hardest risk to remediate because:
- The entire history must be rewritten (`git filter-repo` / BFG)
- All forks and clones already have the secret
- GitHub/GitLab may cache blobs even after a force-push

### 1.4 Secrets in git metadata
- **Commit messages** — "temp: hardcode API key = sk-abc123 to debug"
- **Branch names** — `fix/prod-password-reset-token-abc123`
- **Tag annotations** — release notes with internal URLs or keys
- **Stash descriptions** — `git stash save "wip: added real db password"`

---

## 2. Identity & Attribution Risks

### 2.1 Wrong author identity
- Committing with a personal email on a work repository (or vice versa), exposing private addresses in public history
- Global `git config user.email` not matching the expected project identity
- No per-repo identity override when working across personal/work/client projects

### 2.2 Commit spoofing / unsigned commits
- `user.name` and `user.email` are free-text — anyone can impersonate any contributor
- Without GPG or SSH commit signing (`git config commit.gpgsign true`), there is no cryptographic proof of authorship
- Platforms like GitHub show a "Verified" badge only for signed commits

### 2.3 PII in commit history
- Real full names and email addresses of contributors permanently embedded in history of public repos
- Internal employee IDs, usernames, or role names leaking organizational structure

---

## 3. Repository Content Risks

### 3.1 Internal infrastructure disclosure
- Hardcoded internal hostnames, IP addresses, and domain names in source or config
- Internal S3 bucket names, RDS endpoints, internal API base URLs
- Absolute local paths (`/home/jsmith/work/…`) revealing directory structure or usernames

### 3.2 Sensitive binary or document files
- Internal PDFs, Word/Excel docs, slide decks with confidential or NDA-protected content
- Build artifacts containing embedded secrets (e.g., Android APKs, Java JARs)
- Compiled binaries that embed credentials at build time

### 3.3 License and IP exposure
- Committing third-party code that is GPL/AGPL (copyleft) into a proprietary closed-source repo
- Committing NDA-protected vendor code or customer data to a public repo
- Copy-pasted snippets from licensed Stack Overflow answers (CC BY-SA)

---

## 4. Push & Remote Configuration Risks

### 4.1 Pushing to the wrong remote or branch
- Pushing a private/internal repo to a public GitHub remote by mistake
- Direct push to `main`/`master` bypassing PR review and CI gates
- `git push --force` on a shared branch — rewrites public history, loses others' work
- Pushing a local experiment branch to a shared remote

### 4.2 Incorrect repository visibility
- A GitHub/GitLab repo set to **public** when it should be private
- Forking a private repo and the fork defaults to public
- GitHub Actions artifacts, Pages deployments, or Packages making internal content public

### 4.3 Insecure remote protocols
- Using unauthenticated `git://` protocol (port 9418) — susceptible to MITM
- HTTP (non-TLS) git remotes
- SSH remotes with unprotected keys (no passphrase on private key)

### 4.4 `.gitignore` gaps
- Missing `.gitignore` causing `git add .` to stage everything including secrets
- Files already tracked before being added to `.gitignore` (tracking is not automatically removed)
- Overly broad negation rules (`!*.key`) accidentally un-ignoring sensitive files

---

## 5. Git History & Rewrite Risks

### 5.1 `git rebase` / `git cherry-pick` resurfacing old secrets
- Rebasing a branch onto an updated base can replay commits that introduced secrets, even if they were patched in a later commit
- Cherry-picking a commit that added a secret without picking the follow-up removal commit

### 5.2 Merge conflicts reintroducing secrets
- During a conflict resolution, an older version of a file (with a secret) is accidentally chosen over the newer sanitized version

### 5.3 Orphaned refs holding sensitive blobs
- Git tags, remote-tracking branches, and `ORIG_HEAD`/`MERGE_HEAD` keeping old commits reachable after a filter/rewrite

---

## 6. CI/CD & Build Pipeline Risks

### 6.1 Secrets in CI configuration files
- Hardcoded secrets in `.github/workflows/*.yml`, `.gitlab-ci.yml`, `Jenkinsfile`, `Dockerfile`
- `ARG` / `ENV` directives in Dockerfiles baking secrets into image layers
- `RUN curl … -H "Authorization: Bearer sk-…"` in Dockerfiles — secret visible in `docker history`

### 6.2 Exposed pipeline artifacts
- Build logs printed to stdout containing env var values (debugging `printenv`)
- Uploaded artifacts (ZIPs, JARs) that include `.env` or config files

### 6.3 GitHub Actions / OIDC misconfigurations
- `pull_request_target` trigger allowing fork PRs to access repo secrets
- Overly permissive `GITHUB_TOKEN` permissions (`write-all`)
- Pinning Actions by tag instead of commit SHA (supply chain)

---

## 7. Dependency & Supply Chain Risks

### 7.1 Lockfile tampering
- `package-lock.json` or `yarn.lock` modified to point to a malicious package version
- Dependency confusion attacks — a private package name published to the public registry

### 7.2 Submodule risks
- Submodule URLs pointing to internal/private repos — leaking their existence when repo is public
- Submodule commit SHAs pointing to now-deleted commits that contained secrets

### 7.3 Malicious `.git/hooks`
- Hooks in a cloned repo executing arbitrary code on `commit`, `push`, or `checkout`
- Supply chain attack via a compromised upstream that ships hooks in a non-standard location

---

## 8. Access Control & Sharing Risks

### 8.1 Overly broad collaborator permissions
- External contributors granted write/admin access instead of read
- Stale deploy keys, personal access tokens, or OAuth apps with broad scopes that are never rotated

### 8.2 Token scope creep
- Using a personal access token with `repo` (full) scope when only `read:packages` is needed
- Long-lived tokens (no expiry) used in automation

### 8.3 Public gists and snippets
- Developers sharing debug snippets via public GitHub Gists that include secrets or internal URLs
- Stack Overflow / Pastebin pastes with real credentials

---

## Risk Severity Matrix

| Risk | Likelihood | Impact | Priority |
|---|---|---|---|
| Hardcoded secrets / API keys in source | Very High | Critical | P0 |
| `.env` or key file tracked in git | High | Critical | P0 |
| Secrets in git history | High | Critical | P0 |
| Wrong author email on commit | High | Medium | P1 |
| Push to wrong remote / public repo | Medium | Critical | P1 |
| Force push to shared branch | Medium | High | P1 |
| Secrets in commit messages | Medium | High | P1 |
| CI config with hardcoded secrets | Medium | High | P1 |
| Unsigned / spoofed commits | Medium | Medium | P2 |
| Insecure remote protocol (git://) | Low | High | P2 |
| Internal hostname/IP disclosure | Medium | Medium | P2 |
| Lockfile tampering | Low | High | P2 |
| Malicious git hooks | Low | Critical | P2 |
| Sensitive binary files committed | Medium | Medium | P2 |
| License / IP violations | Low | High | P3 |

---

## Mapping to `git-safe-publish` Commands

| Risk Category | Relevant Command |
|---|---|
| Secrets in staged/committed files | `git-safe-check`, `git-safe-publish` |
| Secrets in full history | `git-safe-search` |
| Wrong author identity | `git-safe-publish`, `git-safe-push` |
| Wrong remote / branch | `git-safe-push` |
| Missing `.gitignore` coverage | `git-safe-check` |
| Unsigned commits | `git-safe-publish` |
| Force push protection | `git-safe-push` |
| CI config secrets | `git-safe-check`, `git-safe-search` |
