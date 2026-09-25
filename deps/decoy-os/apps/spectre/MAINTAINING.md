# Maintaining Spectre

This document describes the maintenance processes for the Spectre project.

## Table of Contents
- [Release Process](#release-process)
- [Branch Management](#branch-management)
- [CI/CD Management](#cicd-management)
- [Dependency Management](#dependency-management)
- [Security Updates](#security-updates)
- [Documentation Maintenance](#documentation-maintenance)
- [Community Management](#community-management)
- [Emergency Procedures](#emergency-procedures)

---

## Release Process

### Versioning
Follow [Semantic Versioning](https://semver.org/):
- **MAJOR** — Incompatible API changes
- **MINOR** — New functionality (backward compatible)
- **PATCH** — Bug fixes (backward compatible)

Current: **v10.x** (V10 = Active Containment, Phase 1 = Detection Engineering)

### Release Checklist

#### Pre-Release
- [ ] All CI checks pass on `develop`
- [ ] All tests pass locally
- [ ] Version bumped in `pyproject.toml`
- [ ] `CHANGELOG.md` updated
- [ ] `docs/progress.md` updated
- [ ] Release notes drafted

#### Release (Automated via Workflow)
```bash
# Create and push tag (triggers release workflow)
git tag -a v10.x.y -m "Release v10.x.y: Description"
git push origin v10.x.y
```

The release workflow (`.github/workflows/release.yml`) will:
1. Create GitHub Release with changelog
2. Build and upload artifacts to GitHub Release
3. Publish to PyPI (trusted publisher)
4. Build and push Docker image to GHCR

#### Post-Release
- [ ] Verify PyPI package: `pip install spectre-hids[yara]`
- [ ] Verify Docker image: `docker pull ghcr.io/aayushbankar/spectre:latest`
- [ ] Update `develop` branch with release changes
- [ ] Announce on social media

### Release Types

| Type | Trigger | Example |
| :--- | :--- | :--- |
| **Major** | Breaking changes, architecture rewrite | v11.0.0 |
| **Minor** | New features, new rule packs | v10.1.0 |
| **Patch** | Bug fixes, small improvements | v10.0.5 |
| **Hotfix** | Critical security/bug fix | v10.0.4.1 |

---

## Branch Management

### Branch Structure
```
main ──────────────────●────●────●──── (tagged releases only)
    \                   \
     \                   \
develop ────────────────●────●──── (integration branch)
    \                   \    \
     \                   \    \
feat/xxx ───────────────●────● (feature branches)
fix/xxx ────────────────● (fix branches)
rule/xxx ───────────────● (rule contributions)
```

### Branch Policies

| Branch | Protection | Merges From | Deploys |
| :--- | :--- | :--- | :--- |
| `main` | Required reviews, CI passing | `develop` only (via release) | Production |
| `develop` | CI passing | Feature/fix/rule branches | Staging (manual) |
| `feat/*` | CI passing | — | — |
| `fix/*` | CI passing | — | — |
| `rule/*` | CI passing | — | — |

### Branch Cleanup
```bash
# After merge, delete remote branch
git push origin --delete feat/branch-name

# Clean local branches
git branch -d feat/branch-name
git remote prune origin
```

---

## CI/CD Management

### Workflow Overview

| Workflow | File | Trigger | Purpose |
| :--- | :--- | :--- | :--- |
| **CI** | `ci.yml` | Manual (`workflow_dispatch`) | Lint, typecheck, tests, build, Docker |
| **Release** | `release.yml` | Tag push (`v*`) | Release, PyPI, Docker, GitHub Release |
| **Rule Test** | `rule-test.yml` | Manual (`workflow_dispatch`) | Rule validation, Sigma conversion |

### Current State: Manual Only
All workflows are **disabled from automatic triggers** and run only on:
- `workflow_dispatch` (manual trigger via GitHub UI/API)
- Tag push (release workflow only)

This is intentional during active development to avoid noise and resource waste.

### Enabling Automatic Triggers (When Ready)
Edit `.github/workflows/ci.yml`:
```yaml
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]
  workflow_dispatch:  # Keep manual option
```

### Manual Workflow Triggers
```bash
# Via GitHub CLI
gh workflow run ci.yml --ref develop

# Via GitHub UI
# Actions → CI → Run workflow → Select branch → Run workflow
```

### Workflow Maintenance
- **Keep workflows fast** — Parallelize jobs, cache dependencies
- **Pin action versions** — Use specific versions (e.g., `actions/checkout@v4`)
- **Minimize secrets** — Use OIDC for PyPI, GITHUB_TOKEN for GHCR
- **Cache aggressively** — pip, Docker layers, build artifacts
- **Fail fast** — `fail-fast: true` on matrix jobs

---

## Dependency Management

### Policy
- **Pin major versions** in `pyproject.toml` (e.g., `psutil>=5.9.0,<6.0.0`)
- **Update minor/patch** regularly for security
- **Test thoroughly** before updating major versions
- **Document breaking changes** in CHANGELOG

### Update Process
```bash
# Check for updates
pip list --outdated

# Update minor/patch (test first!)
pip install -U "package>=min,<next_major"

# Update pyproject.toml
# Test: pip install -e ".[dev,yara]" && pytest && mypy spectre cli

# Commit
git commit -am "deps: update package to x.y.z"
```

### Security Updates
- **Monitor**: GitHub Dependabot alerts, PyPI security advisories
- **Prioritize**: CVSS ≥ 7.0 within 48 hours
- **Process**: Update → Test → Patch release

### Dependency Sources
| Category | Packages |
| :--- | :--- |
| Core | psutil, networkx, fastapi, uvicorn |
| CLI | click, rich, pyyaml |
| Dev | pytest, ruff, mypy, pre-commit |
| Optional | yara-python |

---

## Security Updates

### Vulnerability Response

| Severity | SLA | Action |
| :--- | :--- | :--- |
| Critical (CVSS ≥ 9.0) | 24 hours | Emergency patch release |
| High (CVSS ≥ 7.0) | 48 hours | Patch release |
| Medium (CVSS ≥ 4.0) | 2 weeks | Next minor release |
| Low (CVSS < 4.0) | Next release | Next minor release |

### Process
1. **Assess** — Verify vulnerability affects Spectre
2. **Patch** — Update dependency or code
3. **Test** — Full test suite + manual verification
4. **Release** — Patch version (e.g., v10.0.5)
5. **Communicate** — Release notes, security advisory if needed

### Reporting
- **Security issues**: See [SECURITY.md](SECURITY.md)
- **No public issues** for vulnerabilities
- **Coordinated disclosure** with reporter

---

## Documentation Maintenance

### Documentation Map
| File | Audience | Update Frequency |
| :--- | :--- | :--- |
| `README.md` | Users, newcomers | Every release |
| `docs/progress.md` | Developers, contributors | Every release |
| `PROJECT_SUMMARY.md` | Agents, reviewers | Major milestones |
| `CHANGELOG.md` | Users, contributors | Every release |
| `CONTRIBUTING.md` | Contributors | As needed |
| `MAINTAINING.md` | Maintainers | As needed |
| `SECURITY.md` | Security researchers | As needed |
| `docs/*.md` (v*_report.md) | Historical | Never (archival) |

### Style Guidelines
- **Markdown** with GitHub Flavored Markdown
- **Tables** for structured data
- **Code blocks** with language tags
- **Relative links** for internal references
- **Badges** in README only

### Update Process
1. Edit markdown files
2. Validate links: `markdown-link-check` (optional)
3. Preview locally: `mkdocs serve` (if configured)
4. Commit with `docs:` prefix

---

## Community Management

### Channels
| Channel | Purpose | Moderation |
| :--- | :--- | :--- |
| GitHub Issues | Bugs, features, rules | Maintainers |
| GitHub Discussions | Questions, ideas, show-and-tell | Maintainers |
| Pull Requests | Code review | Maintainers |
| Security | Vulnerability reports | Maintainers (private) |

### Response SLAs
| Channel | Initial Response | Resolution |
| :--- | :--- | :--- |
| Security | 24 hours | Per severity SLA |
| Bug Reports | 72 hours | Next release |
| Feature Requests | 1 week | Roadmap planning |
| PR Reviews | 48 hours | Before merge |

### Moderation
- **Be welcoming** — Follow Code of Conduct
- **Stay technical** — Focus on code, not people
- **Close stale** — Auto-close after 30 days inactivity (optional)
- **Label consistently** — Use GitHub labels

---

## Emergency Procedures

### Critical Bug in Production
1. **Assess** — Confirm impact and scope
2. **Hotfix branch** — `fix/critical-description` from `main`
3. **Patch** — Minimal fix, no refactoring
4. **Test** — Critical path only
5. **Release** — Hotfix version (e.g., v10.0.4.1)
6. **Deploy** — Update Docker, PyPI
7. **Communicate** — Release notes, affected users

### CI/CD Failure
1. **Check** — Workflow logs, recent changes
2. **Revert** — If caused by recent merge, revert
3. **Fix** — Address root cause
3. **Re-run** — Manual workflow dispatch

### Security Incident
1. **Contain** — Assess scope, revoke compromised tokens
2. **Investigate** — Logs, access patterns
3. **Remediate** — Rotate secrets, patch vulnerabilities
4. **Report** — Legal/compliance if required
5. **Postmortem** — Document, improve processes

---

## Useful Commands

### Quick Reference
```bash
# Full local CI
ruff check . && ruff format --check . && mypy spectre cli && pytest -v

# Release
git tag -a v10.x.y -m "Release v10.x.y: Description"
git push origin v10.x.y

# Manual CI
gh workflow run ci.yml --ref develop

# Cleanup
git branch -d $(git branch --merged | grep -v '\*\|main\|develop')
git remote prune origin

# Dependency check
pip list --outdated

# Security audit
pip audit
```

---

## Key Contacts

| Role | GitHub | Contact |
| :--- | :--- | :--- |
| Project Lead | @Aayushbankar | GitHub |
| Maintainers | — | GitHub |

---

## Related Files
- [CONTRIBUTING.md](CONTRIBUTING.md) — For contributors
- [SECURITY.md](SECURITY.md) — Security policy
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — Community standards
- [CHANGELOG.md](CHANGELOG.md) — Release history
- `.github/workflows/` — CI/CD pipelines