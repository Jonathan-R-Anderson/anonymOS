# Contributing to Spectre

Thank you for your interest in contributing to Spectre! This document outlines the process for contributing to the project.

## Table of Contents
- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Code Style](#code-style)
- [Pull Request Process](#pull-request-process)
- [Rule Contributions](#rule-contributions)
- [Reporting Issues](#reporting-issues)

---

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). Please read it before contributing.

---

## Getting Started

### Prerequisites
- Python 3.8+
- Git
- Linux (for full functionality)

### Fork & Clone
```bash
# Fork the repo on GitHub, then clone your fork
git clone https://github.com/YOUR_USERNAME/spectre.git
cd spectre

# Add upstream remote
git remote add upstream https://github.com/Aayushbankar/spectre.git
```

---

## Development Setup

### Option 1: Local Development (Recommended)
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install in development mode with all extras
pip install -e ".[dev,yara]"

# Verify installation
spectre doctor
```

### Option 2: Docker Development
```bash
# Build development image
docker build -t spectre-dev .

# Run in container
docker run -it --rm -v $(pwd):/app spectre-dev bash
```

### Pre-commit Hooks (Optional)
```bash
# Install pre-commit
pip install pre-commit

# Install hooks
pre-commit install
```

---

## Making Changes

### Branch Strategy
- `main` — Stable releases only (tagged versions)
- `develop` — Integration branch for features
- Feature branches — `feat/<description>`
- Fix branches — `fix/<description>`
- Rule contributions — `rule/<pack>/<rule-name>`

### Commit Messages
Follow [Conventional Commits](https://www.conventionalcommits.org/):
```
type(scope): description

[optional body]

[optional footer]
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`, `rule`

Examples:
```
feat(rules): add new webshell detection rule
fix(sensor): handle PID recycling edge case
docs(readme): update installation instructions
rule(webshell): add suspicious_strings.yar to pack
```

### Keep Changes Focused
- One logical change per PR
- Small, reviewable commits
- Update tests with code changes
- Update docs with user-facing changes

---

## Testing

### Run All Tests
```bash
# Run full test suite
pytest -v

# Run with coverage
pytest --cov=spectre --cov=cli --cov-report=term-missing

# Run specific test file
pytest tests/unit/test_all.py -v
```

### Test Categories
```bash
# Unit tests only
pytest tests/unit/ -v

# Integration tests (requires root)
sudo pytest tests/integration/ -v

# Rule tests
spectre test rule spectre/rules/packs/webshell/*.yml

# Rule loading
spectre rule list
```

### Manual Testing Checklist
Before submitting a PR, verify:
- [ ] `spectre doctor` passes
- [ ] `spectre --help` works
- [ ] `spectre run --verbose` starts without errors (Ctrl+C to stop)
- [ ] `spectre api` starts and serves dashboard
- [ ] `spectre test rule` passes for modified rules
- [ ] `spectre rule list` shows all packs
- [ ] `ruff check .` passes
- [ ] `mypy spectre cli` passes

---

## Code Style

### Python Style
- **Formatter**: Ruff (configured in `pyproject.toml`)
- **Type Checker**: mypy (configured in `pyproject.toml`)
- **Line Length**: 100 characters
- **Quotes**: Double quotes
- **Imports**: Sorted by Ruff (stdlib → third-party → local)

### Type Annotations
- Use built-in generics: `list[str]`, `dict[str, int]`, `tuple[str, int]`
- Use `from __future__ import annotations` at top of files
- Avoid `typing.List`, `typing.Dict`, `typing.Tuple`
- Use `TYPE_CHECKING` for runtime-imported types

### Docstrings
- Google style docstrings for public APIs
- One-line summary for simple functions
- Args, Returns, Raises sections for complex functions

### Rule Files (Sigma YAML)
- Follow [Sigma specification](https://github.com/SigmaHQ/sigma)
- Include: `title`, `id`, `description`, `status`, `author`, `date`, `logsource`, `detection`, `level`, `tags`
- MITRE tags: `attack.tXXXX` or `attack.tXXXX.XXX`
- Place in appropriate pack directory under `spectre/rules/packs/`

---

## Pull Request Process

### Before Submitting
1. **Rebase** on latest `develop` branch
2. **Run all tests** locally
3. **Run linters**: `ruff check . && ruff format --check .`
4. **Run type check**: `mypy spectre cli`
5. **Update documentation** if needed
6. **Update CHANGELOG.md** (if applicable)

### PR Template
```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Rule contribution
- [ ] Refactoring
- [ ] Test addition

## Testing
- [ ] All existing tests pass
- [ ] New tests added
- [ ] Manual testing performed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests pass locally
```

### Review Process
1. **Automated checks** must pass (CI)
2. **Maintainer review** (at least 1 approval)
3. **Address feedback** (push new commits to same branch)
4. **Squash and merge** (maintainer merges to `develop`)

### After Merge
- Delete feature branch
- Pull latest `develop`
- Celebrate! 🎉

---

## Rule Contributions

### Adding New Rules
1. **Choose the right pack**:
   - `webshell` — Web server compromises, post-exploitation
   - `privilege_escalation` — Sudo, SUID, kernel exploits, persistence
   - `credential_access` — Shadow, SSH keys, browser creds, cloud secrets
   - `lateral_movement` — SSH, RDP, SMB, WMI, pass-the-hash

2. **Create Sigma YAML** in `spectre/rules/packs/<pack>/<rule-name>.yml`:
```yaml
title: Descriptive Rule Title
id: unique-uuid-or-descriptive-id
description: What this rule detects
status: stable|test|experimental
author: Your Name
date: YYYY-MM-DD
logsource:
    category: process_creation|file_event|network_connection
    product: linux
detection:
    selection_criteria:
        Field|modifier: value
    condition: selection_criteria
level: low|medium|high|critical
tags:
    - attack.tXXXX
    - attack.tactic
references:
    - https://attack.mitre.org/techniques/TXXXX/
falsepositives:
    - Legitimate use case
license: MIT
```

3. **Test the rule**:
```bash
spectre test rule spectre/rules/packs/<pack>/<rule-name>.yml
```

4. **Install the pack** to verify:
```bash
spectre rule install <pack>
spectre rule list
```

### Rule Guidelines
- **Be specific** — Avoid overly broad rules that generate false positives
- **Include MITRE tags** — Use `attack.tXXXX` format
- **Document false positives** — Help operators tune
- **Use modifiers** — `|contains`, `|endswith`, `|re` for flexibility
- **Test thoroughly** — Verify with real and simulated attacks

---

## Reporting Issues

### Bug Reports
Use the [Bug Report Template](.github/ISSUE_TEMPLATE/bug_report.yml):
- Clear, descriptive title
- Steps to reproduce
- Expected vs actual behavior
- Environment details (OS, Python version, Spectre version)
- Logs/screenshots if applicable

### Feature Requests
Use the [Feature Request Template](.github/ISSUE_TEMPLATE/feature_request.yml):
- Clear problem statement
- Proposed solution
- Alternatives considered
- Use cases

### Rule Requests
Use the [Rule Request Template](.github/ISSUE_TEMPLATE/rule_request.yml):
- Attack technique or behavior to detect
- MITRE ATT&CK reference
- Example attack chain
- Expected false positives

### Security Issues
**Do not** open public issues for security vulnerabilities. See [SECURITY.md](SECURITY.md) for responsible disclosure.

---

## Getting Help

- **Discussions**: [GitHub Discussions](https://github.com/Aayushbankar/spectre/discussions)
- **Documentation**: [README.md](README.md), [docs/](docs/)
- **Code Questions**: Open a Discussion or PR

---

## Recognition

Contributors are recognized in:
- [CHANGELOG.md](CHANGELOG.md)
- Release notes
- GitHub contributors page

Thank you for contributing to Spectre! 🚀