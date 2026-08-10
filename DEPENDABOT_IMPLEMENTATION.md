# Dependabot Optimization Implementation for Consul-ECS

## Overview

This document summarizes the Dependabot optimization implementation for consul-ecs, adapted from the Consul Enterprise reference implementation. The goal is to reduce PR volume, automate routine approvals, and eliminate manual overhead for dependency management.

## What Changed: Four Files Created

### 1. `.github/dependabot.yml`

**Purpose:** Central Dependabot configuration controlling when, what, and how dependencies are updated.

**Key Sections:**

#### Go Modules (gomod)
- **Schedule:** Weekly on Sundays (lower velocity than daily Enterprise schedule)
- **Grouping:** 
  - Patch updates grouped into one PR per week
  - Minor updates grouped into one PR per week
  - Major updates ungrouped (individual PRs for review)
- **Labels:** `go`, `dependencies`, `pr/no-changelog`
- **PR Limit:** 10 open PRs max (safety limit)

**Why Weekly Instead of Daily?**
ECS doesn't have the dependency velocity of Enterprise. Weekly cadence reduces noise while staying current with important updates.

#### GitHub Actions (github-actions)
- **Schedule:** Monthly (Actions rarely have meaningful updates)
- **Grouping:**
  - Patch + Minor grouped together (low breaking-change risk)
  - Major updates ungrouped (rare but require review)
- **Labels:** `github_actions`, `dependencies`, `pr/no-changelog`
- **PR Limit:** 5 open PRs max

**Why Monthly?**
GitHub Actions change very slowly. Monthly cadence saves CI resources and reduces PR spam.

**Removed from Enterprise:**
- All `backport/ent/*` labels — ECS doesn't backport to previous versions
- Daily schedule for gomod — Too noisy for ECS velocity

---

### 2. `.github/workflows/dependabot-label-and-auto-approve.yml`

**Purpose:** Automatically label Dependabot PRs by semver type and selectively auto-approve/merge based on risk.

**Workflow Logic:**

1. **Trigger:** `pull_request_target` (fires when Dependabot opens a PR)
2. **Guard:** Only runs for `dependabot[bot]` actor
3. **Metadata Fetch:** Uses `dependabot/fetch-metadata@v3.1.0` to determine update type

**Behavior by Update Type:**

| Update Type | Labels Applied        | Approval | Auto-Merge | Human Review |
|-------------|----------------------|----------|-----------|--------------|
| PATCH       | patch, pr/no-changelog| ✓ Yes    | ✓ Yes     | No           |
| MINOR       | minor, pr/no-changelog| ✓ Yes    | ✗ No      | Yes          |
| MAJOR       | major                 | ✗ No     | ✗ No      | Yes          |

**Why This Strategy?**
- Patch updates are bug fixes with no API changes (very low risk) → safe to auto-merge
- Minor updates add new APIs that could affect Consul integration → approve but require human merge
- Major updates indicate breaking changes → no automation, full review required
- Auto-merge is scoped to patch ONLY to prevent supply-chain attacks from minor/major updates

**Removed from Enterprise:**
- Backport labels in label steps — ECS has no backport strategy
- Multiple label combinations — Kept simple for consistency

---

### 3. `.github/workflows/dependabot-major-changelog.yml`

**Purpose:** Automatically create changelog entries for major version dependency bumps.

**Workflow Logic:**

1. **Trigger:** `pull_request` (opened, reopened, or synchronized by Dependabot)
2. **Guard:** Only runs for major version updates
3. **Method:** GitHub Contents API (no checkout, never executes PR code)
4. **File Creation:** Creates `_<PR_NUMBER>.txt` in `.changelog/` directory

**Safety Features:**
- Uses `printf '%s'` (not format strings) to prevent injection from dependency names/versions
- Checks for existing file SHA to make PUT idempotent (safe to retry)
- Base64 encodes content before API submission
- Never checks out or executes untrusted code

**File Format:**
```
```release-note:improvement
chore: Update of <dependency-names> from <previous-version> to <new-version>
```
```

**Why This?**
Major dependency bumps often have breaking changes. Auto-generating a changelog entry ensures:
- Reviewers don't forget to document the change
- Changelog entry is present on the PR branch
- Release notes are consistent and complete

---

### 4. `.changelog/README.md`

**Purpose:** Documentation for changelog fragments used in major dependency updates.

**Contents:**
- File naming convention: `_<PR_NUMBER>.txt`
- File format with categories (improvement, bug, breaking-change)
- Example entry
- CI/CD integration notes

---

## Key Differences: Enterprise vs ECS

### Schedule Tuning

| Setting              | Consul Enterprise | Consul-ECS | Reason                                |
|---------------------|-------------------|-----------|---------------------------------------|
| gomod interval      | daily             | weekly    | ECS lower velocity; reduce noise      |
| gomod day           | –                 | sunday    | Consistent off-hours schedule         |
| github-actions interval | daily          | monthly   | Actions rarely change; save CI        |
| github-actions limit | 2                 | 5         | Higher for monthly cadence            |

### Label Strategy

**Removed Entirely:**
```
backport/ent/2.0
backport/ent/1.22
backport/ent/1.21
```

**Why?** ECS doesn't maintain multiple release branches. All work flows to `main`. Backport labels add no value.

**Kept:**
```
patch, minor, major              # Semver type labels
pr/no-changelog                  # Metadata for CI/changelog automation
dependencies, go, github_actions # Metadata for filtering/discovery
```

### Auto-Approval Logic

**Identical:** Both use the same strategy:
- Patch: auto-approve + auto-merge (squash)
- Minor: auto-approve, no auto-merge
- Major: no action (human review only)

**Rationale remains the same:** Minimize human overhead while maintaining safety gates for breaking changes.

### Changelog Generation

**Identical:** Both use the same file format and API-driven approach.

**Filename Convention:** Both use `_<PR_NUMBER>.txt` (Enterprise internal convention adopted for ECS consistency).

---

## Expected Outcomes

### PR Volume Reduction
- **Before:** Individual PRs for each dependency (e.g., 10 Go updates = 10 PRs)
- **After:** Grouped PRs (patch group + minor group = 2 PRs per week)
- **Savings:** ~80-90% fewer PRs

### Testing Cycles
- **Before:** Each PR triggers full CI suite independently
- **After:** Combined PRs reduce total CI runs significantly
- **Example:** 10 patch PRs = 10 test runs → 1 combined PR = 1 test run

### Merge Speed
- **Before:** All dependency PRs require manual review and merge
- **After:** Patch PRs auto-merge immediately after CI passes (~1 hour)
- **Minor/Major:** Still require human review but are clearly labeled for triage

### Maintenance Effort
- **Before:** Daily vigilance for dependency updates
- **After:** Weekly or monthly scheduled reviews
- **Automation:** Changelog entries generated automatically for major updates

---

## Setup Checklist

- [ ] Verify `.github/dependabot.yml` exists and is valid YAML
- [ ] Verify `.github/workflows/dependabot-label-and-auto-approve.yml` exists
- [ ] Verify `.github/workflows/dependabot-major-changelog.yml` exists
- [ ] Verify `.changelog/README.md` exists
- [ ] Enable Dependabot alerts (Settings → Code security and analysis)
- [ ] Enable Dependabot version updates (Settings → Code security and analysis)
- [ ] Create required labels in Settings → Labels:
  - `patch`
  - `minor`
  - `major`
  - `pr/no-changelog`
  - `dependencies`
  - `go`
  - `github_actions`
- [ ] Verify workflows appear in Actions tab without errors
- [ ] Monitor first scheduled run (week 1, Sunday)
- [ ] Verify labels applied correctly
- [ ] Verify patch PRs auto-merge after CI passes
- [ ] Verify minor PRs are approved but await manual merge
- [ ] Verify major PRs show no automation

---

## Troubleshooting

### Workflows Not Triggering
- **Check:** GitHub Actions enabled (Settings → Actions)
- **Check:** Workflow files have correct syntax (Actions tab shows errors)
- **Check:** `on:` triggers are correct (`pull_request_target` for approval, `pull_request` for changelog)

### Labels Not Applied
- **Check:** Labels exist in Settings → Labels (workflow can only apply existing labels)
- **Check:** Label names match exactly in workflow (case-sensitive)

### Auto-Merge Not Activating
- **Check:** Auto-merge enabled in repo settings (Settings → General → Allow auto-merge)
- **Check:** CI checks are passing on the PR
- **Check:** Update type correctly detected as PATCH (minor/major won't auto-merge by design)

### No Dependabot PRs After 2 Weeks
- **Check:** Dependabot version updates enabled (Settings → Code security)
- **Check:** No YAML syntax errors in `.github/dependabot.yml`
- **Check:** Dependencies are not already up-to-date
- **Check:** Schedule is correct (gomod: weekly/Sunday, actions: monthly)

---

## File References

```
.github/
  dependabot.yml
  workflows/
    dependabot-label-and-auto-approve.yml
    dependabot-major-changelog.yml
.changelog/
  README.md
```

---

## References

- **Source:** Adapted from Consul Enterprise PR #12934
- **Key Differences:** Removed backport labels, adjusted schedules for ECS velocity
- **Downstream Impact:** Simplifies release process, reduces backport PRs (none for ECS)

---

## Timeline

- **Week 1:** First weekly go module check runs (Sundays)
- **Day 1 of PR:** Auto-approval and labeling workflow executes
- **Patch PRs:** Auto-merge within 1 hour of CI passing
- **Minor PRs:** Approved, awaiting human merge (can take days to weeks)
- **Major PRs:** Awaiting human review (can take days to weeks)
- **Month 1:** First monthly GitHub Actions check runs

---

## Questions?

Refer to the detailed analysis documents for:
- Line-by-line comparison with Consul Enterprise
- Comprehensive setup guide with screenshots
- Security & safety considerations
