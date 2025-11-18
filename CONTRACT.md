# Server Stats Script Contract

This repository MUST always contain the following artifacts:

## 1. Required Script
- **enhanced-server-stats.sh**
- Must support non-interactive execution
- Must output plain text logs
- Must exit with code 0 on success
- Must not require sudo for standard metrics

## 2. Stability Requirements
- enhanced-server-stats.sh file name MUST NOT change.
- The script MUST remain at the repo root.
- Output format should not break backward compatibility without version bump.

## 3. Testing Requirements
A PR cannot be merged unless:
- GitHub Action validation passes
- Script is syntactically valid (shellcheck)
- Contract validation passes
