# CLA helper scripts

## Add a signer

```bash
tools/cla/add-signer.sh <github-username>
```

This appends the username to `.github/cla-signers.txt` if not already present.

### Example

```bash
tools/cla/add-signer.sh octocat
git add .github/cla-signers.txt
git commit -m "cla: add signer octocat"
```

## Notes

- Run from repository root.
- Maintainers can also apply PR label `cla-signed` / `cla-exempt` when appropriate.
