# Check a source-only GitHub push

Run the read-only guard before **each** public push. It never pushes, fetches,
changes files, installs hooks, or reads workspace secrets. Do not use `--all`,
`--mirror`, force-push, or a private `backup/*` / local-history branch.

For an existing public destination, fetch that branch first, then select the
local source branch and remote destination explicitly:

```sh
git fetch origin main
npm run check:public-push -- --remote origin --branch release/source-only --target main
# Only after PASS, with no intervening commits or remote changes:
git -c push.followTags=false push origin refs/heads/release/source-only:refs/heads/main
```

This example names a branch; substitute the actual source-only release branch.
The check uses `refs/remotes/origin/main` as its baseline, not the index or
the latest commit alone. Fetch immediately before checking: stale tracking refs
cannot prove what the remote currently holds. A normal non-force push will still
reject incompatible remote changes. Explicit refspecs and disabling followTags
avoid uploading other branches or annotated tags through Git configuration.

For a genuinely new remote branch with no remote-tracking destination:

```sh
git fetch origin
npm run check:public-push -- --remote origin --branch release/source-only --target release/source-only --new-branch
```

New-branch checks inspect **all reachable history**, not just a recent clean
commit. If an old local commit added a database and a newer one removed it, that
push still fails. Build a source-only release branch from the fetched upstream
commit instead of uploading private local history. Keep original branches and
local databases intact; this guard does not authorize history rewriting.

## Results and limits

- Exit 0: passed; exit 1: sensitive or unverifiable files; exit 2: invalid input
  or an incomplete check. Both nonzero statuses block the proposed push.
- Findings contain JSON-escaped paths and categories only, never matching lines
  or secret values. Git error output is suppressed.
- Every outgoing commit tree and the source tip are checked, including merge
  commits and ignored-but-tracked files. Database extensions, SQLite magic,
  environment/private-key files, key headers, recognizable provider credentials,
  and high-confidence quoted credential assignments are checked.
- `.env.example`, `.env.sample`, and `.env.template` are allowed **by name only**;
  their contents are still scanned. Only narrowly defined dummy values are
  exempt; test folders are never broadly exempt.
- Blobs over 64 MiB, submodules, and Git LFS pointers fail closed because their
  complete content cannot be checked here. This is a heuristic guard, not a
  guarantee that all possible credential formats or external data are safe.
- Shallow repositories are rejected because older commits may be missing;
  Git replacement objects are disabled so they cannot hide original content.
- The guard is opt-in. A direct `git push` does not automatically run it.
  It checks one named branch destination, not tags or arbitrary refspecs.

Run isolated regression fixtures with `npm run test:public-push`. They create
temporary local repositories only, with synthetic values and no network access.
