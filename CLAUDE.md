# Instructions for Claude

## Commit authorship

- Before committing any work, ask the user who the author should be. If they
  say nothing different, the author is `abijit2626 <abijit2626@gmail.com>`.
- Commit and push with that author and committer. Set it explicitly, for
  example `git -c user.name=abijit2626 -c user.email=abijit2626@gmail.com commit`.
- Never add `Co-Authored-By`, "Generated with Claude", session links, or any
  other Claude attribution to commit messages or PR descriptions, unless the
  user explicitly says to.
- Never push commits authored by `Claude <noreply@anthropic.com>`.
