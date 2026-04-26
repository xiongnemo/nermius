# AGENTS

This repository uses the following working rules:

1. Set `GOPROXY='https://goproxy.cn,direct'` before running Go commands such as `go test` or `go build`.
2. After updating any command or subcommand, check whether the corresponding documentation in `README.md` also needs to be updated.
3. After updating any command or subcommand, also check the autocompletion implementation for regressions.
   If there is no dedicated completion source file, inspect the Cobra-generated `completion` subcommand wiring and behavior instead.
4. After finishing a single feature or fixing a bug, create a commit for that unit of work.
5. Versioning uses `VERSION` as the epoch file. CI computes the effective base version as `VERSION`'s major/minor plus `VERSION`'s patch plus the number of commits since `VERSION` was last changed. Do not manually bump patch for every commit; to reset patch after changing major/minor, edit `VERSION` to the new epoch version in that change.
