# AGENTS

This repository uses the following working rules:

1. Set `GOPROXY='https://goproxy.cn,direct'` before running Go commands such as `go test` or `go build`.
2. After updating any command or subcommand, check whether the corresponding documentation in `README.md` also needs to be updated.
3. After updating any command or subcommand, also check the autocompletion implementation for regressions.
   If there is no dedicated completion source file, inspect the Cobra-generated `completion` subcommand wiring and behavior instead.
