# codecref

A frozen copy of the library at commit `7be1643`, used only by `codec_diff_test.go` in the repository root. The
differential tests decode the codec golden inputs and fuzz input with both copies and require the same results, so
restructuring the codec cannot change its behavior unnoticed.

- The files are the root package's non-test `.go` files at `7be1643` without their `//go:generate` lines (the
  generators run from the repository root). Check with:
  `for f in internal/codecref/*.go; do git show 7be1643:${f##*/} | grep -v '^//go:generate ' | cmp - "$f"; done`
- Do not edit or lint these files; they are excluded from golangci-lint.
- Delete this directory together with `codec_diff_test.go` and its CI fuzz step once the codec restructuring is
  complete.
