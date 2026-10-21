# SafeUpload driver

Kernel minifilter and harnesses for staged protection of writes (local fixed NTFS). The agent that talks to it lives in `../agente/`.

## Start here

1. [`POST-MVP-PLAN.md`](POST-MVP-PLAN.md) — current scope, owner decisions, stops and qualification status.
2. [`M2-COMPLETION-PLAN.md`](M2-COMPLETION-PLAN.md) — the 2026-10-13 review and proposed execution order (recommendations, not approvals).
3. [`MVP-PLAN.md`](MVP-PLAN.md) — historical component baseline.
4. [`docs/README.md`](docs/README.md) — index of the designs, reviews, operations notes and history, with the former locations of moved files.
5. [`../AGENTS.md`](../AGENTS.md) — contributor rules: product invariants, verification, lab boundaries.

## Layout

| Path | What it is |
|---|---|
| `SafeUpload.Minifilter/` | The kernel minifilter (writer tracking, staging, admission, native operations) and its host-side tests in `tests/`. |
| `SafeUpload.Inspector/` | v1 user-mode client of the minifilter's communication port. |
| `SafeUpload.WriterFixture/`, `SafeUpload.SectionFault/`, `SafeUpload.ArchitectureProbe/` | Qualification-only fixtures: a single-file writer, a fault-injection filter for section creation, and a bounded same-stack isolation experiment. None is part of the product. |
| `SafeUpload.Driver.sln` | Solution for the projects above. |
| `scripts/` | Builds, Windows harnesses, verdict checks and lab runners; see [`scripts/README.md`](scripts/README.md). |
| `docs/` | Designs, reviews, operations notes and history; see [`docs/README.md`](docs/README.md). |
| `evidence/` | Raw harness output stays local and ignored; curated, cited summaries are tracked. See [`evidence/README.md`](evidence/README.md). |
| `recovery-dispositioned/` | Preserved recovery markers from 2026-10-05/06. Their `disposition.json` files record these paths, and CI enables long paths for them; do not move or rewrite. |

## Conventions

- Run `python3 scripts/check-doc-links.py` after moving or renaming documentation; it fails on any relative link that is not already in `scripts/doc-links-baseline.txt`.
- Raw run output goes to `evidence/<date>/<label>-*`; never reuse a label or overwrite a failed receipt.
- Source comments that point at designs use the paths under `docs/`.
