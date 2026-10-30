# Driver documentation

Current scope, owner decisions, stops and qualification status are in [`../POST-MVP-PLAN.md`](../POST-MVP-PLAN.md); read the design for a T item before changing its implementation. The review and proposed order of 2026-10-13 is [`../M2-COMPLETION-PLAN.md`](../M2-COMPLETION-PLAN.md) and the historical MVP baseline is [`../MVP-PLAN.md`](../MVP-PLAN.md). Those three stay at the top of `driver/` because the repository instructions name them. Old logs and memory summaries never override a current decision.

Documents keep their original file names, so a bare name such as `T5-DELETES.md` still identifies one file. The map of old locations is at the end.

## Architecture

What the driver is and how staged writes work.

| Document | What it covers |
|---|---|
| [ARQUITETURA.md](architecture/ARQUITETURA.md) — Arquitetura do minifiltro SafeUpload — v2 | Portuguese. Minifilter v2 design: from "intercept everything, ask every time" to real-world use. |
| [STAGED-WRITES.md](architecture/STAGED-WRITES.md) — Staged writes: design summary | Short design summary of how the driver stages, seals and publishes writes. Read this first. |

## Operations and process

Deployment, delivery gates and lab workflow. The image pipeline that builds colleagues' lab VMs (Packer, Ansible, Terraform) is in [`../../lab/`](../../lab/README.md).

| Document | What it covers |
|---|---|
| [DEPLOY.md](operations/DEPLOY.md) — DEPLOY.md — Minifiltro SafeUpload (v1) | Portuguese. Build, sign, install and test procedure for the minifilter (v1 text, staged-write MVP state at the top). |
| [FEATURE-DELIVERY-GATES.md](operations/FEATURE-DELIVERY-GATES.md) — Phase 1 feature-only delivery gates | Feature-only build and gate process now that staging is the product. |
| [LAB-WORKFLOW-DESIGN.md](operations/LAB-WORKFLOW-DESIGN.md) — SafeUpload lab and development workflow design | Proposal for lab and development tooling; implements nothing. |

## Design: lifetime and retirement

Stage versions, contexts, the stage worker and the journal (T4, T11).

| Document | What it covers |
|---|---|
| [T11-SOP-LIFETIME.md](design/lifetime/T11-SOP-LIFETIME.md) — T11 SOP startup proof and incarnation retirement | Startup proof and incarnation retirement for the section object pointers (T11). |
| [T11-UNBOUND-JOURNAL-SCALING.md](design/lifetime/T11-UNBOUND-JOURNAL-SCALING.md) — T11 / T4: unbound transfer journal scaling | Scaling of the unbound transfer journal (T11 / T4). |
| [T4-STAGE-LIFETIME.md](design/lifetime/T4-STAGE-LIFETIME.md) — T4 design note: stage-version lifetime and an event-driven stage worker | Event-driven stage worker and version/context lifetime (T4). |
| [UX-LEAK.md](design/lifetime/UX-LEAK.md) — T4: disposal completion and inert stream-context retirement | Disposal completion and stream-context retirement; the event-wait protocol is historical. |
| [UX-LEAK2.md](design/lifetime/UX-LEAK2.md) — Retirement follow-up: CREATE leases and immediate reopen controls | CREATE leases and immediate-reopen controls that followed UX-LEAK. |

## Design: applications (T8)

| Document | What it covers |
|---|---|
| [T8-CLOSURE-PLAN.md](design/T8-CLOSURE-PLAN.md) — T8 closure plan | Native-parity catalog for Office/Explorer/Edge/robocopy/7-Zip, fix order, metadata/MOTW, qualification and owner decisions. |

## Design: publication, deletes and namespace

Seal, publish, delete, rename, folders and outside-scope behavior (T5, T6).

| Document | What it covers |
|---|---|
| [T8-WORD-DROP2.md](design/publication-and-namespace/T8-WORD-DROP2.md) — T8: Word drop 2 plan | Capture-first plan for the Word overwrite and Retained-rename failures after MVP drop 1. |
| [T5-BOUND-PUBLICATION.md](design/publication-and-namespace/T5-BOUND-PUBLICATION.md) — T5 bound publication: concrete integration contract | Bound-profile publication contract. The bound line is post-M2. |
| [T5-DELETES.md](design/publication-and-namespace/T5-DELETES.md) — T5/T8 design: private discard, public delete, and in-folder rename | Private discard, public delete and in-folder rename; section 8 lists the required qualification rows. |
| [T5-NATIVE-PUBLIC-OPENS.md](design/publication-and-namespace/T5-NATIVE-PUBLIC-OPENS.md) — T5 native public opens and delete lifetime | Native public opens, delete lifetime, descriptor controls and the unreadable-seed owner choice. |
| [T5-PUBLIC-PROXY-ROUTING.md](design/publication-and-namespace/T5-PUBLIC-PROXY-ROUTING.md) — T5 public proxy routing and local lifetime | NOT READY - rejected routing; kept as evidence. |
| [T5-RECOVERY-HOLDS.md](design/publication-and-namespace/T5-RECOVERY-HOLDS.md) — T5 batch 2: recovery holds and released-stage delete receipts | Batch 2: recovery holds and released-stage delete receipts. |
| [T5-UX-NAMESPACE-GAP.md](design/publication-and-namespace/T5-UX-NAMESPACE-GAP.md) — T5 UX namespace gap on the MVP pair | The unbound MVP namespace design (D1-D6) and its manual VM acceptance list. |
| [T5-VOLUNTARY-UNLOAD.md](design/publication-and-namespace/T5-VOLUNTARY-UNLOAD.md) — T5 voluntary unload: batch 1 | Batch 1: voluntary unload and exact cleanup acknowledgements. |
| [UX-DIRECTORIES.md](design/publication-and-namespace/UX-DIRECTORIES.md) — Directory UX on the unbound MVP profile | Folder operations on the unbound profile. |
| [UX-OUTSIDE.md](design/publication-and-namespace/UX-OUTSIDE.md) — Outside-scope application compatibility (2026-10-16) | Behavior for applications and paths outside the protected scope. |

## Design: admission

Coverage retry and read-write admission (T18).

| Document | What it covers |
|---|---|
| [T18-COVERAGE-RETRY.md](design/admission/T18-COVERAGE-RETRY.md) — T18 — coverage snapshot retry before Degraded | Retry an ERROR_RETRY coverage answer before reporting Degraded. |
| [UX-ACTIVATING.md](design/admission/UX-ACTIVATING.md) — Published-file read-write admission | Read-write admission of published files (writer promotion). |

## Design: metadata

Native metadata and Mark of the Web (T8).

| Document | What it covers |
|---|---|
| [T8-METADATA-INTEGRATION.md](design/metadata/T8-METADATA-INTEGRATION.md) — T8 metadata and whole-version publication integration | Proposal: metadata and whole-version publication. |
| [UX-METADATA-ROUND2.md](design/metadata/UX-METADATA-ROUND2.md) — T8 metadata round 2 — blocked prerequisite checkpoint | Blocked prerequisite checkpoint; does not finish the T8 contract. |
| [UX-METADATA.md](design/metadata/UX-METADATA.md) — T8 metadata on the unbound MVP line | Native metadata and Mark of the Web on the unbound line. |

## Design: large files and budgets

Staging budget, reservations and large-file recovery (T9).

| Document | What it covers |
|---|---|
| [UX-LARGE-CONCURRENCY.md](design/large-files/UX-LARGE-CONCURRENCY.md) — T4/T9: growing reservations for ordinary overlapping saves | Growing reservations for overlapping saves (owner-approved 2026-10-19). |
| [UX-LARGE-INTEGRATION.md](design/large-files/UX-LARGE-INTEGRATION.md) — Large-mode integration on demo/apps | Superseded by UX-LARGE; kept for the integration record. |
| [UX-LARGE-RECOVERY.md](design/large-files/UX-LARGE-RECOVERY.md) — T9 failed-allocation and notification recovery | Failed-allocation and notification recovery. |
| [UX-LARGE-VM.md](design/large-files/UX-LARGE-VM.md) — T9 large-file Windows qualification list | Windows qualification list for large files. |
| [UX-LARGE.md](design/large-files/UX-LARGE.md) — T9 large files: product defaults and accounted staging | Current T9 design: product defaults, budgets and accounting. |

## Design: other destinations

USB/removable and SMB/UNC (T21, T22); disabled until their own gates.

| Document | What it covers |
|---|---|
| [T21-USB-REMOVABLE-DESIGN.md](design/destinations/T21-USB-REMOVABLE-DESIGN.md) — T21 — USB/removable staged protection | Design for USB/removable destinations (not enabled). |
| [T22-SMB-UNC-DESIGN.md](design/destinations/T22-SMB-UNC-DESIGN.md) — T22 — staged protection for SMB / UNC destinations | Design for SMB/UNC destinations (not enabled). |

## Reviews and review inputs

Review checklists, packages and deltas. Reports by the independent reviewers are under `driver/evidence/`.

| Document | What it covers |
|---|---|
| [M2-REVIEW-CONDITIONS.md](reviews/M2-REVIEW-CONDITIONS.md) — M2 review conditions — final adversarial checklist | Final adversarial review checklist for M2; not an acceptance. |
| [POST-MVP-REVIEW-M1.md](reviews/POST-MVP-REVIEW-M1.md) — M1 independent review (Luna, 2026-10-09) | Independent review of the M1 driver diff. |
| [T5-ATTACH-COMPLETION-KEY-DELTA.md](reviews/T5-ATTACH-COMPLETION-KEY-DELTA.md) — T5 attach completion: focused re-review delta | Focused re-review delta: attach completion key. |
| [T5-MVP-PAIR-REVIEW-DELTA.md](reviews/T5-MVP-PAIR-REVIEW-DELTA.md) — T5 MVP pair: focused pre-boot review delta | Focused pre-boot review delta of the MVP pair. |
| [T5-PREBOOT-REVIEW-PACKAGE.md](reviews/T5-PREBOOT-REVIEW-PACKAGE.md) — T5 increments 2–10: pre-boot lifetime review package | Pre-boot lifetime review package for T5 increments 2-10. |

## History

Work log and early planning notes; they do not override the status plan.

| Document | What it covers |
|---|---|
| [ONBOARDING.md](history/ONBOARDING.md) — O driver do Victor — guia de retomada | Portuguese. Resume guide for the earlier taint-based design; historical. |
| [PLANEJAMENTO.md](history/PLANEJAMENTO.md) — Planejamento — driver SafeUpload | Portuguese. Planning notes from 2026-09-17; historical. |
| [POST-MVP-LOG.md](history/POST-MVP-LOG.md) — Post-MVP work log | Chronological work log with the reasons for every unattended decision. |

## Where documents used to live

Older logs, review notes and evidence files link to the former top-level paths. Each moved file keeps its name:

| Former path | Current path |
|---|---|
| `driver/ARQUITETURA.md` | `driver/docs/architecture/ARQUITETURA.md` |
| `driver/DEPLOY.md` | `driver/docs/operations/DEPLOY.md` |
| `driver/FEATURE-DELIVERY-GATES.md` | `driver/docs/operations/FEATURE-DELIVERY-GATES.md` |
| `driver/LAB-WORKFLOW-DESIGN.md` | `driver/docs/operations/LAB-WORKFLOW-DESIGN.md` |
| `driver/M2-REVIEW-CONDITIONS.md` | `driver/docs/reviews/M2-REVIEW-CONDITIONS.md` |
| `driver/ONBOARDING.md` | `driver/docs/history/ONBOARDING.md` |
| `driver/PLANEJAMENTO.md` | `driver/docs/history/PLANEJAMENTO.md` |
| `driver/POST-MVP-LOG.md` | `driver/docs/history/POST-MVP-LOG.md` |
| `driver/POST-MVP-REVIEW-M1.md` | `driver/docs/reviews/POST-MVP-REVIEW-M1.md` |
| `driver/STAGED-WRITES.md` | `driver/docs/architecture/STAGED-WRITES.md` |
| `driver/T11-SOP-LIFETIME.md` | `driver/docs/design/lifetime/T11-SOP-LIFETIME.md` |
| `driver/T11-UNBOUND-JOURNAL-SCALING.md` | `driver/docs/design/lifetime/T11-UNBOUND-JOURNAL-SCALING.md` |
| `driver/T18-COVERAGE-RETRY.md` | `driver/docs/design/admission/T18-COVERAGE-RETRY.md` |
| `driver/T21-USB-REMOVABLE-DESIGN.md` | `driver/docs/design/destinations/T21-USB-REMOVABLE-DESIGN.md` |
| `driver/T22-SMB-UNC-DESIGN.md` | `driver/docs/design/destinations/T22-SMB-UNC-DESIGN.md` |
| `driver/T4-STAGE-LIFETIME.md` | `driver/docs/design/lifetime/T4-STAGE-LIFETIME.md` |
| `driver/T5-ATTACH-COMPLETION-KEY-DELTA.md` | `driver/docs/reviews/T5-ATTACH-COMPLETION-KEY-DELTA.md` |
| `driver/T5-BOUND-PUBLICATION.md` | `driver/docs/design/publication-and-namespace/T5-BOUND-PUBLICATION.md` |
| `driver/T5-DELETES.md` | `driver/docs/design/publication-and-namespace/T5-DELETES.md` |
| `driver/T5-MVP-PAIR-REVIEW-DELTA.md` | `driver/docs/reviews/T5-MVP-PAIR-REVIEW-DELTA.md` |
| `driver/T5-NATIVE-PUBLIC-OPENS.md` | `driver/docs/design/publication-and-namespace/T5-NATIVE-PUBLIC-OPENS.md` |
| `driver/T5-PREBOOT-REVIEW-PACKAGE.md` | `driver/docs/reviews/T5-PREBOOT-REVIEW-PACKAGE.md` |
| `driver/T5-PUBLIC-PROXY-ROUTING.md` | `driver/docs/design/publication-and-namespace/T5-PUBLIC-PROXY-ROUTING.md` |
| `driver/T5-RECOVERY-HOLDS.md` | `driver/docs/design/publication-and-namespace/T5-RECOVERY-HOLDS.md` |
| `driver/T5-UX-NAMESPACE-GAP.md` | `driver/docs/design/publication-and-namespace/T5-UX-NAMESPACE-GAP.md` |
| `driver/T5-VOLUNTARY-UNLOAD.md` | `driver/docs/design/publication-and-namespace/T5-VOLUNTARY-UNLOAD.md` |
| `driver/T8-METADATA-INTEGRATION.md` | `driver/docs/design/metadata/T8-METADATA-INTEGRATION.md` |
| `driver/UX-ACTIVATING.md` | `driver/docs/design/admission/UX-ACTIVATING.md` |
| `driver/UX-DIRECTORIES.md` | `driver/docs/design/publication-and-namespace/UX-DIRECTORIES.md` |
| `driver/UX-LARGE-CONCURRENCY.md` | `driver/docs/design/large-files/UX-LARGE-CONCURRENCY.md` |
| `driver/UX-LARGE-INTEGRATION.md` | `driver/docs/design/large-files/UX-LARGE-INTEGRATION.md` |
| `driver/UX-LARGE-RECOVERY.md` | `driver/docs/design/large-files/UX-LARGE-RECOVERY.md` |
| `driver/UX-LARGE-VM.md` | `driver/docs/design/large-files/UX-LARGE-VM.md` |
| `driver/UX-LARGE.md` | `driver/docs/design/large-files/UX-LARGE.md` |
| `driver/UX-LEAK.md` | `driver/docs/design/lifetime/UX-LEAK.md` |
| `driver/UX-LEAK2.md` | `driver/docs/design/lifetime/UX-LEAK2.md` |
| `driver/UX-METADATA-ROUND2.md` | `driver/docs/design/metadata/UX-METADATA-ROUND2.md` |
| `driver/UX-METADATA.md` | `driver/docs/design/metadata/UX-METADATA.md` |
| `driver/UX-OUTSIDE.md` | `driver/docs/design/publication-and-namespace/UX-OUTSIDE.md` |
