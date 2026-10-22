# T8 closure plan — Office and everyday apps behave as without SafeUpload

2026-10-22. **Owner agreed to the recommendations of section 6 (decisions 1–4) on 2026-10-22; decision 5 stays open. No implementation, review or qualification claim yet.** Scope and status remain in
[`POST-MVP-PLAN.md`](../../POST-MVP-PLAN.md) (T8 section and the 2026-10-16 owner decisions); the metadata/MOTW mechanism is
[`T8-METADATA-INTEGRATION.md`](metadata/T8-METADATA-INTEGRATION.md) with its [review](../../evidence/2026-10-19/t8-design-review-sol-high.md)
(REVISE) and [concrete analysis](../../evidence/2026-10-19/t8-concrete-design-analysis-sol-high.md).

## 1. Why the last two user-visible bugs escaped

| Bug the owner hit | Cause | Why no row caught it |
|---|---|---|
| Deleting a published file from the protected folder failed "Access denied" (`del`, `Remove-Item`, Explorer Shift+Delete). | `DeleteFileW` opens with `FILE_OPEN_REPARSE_POINT`, which the native route excluded, so the delete took staged admission and was refused. Fixed by T5 D7 (2026-10-22). | The only row case that calls `DeleteFileW` on a published file first got past its own harness defects in `m2t5ord7`/`ord8`; no earlier row reached it, and the host controls did not model the native-route exclusion. |
| A `.docx` saved in the protected folder came back read-only in Word. | Word reopens the file right after its save; the reopen met gate 6 (rename exchange still pending) and got a sharing violation, so Word marked the document read-only. Analysed 2026-10-19 ([analysis](../../evidence/2026-10-19/word-readonly-gate-analysis-sol-high.md), [review](../../evidence/2026-10-19/word-reopen-design-review-sol-high.md): REVISE); **never implemented**. | The rows check bytes, privacy and lifetime. None checks what the application itself reports (read-only flag, error dialog, Protected View). |

Both are the same class: **the protected folder behaved differently from an ordinary folder for an operation SafeUpload should not
affect**. The rows were strong on "no uninspected byte escapes" and weak on "the app works exactly as before". This plan adds that
second bar and makes it a standing gate.

## 2. The bar: native parity plus zero unexplained refusals

For every case in the catalog (section 3), the same standard user performs the same operation twice: once in an unprotected control
folder on the same volume and once in the protected folder. The case passes only if:

1. **Same outcome:** every step returns the same Win32/NTSTATUS result; the same final names exist with the same bytes; the application
   reports the same state (not read-only, no error or "file in use" dialog, Protected View only where Windows shows it, document
   saved/dirty flags identical).
2. **Same metadata** within the owner's 2026-10-16 contract: owner, group, DACL/SACL/label, times and attributes as Windows gives the
   control, `ChangeTime` excepted; Zone.Identifier exactly where the control has it.
3. **Zero unexplained refusals:** the driver's deny ring has no entry for the case's processes except the intended differences below.
   A refusal that the control did not get is a bug even when the case eventually succeeds (that is how the Word read-only bug looked).
4. **Intended differences only**, each listed in the case: sensitive (CPF) content is blocked and handed back with the original intact
   or the new name absent; images and `.7z` are refused with their reason; EFS, offline, EA, other ADS, reparse points and hard links
   into protection are refused with their reason; folder moves into protection follow the copy rule; the reasons appear in the tray.

The existing byte/privacy, raw-observer, registry-Known, staging-empty and journal-settled lines stay required on top of this.

## 3. Everyday-operation catalog (the owner's eight T8 workflows plus Explorer and the T5 regression set)

Each line becomes one parity case (control and protected), run as `t5actor` in the interactive session.

| Area | Operations |
|---|---|
| Word, Excel, PowerPoint (Microsoft 365 Apps) | open existing by double-click and File > Open (not read-only, no Protected View for local files); edit + save in place (temp file + rename swap, `~$` owner file, AutoRecover); Save As new name; Save As over an existing file; **close and reopen at once**; open the same file twice and from a second app (native "locked for editing"); rename/delete while open (native refusal); CPF save (blocked, handed back, original intact); export to PDF; Save As to an unprotected folder; downloaded (MOTW) document: Protected View, Enable Editing, save. |
| WordPad | open/save `.rtf` and `.docx`, Save As, reopen, CPF save. |
| Explorer | list, details and preview pane, thumbnails; New > text/Word/Excel; rename (incl. extension); copy in/within/out; move in (copy rule)/within/out; replace on copy; Recycle Bin delete, restore, Shift+Delete, empty bin; Properties (read-only toggle, Security and Details tabs); drag and drop; Send to > Compressed folder; Extract All; search; new/rename/delete folder (idle). |
| Browser (Edge) | download into the protected folder (clean and CPF), open after download, Zone.Identifier present, Protected View on open; download then copy/move of the downloaded file. |
| robocopy | into protection (`/E`, `/COPY:DAT`, `/MIR` with deletes, `/MOV`), out of protection, rerun over identical files; retry flags behave as on the control. |
| 7-Zip | open an archive from protection; extract many files into protection; create/update a `.zip` from protected files; `.7z` creation refused with its reason. |
| T5 regression | the Notepad, probe-delete, public-delete and workflow cases of `Invoke-StageNotepad.sh`, unchanged. |

Every bug found from now on adds its case to this catalog permanently (with the native control), so a fixed bug cannot return
unnoticed.

## 4. Workstreams and order

**A. Parity harness (first, 2–3 days).** Reuse the T5 coordinator, actor, raw observer, superseded-sample rule and verdict style.
Add: an app driver (Office through COM automation for deterministic saves, which use the same save engine as the UI; UI Automation
only to read what the user sees: title-bar read-only marker, Protected View bar, error dialogs; Explorer through the shell API as T5
does; Edge download through its download path, not a raw HTTP write); a paired control/protected runner; the outcome-tuple comparator;
and the deny-ring attribution per case. It must run in about 30 minutes in ordinary mode so it can be rerun after every fix.

**B. Discovery sweep (1–2 days).** Run the whole catalog on the current pair (driver `29D6130E…`, agent `m2t5a5`) on the Office dev
disk, budget on (the product default) and off. Output: a triaged defect list, each with the failing case, the deny-ring entries and
a hypothesis. Already known and expected to reappear:

1. Word read-only after save (gate 6; implement the reviewed conservative owner-reopen settlement).
2. Word/Office save sequence: `FileBasicInformation`, compression/object-ID queries, temporary files and the rename swap over a
   published file (found 2026-10-16 on the MVP line; recheck on the current pair).
3. Office `~$` owner-file allocation/receipt refusals (gate 3, 2026-10-19).
4. Metadata-only opens (Properties, preview, search) refused with a sharing violation while an allocation or directory mutation is
   pending (`m2t5ord6`/`ord7`, reason 17 gates 1 and 3); native NTFS never applies share modes to them.
5. Two writers opening one protected file at the same instant (T4 decision 2026-10-20: a sharing-policy question for T5/T8).
6. The T9 budget-on defects (whole-allowance reservation, refund wait in the receive loop) that make overlapping Office saves fail
   with the product default.

**C. Fix waves (about 1–2 weeks, depends on B).** Order by user impact: open/reopen and read paths; save sequences; Explorer;
robocopy/7-Zip bulk; browser downloads. Use the owner's 2026-10-16 dev rule: dev builds go unreviewed onto the dev run disk for fast
iteration; each fix lands with its host controls and its new catalog case, and the whole catalog is rerun after every fix (this is the
regression guard that would have caught the `m2t5ord9` registry regression before a qualification row). Kernel lifetime deltas are
batched into one coherent change and get one Sol 6.1 high review before the first qualification boot, as the review policy requires.
Agent deltas run the four-leg matrix at the delivery checkpoint.

**D. Metadata contract and Mark of the Web (about 2–3 weeks, the largest risk; starts in parallel with B).** Follow the four
increments of `T8-METADATA-INTEGRATION.md`: (1) native construction and producer feasibility controls on the unprotected target,
(2) immutable version authority, exact output/security capability and the commit fence, (3) Zone.Identifier as part of the version,
atomic publication and exact hand-back, (4) gates and rows. The unmerged `ux/meta2` branch (7 commits, about 5,400 lines, based
2026-10-16, 154 commits behind) is a source of parts, not a ready merge: port piece by piece behind its own controls. Two items are
unresolved engineering questions, not just work: native full-security construction for an existing file the caller may write but
not re-create, and a **completion witness for browser and Explorer MOTW** (the review's feasibility stop). The first native spike
answers whether a transparent mechanism exists; if not, the owner chooses the user-visible behavior (decision 5).

**E. Qualification (3–5 days).** Final matched pair: two WDK profiles, PREfast, ApiValidator, imports, four-leg matrix, PS 5.1 gates.
Rows in ordinary, runtime-Verifier and boot-Verifier modes: the eight workflow rows and the whole parity catalog, with independent byte
observation and separate restoration; the T4 and T5 rows rerun on the same pair (no regression); then an owner manual acceptance pass
on a prepared VM (Notepad, Word, Excel, PowerPoint, Explorer, Edge), whose findings become catalog cases; then the final adversarial
review of the pair.

## 5. Estimate

About 4–7 weeks in total, dominated by D. A–C (everyday parity) can finish in about 2–3 weeks and already removes the class of bug
the owner hit; D is long because two mechanisms are not yet proved. The estimate assumes the Office image is available on day one and
that T9's growing reservations land during C (T8 cannot qualify with the product default before that).

## 6. Owner decisions needed

1. **Office for automated rows.** Recommended: one new Office base image derived from the current `win10-debug3` base (Microsoft 365
   Apps, 7-Zip, Edge settings), you sign in to Office once, the existing base stays untouched, and every row takes a fresh disposable
   overlay from it with the usual restoration. Alternatives: install Office in each row (slow and needs a sign-in each time), or
   use only the retained dev disk (not disposable, so it cannot qualify).
2. **Adopt the parity bar (section 2) as part of T8's "done when".** Recommended: yes; it is the check both escaped bugs would have
   failed.
3. **Order.** Recommended: everyday parity (A–C) first, metadata/MOTW (D) in parallel but not blocking the parity fixes; both stay
   required for M2.
4. **Budget setting for T8 rows.** Recommended: discovery with the product default (budget on) and off; qualify only after T9's
   growing reservations land. Alternative: isolation rows with StageSpace off, as T4 and T5 did, carrying budget-on to T9.
5. **Browser and Explorer Mark of the Web** (only if the spike finds no transparent completion witness). The choice will be among
   behaviors the user sees, for example refusing a download straight into a protected folder with a clear message (save elsewhere,
   then copy), or a SafeUpload-provided download/copy path. Recommendation deferred until the spike's native traces exist.
