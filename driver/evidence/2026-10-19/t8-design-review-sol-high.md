# T8 integration proposal review — retained on resume

Independent reviewer `t8_integration_design_review`, gpt-6.1-sol, high, 2026-10-17; reviewed `adc1fb11`.
**REVISE for product integration.** Acceptable increment-1 feasibility plan; no product implementation approval.

P1: native full-security construction for an existing non-caller owner with no caller parent ADD_FILE/WRITE_OWNER/WRITE_DAC remains
unproved; define how later temporary replacement operations determine the actual native metadata rule. P1: stock Edge/Explorer
pre-registration/finalization producer is absent, so main-stream close or a timer cannot prove whole-version completeness.
P1: commit fence still lacks exact callback/admission/mapped-cleanup owner/capability/drain/retirement design.

Directional 0x0400 comparison, independent post-cleanup authority, exact MOTW hand-back and bookkeeping-only recovery remain sound
requirements. Next: native feasibility controls and a concrete revised design. These are engineering questions, not reapproval of the
existing owner contract. No VM/builder/product edits or qualification by reviewer. Native experiment subsequently committed at `62127384`.
