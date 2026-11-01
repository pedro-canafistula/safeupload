# PDF regression input

`word-export-hybrid.pdf` is the owner's Word export fixture, copied byte-for-byte from `safeupload-demo/.scratch/fmt/in/rel.pdf` on 2026-10-16. Its page text is `Relatorio em PDF`. SHA-256: `c59fb917adc41655f889e83105cd7e14b48f063de8f5a2b1c956d111d8c5f018`.

It has an empty final xref table linking `/Prev` and `/XRefStm`, with repeated table/stream references to identical stored objects. The tests also independently generate clean/CPF variants, disjoint sections, and differing-offset/generation revisions; those are constructed in source so their content and structure are reviewable.
