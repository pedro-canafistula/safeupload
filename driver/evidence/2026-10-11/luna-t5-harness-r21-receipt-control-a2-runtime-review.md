# R21 receipt-writer a2 runtime evidence review

## Evidence checked

I checked the preserved a2 root result (`m2-t5-harness-r21-receipt-control-a2-root-result.json`, SHA-256 `f69532b7c92197960dfd2c6ce542bea28d8ffc3e1ff553f5877e89aa44146d57`), raw control stdout (`m2-t5-harness-r21-receipt-control-a2-controls.stdout.log`, SHA-256 `0c1eadc282ef9b9fcd8cc9ba9bb331cf2f1946b1a56bc6c2ff3cbf4bc97e3942`), stderr (SHA-256 `e19f9cf97a60506aa480a8ed48b661f45aa9eaacb71ac18c66537620b0244233`), and root verification (`m2-t5-harness-r21-receipt-control-a2-root-verification.json`, SHA-256 `254389a8b463b4c8661932338f0b48f1fa05398a9eaacfe3ae06f23391b6ed8c`). The verification binds the a2 control capture `0ec098e291138b215e891c77e54f97075236cbbe7e63c6aa3b61a1f0adb2df72`, the protocol module SHA-256 `f9dba8569c7bf2fafef648c5b6d49211ee299b6adc4651733dfb5acbbd6f251a`, and control SHA-256 `265b1bef47b4b5ccd907cfc5f8427bbfee5113f583ae8136d042e5d041f1b3c0`.

The raw stdout contains exactly one complete `R21_RECEIPT_WRITER_CONTROL_PASS` JSON line. It records Windows PowerShell `5.1.19041.6456`, parse errors zero for both pinned files, six passing checks, unchanged before/after module and control hashes, and the fresh TEMP fixture removed after owned-file cleanup. The six checks cover the allowlisted function extraction, TEMP confinement, wrong tuple and path rejected before writes, final-name collision preserving the prior bytes with no staging artifact, and exact successful receipt bytes and hashes.

## Runner failure versus control result

The overall root runner result correctly remains **FAIL**: its controls step exited 1 and records `Missing or ambiguous complete receipt-writer PASS.` The verified actual control result is separately **PASS**. This distinction is explained by the frozen wrapper plan (SHA-256 `61e173338206fd8de1b52cbbf07d8f3a4f007628ab0c7ed990835c9af5c42a42`): it assigns `$output = @(& ...Invoke-R21ReceiptWriterControl.ps1)` and searches that PowerShell pipeline variable for the PASS sentinel. The control emits the sentinel with `[Console]::Out.WriteLine`, which writes directly to process stdout instead of the invocation’s PowerShell success stream. The sentinel is present in captured raw stdout, while the wrapper’s pipeline variable lacks it. Thus the failure is in wrapper capture, not in an assertion from the receipt-writer control.

I verified the corresponding hashes: the controls stdout hash matches the root result’s recorded controls stdout hash, and the raw stderr hash matches its recorded stderr hash. Root verification classifies `ActualReceiptWriterControlPassed: true` and `RunnerWindowsControlsPassed: false`, preserving both facts. Its post-check hashes match the preserved post-check outputs; those report unchanged local inputs, unchanged two pinned remote source files, the original process terminal, and the owned fixture absent after success. The process PID/start FILETIME agree across raw stdout, control JSON, and verification. No retry was performed; preserve the runner failure and all original evidence.

## Bounded conclusion

The evidence supports a PASS for this isolated actual receipt-writer control on the captured Windows PowerShell 5.1 environment. It covers the pinned writer’s valid output, invalid identity/path guards, no-overwrite collision, sentinel preservation, and owned-temp cleanup. It does not observe a consumer during an in-progress partial write and does not prove concurrent publication visibility. It is not a full gate, coordinator, service, VM, product, or cutover result.

This was read-only evidence review. I did not rerun the control or wrapper, execute source, import a module, use a VM, access a host, or perform a Git operation.
