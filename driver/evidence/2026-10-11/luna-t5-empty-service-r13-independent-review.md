# Independent security review: managed service R13

**Disposition: scoped GO for a fresh Windows diagnostic using this frozen R13 source.** The three R12 `Assert.Null` calls on a non-nullable attachment-state enum are now exact `Assert.Equal(StagedAttachmentStateV20.None, ...)` assertions. The four retained local cross-target compiler profiles report zero warnings and errors. This GO covers only input to a diagnostic build/test run after the independent matrix-tool gate; it does not qualify Windows behavior, the service/native pair, or the product.

## Scope and provenance

I reviewed the immutable source at `output/review-candidates/m2-t5-empty-service-1011-r13/src`, rechecked its relationship to R12, and inspected the changed assertions and retained compiler evidence. R13 changes only `StagedTransferAllocatorTests.cs`; the production service source, including R12's CREATE_AFTER/op19 and V1/V2 ancestry checks, is byte-identical to R12. I did not edit source, run a build or test, use a Windows VM, connect to libvirt, or mutate Git.

The R13 receipt is `driver/evidence/2026-10-11/m2-t5-empty-service-r13-root-review-capture.json`, SHA-256 `828246fd46b6cdaf8ea3be2fab94267dfa9e158c0542c2aa675806b6e7906d19`. I independently checked its closed 202-file path set and all hashes with stable no-follow reads. The live `agente/` tree and frozen candidate match all 202 pins at both the start and end of this review. Exactly one pin differs from R12: `agente/SafeUpload.Agent.Tests/StagedTransferAllocatorTests.cs`, R12 SHA-256 `054afce68c5510cc15d852b27a6f7319f60a3cfdad0568e0750a93cd51e2a4db`, R13 SHA-256 `e07204e6e30a1b06ee6bd711d2c1f7cfcddbeacff2adb67cd365939d4925b220`. The R12 report remains immutable at SHA-256 `471008ceb98f536efc8183985e373dd9ec9818eb4ff164a1ce8081e296faaff9`.

## R12 blocker correction

The R13 diff changes only the three legacy-chain state assertions at `StagedTransferAllocatorTests.cs:508, 519, 558` from `Assert.Null(entry.AttachmentStateV20)` to `Assert.Equal(StagedAttachmentStateV20.None, entry.AttachmentStateV20)`. `AttachmentStateV20` is a non-nullable enum and `None` is its default. The new assertions now check the exact legacy state rather than passing a boxed value-type enum to `Assert.Null`.

No production state-machine behavior changed from R12. The source review of the R12 journal confirms that a measured CREATE_AFTER V2 predecessor needs the exact active driver epoch and durable op15/op19 receipts with positive distinct IDs before first mutation or replay; its V1 parent must match the exact identity, epoch, writer, destination, and EmptyHeld/zero-length state. The explicit legacy path accepts only a fully legacy chain. The R13 changes preserve that source unchanged.

## Compiler evidence and limits

The retained R13 local compiler result is `m2-t5-service-r13-local-diagnostic-a1-root.json`, SHA-256 `9b8c103d8f81000c7942906c7a9528ab1cf7ed05a7a4a3115678730213fc90e7`. All four normal/feature Debug/Release profiles exited 0 with zero warnings and zero errors; the receipt also confirms the frozen source copies remained unchanged. Their logs are:

| Profile | Exit | Warnings | Errors | Raw log SHA-256 |
|---|---:|---:|---:|---|
| normal Debug | 0 | 0 | 0 | `e731d7dbb129b825a7d0af7a3a390be22584717a9092c372680a8b8abae447e5` |
| normal Release | 0 | 0 | 0 | `3ec7bc2dcb265489570e5733cc0915e0aa45bbf7f08438ff112c2c50a529283f` |
| feature Debug | 0 | 0 | 0 | `a808f46f91eacc7f0c69d0d194107b6bbec92a0433eab69cec4083fbea5f43a5` |
| feature Release | 0 | 0 | 0 | `2a8ab75607acdc80d0ca0402868cd18036c8ffc294bc75bb7c32de9b84c4c64d` |

These are local cross-target compiler diagnostics, not Windows test execution. The receipt has `TestsExecuted=false`, `WindowsMatrixQualified=false`, and `PairQualified=false`. The three R12 corrections were not executed in this review; they now have clear, exact assertions suitable for the next Windows diagnostic.

## Frozen R13 source pins

The following table is the complete 202-file `SourceHashes` map from the R13 receipt.

| Source path | SHA-256 |
|---|---|
| `agente/.gitignore` | `3c6ad88f0896281f944a48e70ff1e5903c7a8d26942d4141f68af3c19107a363` |
| `agente/NOTIFICATION-RECORD.md` | `c8d5058ba9a019aae9e80bcac38d2f2ee811183932828075d50e8c63c0c11957` |
| `agente/README.md` | `ffd481562d7eb8fac9cd2aad88b8402dbfc7e51d05f3499b3f5639ebe4511b12` |
| `agente/SafeUpload.Agent.App/App.xaml` | `a4bdd522307865d8c00738af58a82cfd53a329c689fdff6551d6e0764bdccb6a` |
| `agente/SafeUpload.Agent.App/App.xaml.cs` | `4eb898962c58b1c392b4e700b4fc2b955be0561c3be7aa765fad666f260fb0b8` |
| `agente/SafeUpload.Agent.App/AssemblyInfo.cs` | `d41e48d2bce7f9eda84eef27c4008920a5639dd3f56baeff39273d58381575fe` |
| `agente/SafeUpload.Agent.App/ClipboardWatch/ClipboardMonitor.cs` | `94ab4f87032faa89a75ca3b895c889ba79021f55beae8fec81658aa86c453d9c` |
| `agente/SafeUpload.Agent.App/ClipboardWatch/ClipboardPipeClient.cs` | `ec99c07f34b5a64d9f3e61fb458d4614fa33918e55c58062a66bc5de17b13129` |
| `agente/SafeUpload.Agent.App/Mvvm/Converters.cs` | `3decc38a1d7776e50839ea50281a849beb2bed83a79bcbbac63c5a83a5d596c6` |
| `agente/SafeUpload.Agent.App/Mvvm/ObservableObject.cs` | `be496b6d969f63ffe2bf9560e043a4085e3730610ed7c4b9febdedc21bfd71bf` |
| `agente/SafeUpload.Agent.App/Mvvm/RelayCommand.cs` | `3b1d16529d34a46d23e1291a1cc8a764ac540c9cc8997749bd7fd749efd7dc8b` |
| `agente/SafeUpload.Agent.App/Notifications/JustificationPipeClient.cs` | `0f6ed387d557c47684d284d8168045ab0eb54c7879a1f57ab02b3fd13cd7b537` |
| `agente/SafeUpload.Agent.App/Notifications/PipeClient.cs` | `d47f405f373dbd0add71cccb4ba0bfbaf0cd4042b3b40c202b628a260a1c9cbc` |
| `agente/SafeUpload.Agent.App/Resources/Icons.xaml` | `a37ea1d025d6144d26637f8e79ecaded7f9c2b23e97cde40c83b84ca50a95011` |
| `agente/SafeUpload.Agent.App/Resources/Tokens.xaml` | `6cdd9424c20a78b7d953b6fcf54baa9b2047b939f59b0f4fe9becee7395e9b96` |
| `agente/SafeUpload.Agent.App/SafeUpload.Agent.App.csproj` | `9b6ef4b7803464041f1a4bd3986f3c84110a2d7420d641677092f9d9f84ba108` |
| `agente/SafeUpload.Agent.App/TrayIconHost.cs` | `40912e6c128ea43be0e94cc71074eecc0fc659b96f8a07acbe2d6309e7164cec` |
| `agente/SafeUpload.Agent.App/ViewModels/ActivityRowViewModel.cs` | `6874a45fe3c989454729f135f7c9328237e0b700eb0be7798a10ac9ff2d48312` |
| `agente/SafeUpload.Agent.App/ViewModels/AgentViewModel.cs` | `a158ef5e5d0872e851b4f43af4d6f037a54be05b8f3f6e8038c826ceae1227dd` |
| `agente/SafeUpload.Agent.App/ViewModels/FindingViewModel.cs` | `808a7c19fd4d1dc42d33908c0acb9575755348d143560e0eaa12ded3ecdff709` |
| `agente/SafeUpload.Agent.App/ViewModels/HistoryViewModel.cs` | `9bb15fc8aa18e1397c91bf1c684a0a42fbf11c5708253a1bf1de0a24d96cd881` |
| `agente/SafeUpload.Agent.App/ViewModels/QueueRowViewModel.cs` | `5d26230e1979d9b8a996b442df190555b55241c6441c96d2e46e3253bd1959cf` |
| `agente/SafeUpload.Agent.App/ViewModels/StatusViewModel.cs` | `666b6cc64bd5f4d3440e79a3551076a63aba7cef087bd4979c8c00159c8f4ec9` |
| `agente/SafeUpload.Agent.App/Views/AgentWindow.xaml` | `cb1fa11d533fb57bd74c48431c358678c0e634cd2d1a0bad3199254af6ea07ac` |
| `agente/SafeUpload.Agent.App/Views/AgentWindow.xaml.cs` | `91256e822508ae2cbb3fa4b4dc6c2412aa755b97b93fb2cee43d423954b342a1` |
| `agente/SafeUpload.Agent.App/Views/BlockNotificationWindow.xaml` | `b8fac648b2b6196ffc54db959e9b789794443768a171abaa3713764aa8b5f1f0` |
| `agente/SafeUpload.Agent.App/Views/BlockNotificationWindow.xaml.cs` | `f71053f3cc0ff72b7a685cd19215213eeac3dd4ace0fd7b67d72b5d02fc773bd` |
| `agente/SafeUpload.Agent.App/Views/HistoryView.xaml` | `2639bee0a0adb8cadd655da0a7b30e6b34d694774b1e6784d60e345b146b6f0e` |
| `agente/SafeUpload.Agent.App/Views/HistoryView.xaml.cs` | `ab0532945fd0061fc1d883bc989cc559466368ab879da591111d1c810de05d2a` |
| `agente/SafeUpload.Agent.App/Views/StatusView.xaml` | `fe52f9e069bd1e70ced33cb56af12696613eb31032c0fcec5087afdbcfea69a6` |
| `agente/SafeUpload.Agent.App/Views/StatusView.xaml.cs` | `dba1f72485696999794705340a71db57538a6884bbe4bc8339a76fcbb47d1491` |
| `agente/SafeUpload.Agent.App/app.manifest` | `30d95912d895c72ca4bd5800928be890346ba17583e94e04059d05c5604ccc45` |
| `agente/SafeUpload.Agent.ContractSmoke/Program.cs` | `f27a576a3f361937f1c7cb1fd3cdc9d76fcacc8264938063b16d947946e81b4c` |
| `agente/SafeUpload.Agent.ContractSmoke/SafeUpload.Agent.ContractSmoke.csproj` | `f07c18476399cae6a25c633526f479cabdb692b10dfc4ec374f5a40213c9938d` |
| `agente/SafeUpload.Agent.Core/Application/IAuditSink.cs` | `38f7811cc1503292e6900dc979a88538eb28f0ccb3f762182218abe9654b1fe0` |
| `agente/SafeUpload.Agent.Core/Application/IPolicyStore.cs` | `aa64b7cb6f1fc24061f20eda6bf9d0444c57d8585e7d05efbb567141f02f9eec` |
| `agente/SafeUpload.Agent.Core/Application/InspectionService.cs` | `0fab4f38105728751113b6a87bb1292367db3670acfde09975c0a7dbb6effe51` |
| `agente/SafeUpload.Agent.Core/Application/VerdictCache.cs` | `08bbcdcfffa6a0a657930d27edacce3db7a65ca65607cfd2b52f7cf9930ed609` |
| `agente/SafeUpload.Agent.Core/Contracts/AgentNotification.cs` | `360f8cf22dc30e4da259b0a29775ee7f2176dfdb15e1654d2bd0e6bacc79d980` |
| `agente/SafeUpload.Agent.Core/Contracts/ClipboardProtocol.cs` | `f4373e8ce673635a8c5ffd03d2a767022ee0f45ac75c65f256cfffb1bac2e7d5` |
| `agente/SafeUpload.Agent.Core/Contracts/JustificationRequest.cs` | `16adacae281529cf4454d2ac4456ca69cf97e1faf4209452f3a5afd5813ba187` |
| `agente/SafeUpload.Agent.Core/Contracts/NotificationProtocol.cs` | `5f6d42fe30654ee3bb6342f5149366200773ba154e8e809701318f86e05667ca` |
| `agente/SafeUpload.Agent.Core/Domain/AuditEvent.cs` | `a75f62189ede44856b60fe5038d2695139a494e8bbbc4c91a6cd868990d410d3` |
| `agente/SafeUpload.Agent.Core/Domain/Category.cs` | `915ba54d9197595abfbe02bb14cde0527e641e5589029957715833eaf49c202e` |
| `agente/SafeUpload.Agent.Core/Domain/ClipboardPolicy.cs` | `ac4ebeb66113a33145701d77fbe291db1456fc315b469ab577402439509318e0` |
| `agente/SafeUpload.Agent.Core/Domain/ClipboardRules.cs` | `8af16007023d3da7afb68a90063352b8b7fb8f49d004d488162344046df0a27a` |
| `agente/SafeUpload.Agent.Core/Domain/ContentScanner.cs` | `bdecfd0f0315d525477dc0166dcbfa0a9f2192326c6e6fa69198412ae5721e98` |
| `agente/SafeUpload.Agent.Core/Domain/FileOperation.cs` | `7ace2b50d3e333c99e98f361aaac6a3e88a9607d53656413bbe0dbed9fcf71b6` |
| `agente/SafeUpload.Agent.Core/Domain/Finding.cs` | `9dfb4efed163be6b6dcb3dcd55322f9c05bb154a0534d8e92af485bd68b4edf1` |
| `agente/SafeUpload.Agent.Core/Domain/InspectionResult.cs` | `e9933d2024c609980d04540cf93065ef8998843100a7a65b25c2648340c80589` |
| `agente/SafeUpload.Agent.Core/Domain/Policy.cs` | `768ca70db8f91304a0bdfd2b2d166b336e43aa7a1a1a9831f64cf51c9b64ee48` |
| `agente/SafeUpload.Agent.Core/Domain/Validators/CnpjValidator.cs` | `15fa5b56bd8c64ec5c037a2a9810400ab8d32301047c7845cf2f5a79375f4924` |
| `agente/SafeUpload.Agent.Core/Domain/Validators/CpfValidator.cs` | `110c9d013360c9ae0ba7f24cefbf2e547bb02da17bfcb2458fb18f09d34ee6fb` |
| `agente/SafeUpload.Agent.Core/Domain/Validators/DigitRules.cs` | `f28f7935313834a90eff5807a5413fc3d94aa2d54fa5a28ba80d46cd2e25b6a0` |
| `agente/SafeUpload.Agent.Core/Domain/Validators/LuhnValidator.cs` | `3250b21a83e7c822e340fb50037b7d6513f2369c2416d675d3d539a0007410e1` |
| `agente/SafeUpload.Agent.Core/Domain/Validators/Masking.cs` | `1d4722f743d894975437eeb94458be0dc83b16dff3927d060d7163f64c49eb93` |
| `agente/SafeUpload.Agent.Core/Domain/Validators/PasswordHeuristic.cs` | `4c0c27e02faf4846e130ef93c7d1ae02e1246d9901ae364e7d6b1962cd900198` |
| `agente/SafeUpload.Agent.Core/Domain/Validators/SecretDetector.cs` | `35f87ced49f6416061e5ae15d85ec9349c8adce879780a2eda8fe2ce67efaa29` |
| `agente/SafeUpload.Agent.Core/Domain/Verdict.cs` | `4bb7050f59032805f4fe68b859cdb12d90c0c39cfa1966e9ef3048337dfb33ae` |
| `agente/SafeUpload.Agent.Core/Infrastructure/AgentPaths.cs` | `40ed1e6a4f5bfa7302b7546d26a06f3b0d95de1306c0396322e7314ac242e695` |
| `agente/SafeUpload.Agent.Core/Infrastructure/Extraction/ExtractorRegistry.cs` | `1402cfa9000ffcda0a71e9dcf4a32696360f2ad97487c879cd1ea637b4e56e16` |
| `agente/SafeUpload.Agent.Core/Infrastructure/Extraction/ITextExtractor.cs` | `528b62b88a9e5417d09b75ec5b50c5e9fcdec65885ff28be9b67ca9836ab9681` |
| `agente/SafeUpload.Agent.Core/Infrastructure/Extraction/OpenXmlSheetExtractor.cs` | `5236ab2a18d98914f80babc9ae02e0655c1f86c8cb31c5c18d7b8c87b5fdcf32` |
| `agente/SafeUpload.Agent.Core/Infrastructure/Extraction/OpenXmlWordExtractor.cs` | `0b384e01ccb7f398369f2e33af2ea0c4ca241c5bea64c933c1264900c7fe0352` |
| `agente/SafeUpload.Agent.Core/Infrastructure/Extraction/PdfExtractor.cs` | `3fd666ca7d20e5746d807e7a6f46a5c954f7dcd4b38931559081147168d9dbc3` |
| `agente/SafeUpload.Agent.Core/Infrastructure/Extraction/PlainTextExtractor.cs` | `b81b1dd3373645083eb73cc5d52aeb348f9098a906b38fb8d3fb8406615b9439` |
| `agente/SafeUpload.Agent.Core/Infrastructure/HttpPolicyStore.cs` | `9a7feae82cc4e5b62163d9a090eeb75032daff06c66bd2636da43cf6abf4dbb4` |
| `agente/SafeUpload.Agent.Core/Infrastructure/LocalPolicyStore.cs` | `b3d295e4189a1662429e3e26cf0c77dc1c79239666d3c03a0ae7d337a0563b52` |
| `agente/SafeUpload.Agent.Core/Infrastructure/LocalQueueAuditSink.cs` | `49ebe5eac0342aec615ac59362768bb333bde24b0ea20e138e6f179d18d87aee` |
| `agente/SafeUpload.Agent.Core/Infrastructure/PolicyDocument.cs` | `1bf23c0d075858db00fc8f063ababb342ea928567f9827bead00b4880cfec6e1` |
| `agente/SafeUpload.Agent.Core/Infrastructure/ProtectedPolicyAcl.cs` | `5276d72f3575b0bfdb4cb979f503e12d1e2cea56aa806555df46446e6954de3c` |
| `agente/SafeUpload.Agent.Core/SafeUpload.Agent.Core.csproj` | `70be49c2e6f33eaadd27bcacea45cad4d1e9c79edabfb9959370645934881344` |
| `agente/SafeUpload.Agent.Minifilter/AdmissionCoverage.cs` | `959c24e576032ea244e051fc9ad74461859f073af06c37d1acff6fa3899adb19` |
| `agente/SafeUpload.Agent.Minifilter/AdmissionEvidence.cs` | `33814c50610567c43ed55aa20db77b928398940323e65c41e3d137c31de889ac` |
| `agente/SafeUpload.Agent.Minifilter/DriverDiagnostics.cs` | `b64731f92c5fd8476ca50fe359461fa2907c7af73dfb2a523bcedada29883f6a` |
| `agente/SafeUpload.Agent.Minifilter/FilterPort.cs` | `f752d17cc002d6865850739dac232e3128156efe8b2177308915e419ce6f71f2` |
| `agente/SafeUpload.Agent.Minifilter/NtPathTranslator.cs` | `d24dcf21c8b18567db01a6b50eb19fd3956d15cc4c1f078105024f8e73055667` |
| `agente/SafeUpload.Agent.Minifilter/PolicyBuilder.cs` | `69407c698695324ccb607806b76bb93b2e3b02808c20ab51e2f03b0b647c6b63` |
| `agente/SafeUpload.Agent.Minifilter/Protocol.cs` | `865120edcaa5ec9dad587e5223e221f2ae93597e68990ac32b261bcbc4c60222` |
| `agente/SafeUpload.Agent.Minifilter/ReadySignal.cs` | `92645f5f4484dcccc1982e2ec0da84201bcea4337e32bd15682cf6b7e1f1edb2` |
| `agente/SafeUpload.Agent.Minifilter/SafeUpload.Agent.Minifilter.csproj` | `72437f7fecfa5b75a1058602554f94d66ed5929c1957850aba159003b5e6bd84` |
| `agente/SafeUpload.Agent.Minifilter/StagedProofProxy.cs` | `2da74b2dc6e95f1567e09d9f9972b4926d7d159cb495f4c591a3e74223b45b02` |
| `agente/SafeUpload.Agent.Network/Certificates/CertificateAuthorityOptions.cs` | `4718ba74de291f74063fc66ac96b9b975de1af907dc4e15008075c251dead739` |
| `agente/SafeUpload.Agent.Network/Certificates/FirefoxEnterpriseRoots.cs` | `817f38d525977123fcc81d3acce742187b8a6f48e9e9cde9a34957200de0e961` |
| `agente/SafeUpload.Agent.Network/Certificates/HostCertificateFactory.cs` | `19574de860ae0546200be442d8222234b840e52a1ffc7e5ec9d8061a8c09781e` |
| `agente/SafeUpload.Agent.Network/Certificates/MachineCertificateAuthority.cs` | `7ebf04d36b58e293159e4420fcf11b8e92050448314f77615d31b7411465fdf6` |
| `agente/SafeUpload.Agent.Network/Certificates/RevocationListPublisher.cs` | `d502fac57e064cfc77d3d8a152fd5dfc77b3efc5565ec391a16911e7ff549b26` |
| `agente/SafeUpload.Agent.Network/Diversion/BrowserEgressFilter.cs` | `45ca46653af9f72e2ba5a282317ab340fdafa0384f854b59d8dbbea82cf2d388` |
| `agente/SafeUpload.Agent.Network/Diversion/BrowserProxyPolicies.cs` | `59288688c5bf58bec0595d1abca29628f66128b94c42accec6ce9914b32a1cac` |
| `agente/SafeUpload.Agent.Network/Diversion/WfpNative.cs` | `63859850c09e012150b6baff1587dd18b5e1d3e42e6a483c5917ee143b7466cd` |
| `agente/SafeUpload.Agent.Network/Http/HttpHeaders.cs` | `f8da7be8ce1de8ec47a6cf3953ee702a66360be7994fe081de5bf42214f6e3f4` |
| `agente/SafeUpload.Agent.Network/Http/HttpMessageHead.cs` | `bef28844d05d7d68f9602b868ba5073c1387e9a8a3c7780982977b6a25f1c619` |
| `agente/SafeUpload.Agent.Network/Http/HttpStreamReader.cs` | `f11143e27695b2dd968db5ed05ce98b5480e3f63e1093bd74478ed858e4c1fce` |
| `agente/SafeUpload.Agent.Network/Proxy/IUploadInspector.cs` | `1470046bef18b19d776fcc5c6b793c31905542f1201e6d84a6ee64e13bfd44ee` |
| `agente/SafeUpload.Agent.Network/Proxy/PrefixedStream.cs` | `79e5afbbdc0c1d9c09a5b23703cf071c9b5fab7eb71f8b474a9951081f15f560` |
| `agente/SafeUpload.Agent.Network/Proxy/TcpConnectionOwner.cs` | `fe359eee39632c59a8704fda2118db14b08adc53990c6db29fbdaf2563d82c66` |
| `agente/SafeUpload.Agent.Network/Proxy/TlsInspectionProxy.cs` | `ba78aa4def155c43c73bc928c5e2b894dbd93b15f5ec70fa909452b70f32cf24` |
| `agente/SafeUpload.Agent.Network/Proxy/TlsInspectionProxyOptions.cs` | `d755213302e5880578fded917a36b209eaa041bb40a2b840ee02549234570337` |
| `agente/SafeUpload.Agent.Network/SafeUpload.Agent.Network.csproj` | `2ffc11718d27cdece5b2847f34ecb49dd343d78337fb1be62df9c4594ef56177` |
| `agente/SafeUpload.Agent.Service/Clipboard/ClipboardCopyStore.cs` | `8c5efb358456689c70c9bdaf8638e46f50510a2a20f75882a77f9abef4fe510d` |
| `agente/SafeUpload.Agent.Service/Clipboard/ClipboardMetrics.cs` | `1a490bfcd0b54e2d26732f41fc90db6eb5daa7423e38b94a93e2f2f82388f60e` |
| `agente/SafeUpload.Agent.Service/Clipboard/ClipboardPipeServer.cs` | `64b6149811ca094b1cc20d26e94f46b13aa60ace1b4cf1a5faaf3afb09ac9344` |
| `agente/SafeUpload.Agent.Service/Clipboard/ClipboardService.cs` | `c73b80e7173736b761defbf0c1d89312fb9f628c002d70e915c0a1299316367e` |
| `agente/SafeUpload.Agent.Service/Diagnostics/AdmissionEvidenceCapture.cs` | `9e2ba8eada2eab518cc0b7ab09580b78b6a879b803c1ba2429aa432d5ed60b21` |
| `agente/SafeUpload.Agent.Service/Diagnostics/AdmissionEvidenceEndpoint.cs` | `82be8af611c12fc010c66efff35fa1f6c273bc704f5a145a7d921868ac40dfea` |
| `agente/SafeUpload.Agent.Service/Diagnostics/AdmissionEvidenceProtocol.cs` | `ce72ead170e767af36a3887219d413f5e6cc1b022224ad4acce9c8221fd416cf` |
| `agente/SafeUpload.Agent.Service/Diagnostics/AdmissionEvidenceRunLedger.cs` | `ad791bc1e55e09d1617bb3333d644fbfc7c575c58b38c5e3522686bff502b84d` |
| `agente/SafeUpload.Agent.Service/Diagnostics/DiagnosticsPipeServer.cs` | `0fd822bf61f8d5e69fe6c79bb10e8892db34c113c0f69a79c279e4b424aceb15` |
| `agente/SafeUpload.Agent.Service/Diagnostics/DriverDiagnosticsSource.cs` | `bd56c1bacb1f809b8158aa496d15094fee68748491af10bf8416513a4dea99d2` |
| `agente/SafeUpload.Agent.Service/Dispatch/HttpAgentDispatcher.cs` | `4ade4e34ba94a06a83ccb35ba6c132adda90e2ef2350d60799f629352c59cef5` |
| `agente/SafeUpload.Agent.Service/Interception/BootPolicyRegistryWriter.cs` | `1eea1a15f3ba29c0b0751a3c5b0470d54b0d9db06f9a84be9f4ca78ea594195c` |
| `agente/SafeUpload.Agent.Service/Interception/BootPolicySeeder.cs` | `ac6f6f608985deb0b237adc60b26d034ea9b4ca10c963f9eb79ca39b723dcb4b` |
| `agente/SafeUpload.Agent.Service/Interception/FileSystemInterceptor.cs` | `0aa3e52ae00bf95e9781eaa6cda4ce1d4c8bbac6be0950d0cef96170ae592a7b` |
| `agente/SafeUpload.Agent.Service/Interception/MinifilterInterceptor.cs` | `fae5658e09cc849dac310fa9191c3db596a250d2236a53bdcfdf51f1d6c98f10` |
| `agente/SafeUpload.Agent.Service/Interception/MinifilterPolicyFactory.cs` | `6e322619f547f1edae3baf1e9e483af40b255dc65632006f1a2c0f1e4fffce85` |
| `agente/SafeUpload.Agent.Service/Interception/StagedBackingFile.cs` | `6167cf6458f852b8d3be45d0977843fbfe2f48c4984693708055f20c37bbbe3f` |
| `agente/SafeUpload.Agent.Service/Interception/StagedDestinationFile.cs` | `15c2636a97774dac29829541e61162e6766e1893621eb7b890bacaa02f5a20e7` |
| `agente/SafeUpload.Agent.Service/Interception/StagedDiscardCleanup.cs` | `408332adc0f61afdfe88acd03804bf5159d5f61c868b98627a132edc4b04d205` |
| `agente/SafeUpload.Agent.Service/Interception/StagedHandbackCopier.cs` | `4ba24815fbb4d96d7276dc71ad273676b3641a5feebced77add7594786581b4b` |
| `agente/SafeUpload.Agent.Service/Interception/StagedJournalFile.cs` | `5f4a5ae360513425f1ff79c3ad8c0c4fc8c2b3464f416cecc43c57c42224053a` |
| `agente/SafeUpload.Agent.Service/Interception/StagedPublicationGate.cs` | `6120bbbcb62d8e091dbe8ab863c442f647a64a117771a0bd1e3c178ff2b927be` |
| `agente/SafeUpload.Agent.Service/Interception/StagedStageFile.cs` | `53f1916349dba977a935fb1dda1a9670c85a161431a0d4b4b6b3f95c5aa6d800` |
| `agente/SafeUpload.Agent.Service/Interception/StagedTransferAllocator.cs` | `bd38700f5066c9eadad9a694c01bbe428dd457395bd803e9c4050cff587a2da0` |
| `agente/SafeUpload.Agent.Service/Interception/StagedTransferJournal.cs` | `4b270eaef4616c06ba52e0b88deb701d72463dcef8ed6c9c8cc4c39893b23f8d` |
| `agente/SafeUpload.Agent.Service/Interception/StagedTransferPublisher.cs` | `48bc762cba8f7e1cac0b3125f5579f0ddb9a2b7b4894da0b3a04d91f6d996ea6` |
| `agente/SafeUpload.Agent.Service/Network/CertificateAuthorityCommand.cs` | `d8ff3793b6a38eb5d5f337eec8d613013298dda60b5815b1e16a793e43046152` |
| `agente/SafeUpload.Agent.Service/Network/DiversionCommand.cs` | `abd21c3b31d191eff89385a24c6b75871f7677a1bbb474620faf1c5698ca710f` |
| `agente/SafeUpload.Agent.Service/Network/TlsInspectionService.cs` | `8e6eb9991f5f11eeeed16eda4fd19bb2e7419355dbdd0fa351c451080c814806` |
| `agente/SafeUpload.Agent.Service/Notifications/BoundedPipeLine.cs` | `e88ed6b04ce01af1f43e1ed6b96f15682b286f9cf03d547c3610ddaf8e321e8c` |
| `agente/SafeUpload.Agent.Service/Notifications/JustificationPipeServer.cs` | `33d3ea48dbdd7af4f22f7c8beba1d6d60321f5ff7640bcc22331638b8bfb0516` |
| `agente/SafeUpload.Agent.Service/Notifications/NotificationHub.cs` | `96312b119808525c4933022b448e29fcfe475c5f540d2c646a34bed5c5cbdaef` |
| `agente/SafeUpload.Agent.Service/Notifications/NotificationPipeServer.cs` | `be11248ad1b4b9dfa44dc1d93472a758d6d6c3080ac7875fb9cc1600680cf796` |
| `agente/SafeUpload.Agent.Service/Notifications/NotificationRecord.cs` | `33732c3a1fe519e5117de65c0b43182631e738d1cd941709d0248987b8e43e1f` |
| `agente/SafeUpload.Agent.Service/Notifications/OverrideGrantDispatcher.cs` | `75cac4e2c91f6ca02b8ba314ea66ebb8c015f106409d981ece8c9fcf567b8dac` |
| `agente/SafeUpload.Agent.Service/Notifications/PendingOverrides.cs` | `fc7a91c32eccaf291b98580d746d5aaca915385f9e4c37ab8186af016ffdb366` |
| `agente/SafeUpload.Agent.Service/Notifications/SessionResolver.cs` | `965efe08229b33676a791e2ac8e8ecfe5c95cd5029d956930adc80625388c3df` |
| `agente/SafeUpload.Agent.Service/Notifications/StagedJustifications.cs` | `7fd3409684164bd7ba752a5dd1a8197238320459f63b2c1f35995a64addbb584` |
| `agente/SafeUpload.Agent.Service/Program.cs` | `517fd73cb1e12ca2d61ae5c123d8f60fab09d18e0f44ea68322a6020fd18f79a` |
| `agente/SafeUpload.Agent.Service/Properties/launchSettings.json` | `12f699891fb651aaac9405c17ad5dbc5b19cce90c460282c740cdf5a1cd18ee3` |
| `agente/SafeUpload.Agent.Service/SafeUpload.Agent.Service.csproj` | `b19e12f20363601007d9af9ec4d4456a03e4f33ea47cdc3aa8fbf809c41d6b74` |
| `agente/SafeUpload.Agent.Service/appsettings.json` | `ade4faa45582090f6a8fd302d353c51a43c70386016363b33754aec9fba5535e` |
| `agente/SafeUpload.Agent.Tests/AdmissionCoverageTests.cs` | `153cf6e862cf41f963bb5a1980c1023feaa0b96dfe5519582e9a6ac0240d943c` |
| `agente/SafeUpload.Agent.Tests/AdmissionEvidenceEndpointTests.cs` | `e58ee6a2caf6eb64f943ab24a2071d2449aeeb360b7887e58bb36f3771f9dba1` |
| `agente/SafeUpload.Agent.Tests/AdmissionEvidenceWireTests.cs` | `bdd54ada7c00629a23f7e5e19da818ef8ad94a3a4aa37f88b384fff417d48297` |
| `agente/SafeUpload.Agent.Tests/AuditTrailTests.cs` | `6a19d6ac231379f3cb9aa26113887c72cc31e633401c1e981f08f10d19f1b6b6` |
| `agente/SafeUpload.Agent.Tests/BootPolicyRegistryWriterTests.cs` | `27f35ddad6d8552275f726e932bc005b9651cbdffa5c50de55de41f66ff1ae7d` |
| `agente/SafeUpload.Agent.Tests/BootPolicySeederTests.cs` | `dbb51ed258673da0c7f8c559564357494c0da2d94a3f45988d9ff9edd3ea41bc` |
| `agente/SafeUpload.Agent.Tests/CertificateAuthorityTests.cs` | `5dcd28afa2dee0b731bae73e25e7d033345ae59b7e643ab602e9a455e02be14e` |
| `agente/SafeUpload.Agent.Tests/ClipboardPipeTests.cs` | `bcb8062a4fc96e9ea23ceea451658cca82ded6a90981168813588c42cfe82a45` |
| `agente/SafeUpload.Agent.Tests/ClipboardPolicyTests.cs` | `323af07230a4bcdbce90dc2ca4ecbe77cf3009a7b59d66e7ee4a6a37be2e3ab0` |
| `agente/SafeUpload.Agent.Tests/ClipboardProtocolTests.cs` | `b58ad0a8f80ba9efa749f5971e7869f48287343d7fb4ec73e12b4c116edef3f2` |
| `agente/SafeUpload.Agent.Tests/ClipboardRulesTests.cs` | `7ed4bb074ad658eea5b89135f78bc2677d09b20ce76d7dd1dbe242e233f61947` |
| `agente/SafeUpload.Agent.Tests/ClipboardServiceTests.cs` | `cf4b531a5483151a873661844c9629a5bd490a27a88584bed2ca17b7d770bc21` |
| `agente/SafeUpload.Agent.Tests/ContentScannerTests.cs` | `e61dcbf600fa99b6cffdf5d575fbf5481bf3d42097c21ebaff1066f095e4cd42` |
| `agente/SafeUpload.Agent.Tests/DriverDiagnosticsTests.cs` | `aa908779ecd1c35059b953bbfe182a4f3ea41b7a2a88fdd2bfb24fc477d01109` |
| `agente/SafeUpload.Agent.Tests/ExtractionTests.cs` | `28483dd4eb7392e107de0f1dcdd3ace2a8309d190083ddaceacbd5763dab21f2` |
| `agente/SafeUpload.Agent.Tests/HttpPolicyStoreTests.cs` | `a137526ad679aac8ac12b35c7838c3c4f628f387940890048b1c2410635a1e97` |
| `agente/SafeUpload.Agent.Tests/HttpStreamReaderTests.cs` | `95fd9b90ba7d184fc38b5c1cb61837d77175fb70e9ad2ca0cd4a4df7db72adef` |
| `agente/SafeUpload.Agent.Tests/InspectionServiceTests.cs` | `ec6455cf469a52db34dcfbedb489f008a2c21ba4ca078f6831f2fede356f492b` |
| `agente/SafeUpload.Agent.Tests/InspectionSharingTests.cs` | `2e17181b1ab53542a1a54a4ca63b4c581ae9207f49e3c5644fd288954e191257` |
| `agente/SafeUpload.Agent.Tests/InspectionWorkBudgetTests.cs` | `b09e832420e8c71923ea03785f83a54474e42892682e3dbc6a76bdaec795b51c` |
| `agente/SafeUpload.Agent.Tests/InstallSafeUploadAgentScriptTests.cs` | `6a628a0ebad9e9eba8d830d2235d963ef8afff3194dddaac71c681fe8d8736ba` |
| `agente/SafeUpload.Agent.Tests/JustificationInputTests.cs` | `117dfa69d85ecabd61a54514171b4f2e10e6474932f0504566a54a97f6d5435a` |
| `agente/SafeUpload.Agent.Tests/NotificationHubTests.cs` | `3fe7e7793d84efbfcb745b3c977ee1171e5f3e2183991366455b73f9bce56b1c` |
| `agente/SafeUpload.Agent.Tests/NotificationProtocolTests.cs` | `83cfcf51dfee997cd2bf2b9fb2d29d56b88f7dad3dade04e925a1b86276b88a4` |
| `agente/SafeUpload.Agent.Tests/NotificationRecordTests.cs` | `c4f49d8de7578657f193ec93aa29e1a616e91c71142f8fa52f79333c70ad61a2` |
| `agente/SafeUpload.Agent.Tests/NotificationTestHub.cs` | `5e4781a80c017d0495f63363e79525a4c9f04f6639ce561bc39de48bbca63998` |
| `agente/SafeUpload.Agent.Tests/NtPathTranslatorTests.cs` | `63a9e88180d1306f10c9d32f8275d4b0576a01b48d7c7af8ab40be065452fa8a` |
| `agente/SafeUpload.Agent.Tests/NumericWindowReferenceScanner.cs` | `e299fb69e9a2d9a3e44f952e5eb037b52b552b5b6be5a2a9cb08a48ed21807fd` |
| `agente/SafeUpload.Agent.Tests/NumericWindowTests.cs` | `06a45f38ac1c0fe83c788537d6b59ee428ff78507439c69bee10d45eec48be37` |
| `agente/SafeUpload.Agent.Tests/PlainTextDecodingTests.cs` | `8430e9fd72b0804035dddf34a7ee3c428f90a3560985c3232095f5d3d9a9b465` |
| `agente/SafeUpload.Agent.Tests/PolicyTests.cs` | `26cde67f0d5635774719f3d073ea73edc6adbc2245b048884e5df326724dd8b5` |
| `agente/SafeUpload.Agent.Tests/QueueEncodingTests.cs` | `f6c1aa88495a2d78850aed8b1c22ff3b5b38d2c40f28cda93683e8655ec71803` |
| `agente/SafeUpload.Agent.Tests/SafeUpload.Agent.Tests.csproj` | `7c64d8b444fd4c0f02c90225d7fef9d372a36550f905735769184e917870c8fd` |
| `agente/SafeUpload.Agent.Tests/StagedAttachmentV20Tests.cs` | `e2b4de7d6b6e9e1a8fb4b7c63ae09d8510e264229257723222196c39a5ca374e` |
| `agente/SafeUpload.Agent.Tests/StagedDestinationKindTests.cs` | `e41c3653087aaf65971761f14a7818a229124c02e3fff75ff9761399b5ee6480` |
| `agente/SafeUpload.Agent.Tests/StagedHandbackTests.cs` | `5150d9a7c1bb7395c99950c14daf81736bb4f454a7ebd790dfebc9554a36c4c0` |
| `agente/SafeUpload.Agent.Tests/StagedInspectionFailureTests.cs` | `4c93c96908a65fa1b36abe2431f6fb83cd4f1a7b56fa0411ea5a5a7f2226263b` |
| `agente/SafeUpload.Agent.Tests/StagedProofProxyTests.cs` | `2e719ec2c66dd1278a92b63732372d4f8d2497a525038e6489f7ee9eb8d64878` |
| `agente/SafeUpload.Agent.Tests/StagedTransferAllocatorTests.cs` | `e07204e6e30a1b06ee6bd711d2c1f7cfcddbeacff2adb67cd365939d4925b220` |
| `agente/SafeUpload.Agent.Tests/StagedTransferJournalTests.cs` | `c16dbd3a0e5098c7d0117210ba0c051794fdf6aba9c92bf150ead30bea8de65d` |
| `agente/SafeUpload.Agent.Tests/StagedTransferPublisherTests.cs` | `81cd4dddbc787e0f248f2c5847b4ab70c860210d06578255b2b3a543c892ee99` |
| `agente/SafeUpload.Agent.Tests/TaintQualificationPolicyTests.cs` | `e712dd272d28aea5d77d68ede13b87a294a9467771f74fd171901cd9f7b44447` |
| `agente/SafeUpload.Agent.Tests/TestPrivileges.cs` | `422099339e499c01362bce9adf528dd9c54c5f1fcb5660e7047efbf9489a817f` |
| `agente/SafeUpload.Agent.Tests/TestWorkspace.cs` | `8e7cb393bbafc475bc96fe154083cfba371279ffea2e47bc18a166dab9ebfa64` |
| `agente/SafeUpload.Agent.Tests/TlsInspectionProxyTests.cs` | `fa32a3c8b1757979693440174d1af5ac7a00a46fdf5a0d14d6c5e0dc983f2cc9` |
| `agente/SafeUpload.Agent.Tests/TrafficDiversionTests.cs` | `e6bec7414b355151d47af513acf2547f3577cc132084c2bd666bbd02ac5b1b5a` |
| `agente/SafeUpload.Agent.Tests/ValidatorTests.cs` | `55819e8f29f0aed1e7c1a4760bd9d96fae535d5303a1420a6e3eb806866ac783` |
| `agente/SafeUpload.Agent.Tests/VerdictCacheTests.cs` | `f0a002afb6fd1b61d42a1c8a7f0988f7da61f3d5dd5c4fdcf62143d35684d1bc` |
| `agente/SafeUpload.Agent.sln` | `51119097c175e1395122b810f236ce25c54c7ed518723337cc510b2ad2057493` |
| `agente/SafeUpload.Fixtures/Program.cs` | `9168f308198cea042f3a57173d29c6bd001c8bee46d7e12a497ed6468b6e9567` |
| `agente/SafeUpload.Fixtures/SafeUpload.Fixtures.csproj` | `1d7214dd8aa5bc1d6f05d1517ac1dab8b2cbe95abcec16b57ddbba699f54636c` |
| `agente/SafeUpload.Minifilter.Probe/Program.cs` | `d6cfde5c152d91ec0912621507962e4e7cb8e6af71abdbb0204c7d7de9857551` |
| `agente/SafeUpload.Minifilter.Probe/SafeUpload.Minifilter.Probe.csproj` | `4481fdd135d2021111a3221fc5fe9e782982833696304c2341ecf4c3b94d6a71` |
| `agente/SafeUploadAgent/App.xaml` | `3433751ae980ab14405934e5e73d2b30afa4f49a75a33d926e8989b47b9372e7` |
| `agente/SafeUploadAgent/App.xaml.cs` | `16faa6bdde28b4d34e538bf048e10ecdc9fee9af4887bca016bd2877d8e67d04` |
| `agente/SafeUploadAgent/MainWindow.xaml` | `e7a732be7ce2d8978c09682cc7483a89cfa557c07d6948513e20532a8d83b475` |
| `agente/SafeUploadAgent/MainWindow.xaml.cs` | `41b8b7555609b0343cfcdb6b9f0bb85af4191d854fb2f42bcc3849be784a14f7` |
| `agente/SafeUploadAgent/SafeUploadAgent.csproj` | `e185957afbde0572986b6382f338ea4a0d13935ef65a66cf949538b033eca63d` |
| `agente/scripts/Get-SafeUploadDiagnostics.ps1` | `e5dba7e3f69d8e2a5b4d5fac91be776c2047bc250d5a4f4310b7152fe7a95d20` |
| `agente/scripts/Install-SafeUploadAgent.ps1` | `d8795788b410c03cbdd377cf39865037e8e8013e72e60e7d41007beae1c5a071` |
| `agente/scripts/Protect-SafeUploadPolicy.ps1` | `5004cca415d5f993f6e89e47ae5ffdf4b52ea07d31b85bf8231968d08e4b0a23` |
