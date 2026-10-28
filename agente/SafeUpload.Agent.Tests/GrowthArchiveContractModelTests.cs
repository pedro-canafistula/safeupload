#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SafeUpload.Agent.Tests;

// Revision-8 pure reference models. No product types, I/O, Windows or unfinished
// codecs. JSON tests measure the real default writer, not a schema-3 maximum.
public sealed class GrowthArchiveContractModelTests
{
    private const int EnvelopeLimit = 131072, ControlLimit = 65536, SegmentLimit = 4194304;
    private static readonly Guid Installation = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid Segment = Guid.Parse("22222222-2222-2222-2222-222222222222");
    private static readonly Guid RecordId = Guid.Parse("33333333-3333-3333-3333-333333333333");
    private static readonly Guid Transfer = Guid.Parse("44444444-4444-4444-4444-444444444444");
    private static readonly Guid Transaction = Guid.Parse("55555555-5555-5555-5555-555555555555");
    private static readonly string[] Properties = ["FormatVersion", "ResourceSchema", "InstallationId", "RecordKind",
        "RecordId", "TransferId", "RecordRevision", "PreviousRecordId", "Entry", "ResourceClosure",
        "OrdinaryDiscardDisposal", "ResolutionDelta", "LegacySource"];

    [Theory]
    [InlineData(1192, 1592)]
    [InlineData(1272, 1696)]
    [InlineData(72, 96)]
    public void Actual_base64_lengths_and_default_writer_escaping(int bytes, int chars)
    {
        byte[] source = Enumerable.Repeat((byte)0xfb, bytes).ToArray();
        string value = Convert.ToBase64String(source);
        Assert.Equal(chars, value.Length);
        Assert.Equal(source, Decode64(value, bytes));
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(value);
        Assert.True(json.Length > chars + 2); // '+' is escaped by the actual default writer.
        Assert.Equal(value, JsonSerializer.Deserialize<string>(json));
    }

    [Theory]
    [InlineData("AA== ")]
    [InlineData("AB==")]
    [InlineData("AA")]
    [InlineData("AA==\n")]
    public void Noncanonical_base64_mutants_are_rejected(string value) =>
        Assert.ThrowsAny<Exception>(() => Decode64(value, 1));

    [Fact]
    public void Actual_envelope_serialization_fits_exact_limit_and_refuses_one_byte_more()
    {
        int empty = Envelope("\"\"", "null").Length;
        byte[] exact = Envelope(JsonSerializer.Serialize(new string('a', EnvelopeLimit - empty)), "null");
        Assert.Equal(EnvelopeLimit, exact.Length);
        ValidateEnvelope(exact);
        byte[] over = Envelope(JsonSerializer.Serialize(new string('a', EnvelopeLimit - empty + 1)), "null");
        Assert.Throws<InvalidDataException>(() => ValidateEnvelope(over));
    }

    [Theory]
    [InlineData(65536)]
    [InlineData(131072)]
    public void Bounded_writer_counts_real_encoded_bytes_before_create(int limit)
    {
        int nativeCreates = 0;
        void Admit(string text)
        {
            byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(text);
            Need(bytes.Length <= limit);
            nativeCreates++;
        }
        Admit(new string('a', limit - 2));
        Assert.Throws<InvalidDataException>(() => Admit(new string('a', limit - 1)));
        Assert.Equal(1, nativeCreates);
        Assert.Equal(3074, JsonSerializer.SerializeToUtf8Bytes(new string('\u0001', 512)).Length);
        Assert.Throws<InvalidDataException>(() => Admit(new string('\u0001', limit / 6 + 1)));
    }

    [Theory]
    [InlineData("duplicate")]
    [InlineData("escaped-duplicate")]
    [InlineData("nested-duplicate")]
    [InlineData("unknown")]
    [InlineData("missing")]
    [InlineData("fraction")]
    [InlineData("exponent")]
    [InlineData("numeric-string")]
    [InlineData("overflow")]
    [InlineData("wrong-kind")]
    [InlineData("trailing")]
    [InlineData("bom")]
    [InlineData("utf8")]
    [InlineData("depth")]
    public void Strict_envelope_mutants_cannot_become_candidates(string mutation)
    {
        string valid = Encoding.UTF8.GetString(Envelope("{}", "{}"));
        string changed = mutation switch
        {
            "duplicate" => valid.Replace("\"FormatVersion\":2", "\"FormatVersion\":2,\"FormatVersion\":2", StringComparison.Ordinal),
            "escaped-duplicate" => valid.Replace("\"FormatVersion\":2", "\"FormatVersion\":2,\"\\u0046ormatVersion\":2", StringComparison.Ordinal),
            "nested-duplicate" => valid.Replace("\"Entry\":{}", "\"Entry\":{\"x\":1,\"x\":2}", StringComparison.Ordinal),
            "unknown" => valid.Replace("\"Entry\":{}", "\"Extra\":null,\"Entry\":{}", StringComparison.Ordinal),
            "missing" => valid.Replace("\"Entry\":{},", "", StringComparison.Ordinal),
            "fraction" => valid.Replace("\"RecordRevision\":1", "\"RecordRevision\":1.0", StringComparison.Ordinal),
            "exponent" => valid.Replace("\"RecordRevision\":1", "\"RecordRevision\":1e0", StringComparison.Ordinal),
            "numeric-string" => valid.Replace("\"RecordRevision\":1", "\"RecordRevision\":\"1\"", StringComparison.Ordinal),
            "overflow" => valid.Replace("\"RecordRevision\":1", "\"RecordRevision\":9223372036854775808", StringComparison.Ordinal),
            "wrong-kind" => valid.Replace("\"RecordKind\":1", "\"RecordKind\":5", StringComparison.Ordinal),
            "trailing" => valid + "{}",
            "depth" => valid.Replace("\"Entry\":{}", "\"Entry\":" + new string('[', 17) + "0" + new string(']', 17), StringComparison.Ordinal),
            _ => valid
        };
        byte[] bytes = Encoding.UTF8.GetBytes(changed);
        if (mutation == "bom") bytes = [0xef, 0xbb, 0xbf, .. bytes];
        if (mutation == "utf8") bytes[10] = 0xff;
        Assert.ThrowsAny<Exception>(() => ValidateEnvelope(bytes));
    }

    [Fact]
    public void Full_independent_nested_maxima_are_refused_by_actual_writer_length()
    {
        string entry = JsonSerializer.Serialize(new string('e', EnvelopeLimit - 2));
        string closure = JsonSerializer.Serialize(new string('s', ControlLimit - 2));
        byte[] bytes = Envelope(entry, closure);
        Assert.True(bytes.Length > EnvelopeLimit);
        Assert.Throws<InvalidDataException>(() => ValidateEnvelope(bytes));
        Assert.True(Envelope("null", closure).Length < EnvelopeLimit);
    }

    [Fact]
    public void Full_ack_byte_fields_and_32_by_32_control_arrays_are_measured()
    {
        byte[] delta = JsonSerializer.SerializeToUtf8Bytes(new
        {
            State = 6, OriginalRequest = Convert.ToBase64String(new byte[1192]), FenceId = Transaction,
            OriginCookie = ulong.MaxValue, KernelAckControlRequest = Convert.ToBase64String(new byte[1272]),
            KernelAckControlReply = Convert.ToBase64String(new byte[72]), ResolutionRevision = long.MaxValue
        });
        Assert.InRange(delta.Length, 3500, 8192);
        var rows = Enumerable.Range(1, 32).Select(n => new
        {
            Number = uint.MaxValue - (uint)n, Identity = new { VolumeSerialNumber = ulong.MaxValue,
                FileIdHigh = ulong.MaxValue, FileIdLow = ulong.MaxValue }, FrontierSequence = ulong.MaxValue,
            End = SegmentLimit, Format = 3, CreationPhase = 4
        }).ToArray();
        byte[] control = JsonSerializer.SerializeToUtf8Bytes(new
        {
            Version = 3, TransactionId = Transaction, InstallationId = Installation,
            ExpectedInventoryIdentity = rows[0].Identity,
            ExpectedInventoryBytes = Convert.ToBase64String(new byte[128]), SourceInventoryFormat = 3,
            ExpectedLegacyInventory = (object?)null, Phase = 4, Sources = rows, Targets = rows,
            NewFirstSelected = uint.MaxValue - 31, NewRangeEnd = uint.MaxValue,
            ReservedPhysicalGrowth = long.MaxValue
        });
        Assert.Equal(15182, control.Length);
        Assert.True(control.Length <= ControlLimit);
        // Synthetic maximal row spelling, not the absent product schema-3 serializer.
    }

    [Theory]
    [InlineData(4096)]
    [InlineData(8192)]
    [InlineData(16384)]
    [InlineData(32768)]
    [InlineData(65536)]
    public void Actual_frame_buffers_parse_at_boundary_lengths(int alignment)
    {
        foreach (int length in new[] { 1, 4036, 4037, 65536, 131072 })
        {
            byte[] payload = Enumerable.Repeat((byte)'x', length).ToArray();
            byte[] frame = Frame(payload, alignment);
            Assert.Equal(payload, ReadFrame(frame, alignment, RecordId));
            Assert.Equal(0, frame.Length % alignment);
        }
    }

    [Fact]
    public void Rehashed_frame_with_changed_payload_record_id_still_refuses_selection()
    {
        byte[] payload = Envelope("{}", "{}");
        ReadEnvelopeFrame(Frame(payload, 4096));
        string changed = Encoding.UTF8.GetString(payload).Replace(RecordId.ToString("D"), Transfer.ToString("D"), StringComparison.Ordinal);
        byte[] frame = Frame(Encoding.UTF8.GetBytes(changed), 4096);
        // Native header and payload digest are valid; inner identity binding is wrong.
        Assert.Throws<InvalidDataException>(() => ReadEnvelopeFrame(frame));
    }

    [Theory]
    [InlineData("magic")]
    [InlineData("version")]
    [InlineData("length")]
    [InlineData("record")]
    [InlineData("digest")]
    [InlineData("payload")]
    [InlineData("padding")]
    [InlineData("short")]
    [InlineData("extra")]
    public void Byte_frame_mutants_are_rejected(string mutation)
    {
        byte[] frame = Frame([1, 2, 3], 4096);
        switch (mutation)
        {
            case "magic": frame[0] ^= 1; break;
            case "version": frame[4] = 1; break;
            case "length": BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(8), 131073); break;
            case "record": frame[12] ^= 1; break;
            case "digest": frame[28] ^= 1; break;
            case "payload": frame[60] ^= 1; break;
            case "padding": frame[63] = 1; break;
            case "short": frame = frame[..^1]; break;
            case "extra": frame = [.. frame, 0]; break;
        }
        Assert.Throws<InvalidDataException>(() => ReadFrame(frame, 4096, RecordId));
    }

    [Theory]
    [InlineData("installation")]
    [InlineData("identity")]
    [InlineData("alignment")]
    [InlineData("slot")]
    [InlineData("parity")]
    [InlineData("padding")]
    [InlineData("digest")]
    [InlineData("end")]
    public void Frontier_mutants_fail_even_with_recomputed_hash_where_applicable(string mutation)
    {
        byte[] slot = Slot(4096, 1, 8192, Guid.Empty);
        switch (mutation)
        {
            case "installation": slot[16] ^= 1; break;
            case "identity": slot[32] ^= 1; break;
            case "alignment": slot[56] ^= 1; break;
            case "slot": slot[60] = 1; break;
            case "parity": BinaryPrimitives.WriteUInt64LittleEndian(slot.AsSpan(64), 2); break;
            case "padding": slot[128] = 1; break;
            case "digest": slot[96] ^= 1; break;
            case "end": BinaryPrimitives.WriteInt64LittleEndian(slot.AsSpan(72), 8193); break;
        }
        if (mutation != "digest") SHA256.HashData(slot.AsSpan(0, 96)).CopyTo(slot.AsSpan(96));
        Assert.Throws<InvalidDataException>(() => ReadSlot(slot, 4096, 0));
    }

    [Theory]
    [InlineData(1, 2)]
    [InlineData(2, 3)]
    [InlineData(100, 101)]
    public void Independent_slot_selection_accepts_only_adjacent_monotonic_frontiers(ulong older, ulong newer)
    {
        Guid OldTransaction = older == 1 ? Guid.Empty : Segment;
        byte[] old = Slot(4096, older, checked(8192 + (int)(older - 1) * 4096), OldTransaction);
        byte[] next = Slot(4096, newer, checked(8192 + (int)(newer - 1) * 4096), Transaction);
        Frontier selected = older % 2 == 1 ? SelectSlots(old, next) : SelectSlots(next, old);
        Assert.Equal(newer, selected.Sequence);
    }

    [Fact]
    public void Zeroed_inactive_slot_is_not_a_valid_rollback_after_initialization()
    {
        Assert.Throws<InvalidDataException>(() => SelectSlots(Slot(4096, 3, 16384, Transaction), new byte[4096]));
        Assert.Throws<InvalidDataException>(() => SelectSlots(Slot(4096, 1, 8192, Guid.Empty), Slot(4096, 4, 20480, Transaction)));
    }

    [Theory]
    [InlineData(false, false, "Hold")]
    [InlineData(false, true, "Hold")]
    [InlineData(true, false, "Hold")]
    [InlineData(true, true, "FrontierOnly")]
    public void Torn_slot_and_complete_tail_require_exact_intent_and_candidate(bool intent, bool candidate, string expected)
    {
        byte[] frame = Frame([1], 4096);
        var plan = new AppendPlan(1, 8192, 2, 8192 + frame.Length, Transaction);
        byte[] torn = Slot(4096, 2, plan.TargetEnd, Transaction); torn[96] ^= 1;
        Assert.Equal(expected, Recover(Slot(4096, 1, 8192, Guid.Empty), torn,
            frame, intent ? plan : null, candidate ? frame : [9]));
    }

    [Fact]
    public void Recovery_interrupted_twice_never_reappends_full_exact_tail()
    {
        byte[] frame = Frame([1, 2], 4096);
        var plan = new AppendPlan(1, 8192, 2, 8192 + frame.Length, Transaction);
        byte[] old = Slot(4096, 1, 8192, Guid.Empty), target = Slot(4096, 2, plan.TargetEnd, Transaction);
        var archive = new MigrationModel([Base()], 100, 200, 300);
        archive.Copy(Base());
        for (int crash = 0; crash < 2; crash++)
            Assert.Equal("FrontierOnly", Recover(old, new byte[4096], frame, plan, frame));
        Assert.Equal("BookkeepingOnly", Recover(old, target, frame, plan, frame));
        Assert.Equal(1, archive.NativeCopies);
        archive.Copy(Base());
        Assert.Equal(1, archive.NativeCopies);
    }

    [Theory]
    [InlineData("partial")]
    [InlineData("extra-tail")]
    [InlineData("wrong-offset")]
    [InlineData("wrong-sequence")]
    [InlineData("changed-candidate")]
    [InlineData("frontier-gap")]
    [InlineData("same-sequence-fork")]
    public void Tail_selection_mutants_hold_without_truncating_or_refunding(string mutation)
    {
        byte[] frame = Frame([1, 2], 4096);
        var plan = new AppendPlan(1, 8192, 2, 12288, Transaction);
        byte[] old = Slot(4096, 1, 8192, Guid.Empty), other = new byte[4096], candidate = frame;
        switch (mutation)
        {
            case "partial": frame = frame[..100]; break;
            case "extra-tail": frame = [.. frame, .. new byte[4096]]; break;
            case "wrong-offset": plan = plan with { ExpectedEnd = 12288 }; break;
            case "wrong-sequence": plan = plan with { ExpectedSequence = 9 }; break;
            case "changed-candidate": candidate = Frame([2, 1], 4096); break;
            case "frontier-gap": other = Slot(4096, 4, 16384, Transaction); break;
            case "same-sequence-fork": other = Slot(4096, 1, 12288, Transaction); break;
        }
        Assert.Equal("Hold", Recover(old, other, frame, plan, candidate));
    }

    [Theory]
    [InlineData("unknown-identity")]
    [InlineData("wrong-record")]
    [InlineData("wrong-leaf")]
    [InlineData("changed-bytes")]
    [InlineData("preidentity")]
    public void Candidate_mutants_have_no_authority(string mutation)
    {
        byte[] payload = Envelope("{}", "{}");
        var candidate = new Candidate(Segment, RecordId, RecordId.ToString("N") + ".resource", 1, payload);
        Candidate changed = mutation switch
        {
            "unknown-identity" => candidate with { Identity = null },
            "wrong-record" => candidate with { Record = Transfer },
            "wrong-leaf" => candidate with { Leaf = "../" + candidate.Leaf },
            "changed-bytes" => candidate with { Bytes = Envelope("{\"x\":1}", "{}") },
            _ => candidate with { Phase = 4 } // CreationMayHaveStarted, not Prepared=1.
        };
        Assert.False(CandidateMatches(changed, Segment, RecordId, payload));
        Assert.True(CandidateMatches(candidate, Segment, RecordId, payload));
    }

    [Fact]
    public void Delta_before_base_and_exact_duplicate_preserve_count_and_barriers()
    {
        History b = Base(), d = Delta(b);
        Projection projection = Project([d, b, b]);
        Assert.Equal(0, projection.Debt);
        Assert.Equal(19, projection.EffectiveGeneration);
        Assert.Equal(23, projection.AllocationGeneration);
        Assert.True(Equivalent([b, d], [d, b, b]));
        Assert.False(Equivalent([b, d], [b])); // Removing ACK restores debt.
    }

    [Theory]
    [InlineData("changed-record")]
    [InlineData("two-bases")]
    [InlineData("orphan")]
    [InlineData("gap")]
    [InlineData("fork")]
    [InlineData("wrong-original")]
    [InlineData("wrong-fence")]
    [InlineData("wrong-cookie")]
    [InlineData("unauthenticated")]
    [InlineData("success-base")]
    [InlineData("already-acked")]
    public void Chain_mutants_cannot_erase_debt_or_witnesses(string mutation)
    {
        History b = Base(), d = Delta(b);
        History[] records = mutation switch
        {
            "changed-record" => [b, b with { Bytes = "changed" }],
            "two-bases" => [b, b with { Id = Transaction }],
            "orphan" => [d],
            "gap" => [b, d with { Revision = 12 }],
            "fork" => [b, d, d with { Id = Segment }],
            "wrong-original" => [b, d with { Original = "changed" }],
            "wrong-fence" => [b, d with { Fence = Segment }],
            "wrong-cookie" => [b, d with { Cookie = 1 }],
            "unauthenticated" => [b, d with { Authenticated = false }],
            "success-base" => [b with { State = 7 }, d],
            _ => [b with { State = 6 }, d]
        };
        Assert.Throws<InvalidDataException>(() => Project(records));
    }

    [Theory]
    [InlineData(false, false, 300)]
    [InlineData(true, false, 300)]
    [InlineData(true, true, 200)]
    public void Selection_and_actual_release_are_separate(bool selected, bool persistedRelease, int expected)
    {
        var migration = new MigrationModel([Base()], 100, 200, 300);
        migration.Copy(Base());
        if (selected) migration.Select();
        if (selected && persistedRelease) migration.ReleaseSource(persisted: true, identity: Segment);
        else Assert.Throws<InvalidDataException>(() => migration.ReleaseSource(persistedRelease, Segment));
        Assert.Equal(expected, migration.Charge);
        Assert.False(Equivalent([Base()], [Base() with { AllocationGeneration = 22 }]));
    }

    [Theory]
    [InlineData(1, 4, 2, 2, 3, 6)]
    [InlineData(1, 4, 4, 2, 5, 6)]
    [InlineData(9, 40, 32, 32, 41, 72)]
    public void Selected_range_preserves_untouched_suffix_and_consecutive_targets(
        uint first, uint end, uint sources, uint targets, uint expectedFirst, uint expectedEnd)
    {
        Assert.Equal((expectedFirst, expectedEnd), Select(first, end, sources, targets));
    }

    [Fact]
    public void Overflow_and_missing_selected_suffix_refuse_selection()
    {
        Assert.ThrowsAny<Exception>(() => Select(1, uint.MaxValue, 1, 1));
        Assert.False(Enumerable.Range(3, 4).All(new HashSet<int> { 3, 5, 6 }.Contains));
        Assert.Throws<InvalidDataException>(() => Select(1, 2, 3, 1));
    }

    [Fact]
    public void Legacy_max_payload_can_be_valid_but_unrepresentable_without_losing_source()
    {
        string entry = JsonSerializer.Serialize(new string('a', EnvelopeLimit - 2));
        byte[] wrapped = Envelope(entry, "null", kind: 4);
        Assert.True(wrapped.Length > EnvelopeLimit);
        bool selected = false;
        Assert.Throws<InvalidDataException>(() => { ValidateEnvelope(wrapped); selected = true; });
        Assert.False(selected);
    }

    [Theory]
    [InlineData("frontier-version")]
    [InlineData("frame-version")]
    [InlineData("frontier-hash")]
    [InlineData("payload")]
    [InlineData("uncommitted-tail")]
    [InlineData("duplicate-transfer")]
    public void Legacy_classifier_never_repairs_or_relabels_corrupt_bytes(string mutation)
    {
        byte[] legacy = LegacySegment([Encoding.UTF8.GetBytes("{\"saved\":true}")]);
        Assert.Single(ReadLegacy(legacy));
        switch (mutation)
        {
            case "frontier-version": legacy[4] = 3; break;
            case "frame-version": legacy[4100] = 3; break;
            case "frontier-hash": legacy[16] ^= 1; break;
            case "payload": legacy[4156] ^= 1; break;
            case "uncommitted-tail": legacy = [.. legacy, 1]; break;
            case "duplicate-transfer":
                legacy = LegacySegment([Encoding.UTF8.GetBytes("{}"), Encoding.UTF8.GetBytes("{}")]);
                legacy.AsSpan(4108, 16).CopyTo(legacy.AsSpan(4170, 16)); break;
        }
        byte[] retained = legacy.ToArray();
        Assert.Throws<InvalidDataException>(() => ReadLegacy(legacy));
        Assert.Equal(retained, legacy); // Read-only classifier preserves the failed evidence.
    }

    [Fact]
    public void Legacy_payload_bytes_survive_wrapping_and_preflight_refuses_expansion()
    {
        byte[][] payloads = [Encoding.UTF8.GetBytes("{\"saved\":true}"), Encoding.UTF8.GetBytes("{\"saved\":false}")];
        byte[] legacy = LegacySegment(payloads);
        var parsed = ReadLegacy(legacy);
        Assert.Equal(2, parsed.Length);
        for (int n = 0; n < parsed.Length; n++)
        {
            Assert.Equal(payloads[n], parsed[n]);
            using JsonDocument wrapped = JsonDocument.Parse(Envelope(Encoding.UTF8.GetString(parsed[n]), "null", 4));
            Assert.Equal(parsed[n], Encoding.UTF8.GetBytes(wrapped.RootElement.GetProperty("Entry").GetRawText()));
        }
        // The old admitted 4 MiB segment need not fit one aligned target after wrapping.
        int oldCount = (SegmentLimit - 4096) / (60 + payloads[0].Length);
        long required = 8192L + (long)oldCount * Frame(Envelope(Encoding.UTF8.GetString(payloads[0]), "null", 4), 4096).Length;
        Assert.True(required > SegmentLimit);
        long targetCount = (required + SegmentLimit - 1) / SegmentLimit;
        Assert.True(targetCount > 32);
        Assert.Throws<InvalidDataException>(() => Need(targetCount <= 32));
    }

    [Theory]
    [InlineData("prepared")]
    [InlineData("native-complete")]
    [InlineData("frontier-committed")]
    [InlineData("cursor-advanced")]
    public void Legacy_cursor_recovers_the_same_assignment_without_second_copy(string crash)
    {
        byte[] payload = Encoding.UTF8.GetBytes("{\"saved\":true}");
        var cursor = new LegacyCursorModel(payload);
        Guid id = cursor.Prepare();
        if (crash != "prepared") cursor.Append();
        if (crash is "frontier-committed" or "cursor-advanced") cursor.CommitFrontier();
        if (crash == "cursor-advanced") cursor.Advance();
        cursor = cursor.Restart();
        if (!cursor.Finished)
        {
            Assert.Equal(id, cursor.Prepare());
            cursor.Append(); cursor.CommitFrontier(); cursor.Advance();
        }
        Assert.Equal(1, cursor.NativeCopies);
        Assert.Equal(1, cursor.AssignedIds);
        Assert.Equal(payload, cursor.StoredEntry);
    }

    [Fact]
    public void Small_legacy_frames_at_64KiB_alignment_can_exceed_32_targets_and_hold()
    {
        int oldFrames = (SegmentLimit - 4096) / (60 + 2); // '{}' is valid JSON at the byte layer.
        long alignedTargetBytes = 131072L + (long)oldFrames * 65536;
        Assert.True(alignedTargetBytes > 32L * SegmentLimit);
        int selectedTargets = 0;
        Assert.Throws<InvalidDataException>(() =>
        {
            Need(alignedTargetBytes <= 32L * SegmentLimit);
            selectedTargets = 32;
        });
        Assert.Equal(0, selectedTargets); // Retain the old selected source and charge.
    }

    [Theory]
    [InlineData("copy")]
    [InlineData("selection")]
    [InlineData("delete")]
    public void Migration_faults_preserve_sources_witnesses_and_old_plus_new_charge(string fault)
    {
        History b = Base(), d = Delta(b);
        var migration = new MigrationModel([b, d], 100, 200, 300);
        migration.Copy(b);
        if (fault != "copy") migration.Copy(d);
        if (fault == "copy") Assert.Throws<InvalidDataException>(migration.Select);
        if (fault == "delete") migration.Select();
        Assert.Throws<InvalidDataException>(() => migration.ReleaseSource(false, Segment));
        Assert.Equal(300, migration.Charge);
        Assert.Equal(0, migration.SelectedProjection.Debt);
        // Restart derives selection from durable inventory, not a missing Selected flag.
        migration = migration.Restart();
        Assert.Equal(300, migration.Charge);
        Assert.Equal(0, migration.SelectedProjection.Debt);
    }

    [Fact]
    public void Migration_does_not_admit_copy_until_old_plus_new_charge_fits()
    {
        Assert.Throws<InvalidDataException>(() => new MigrationModel([Base()], 100, 200, 299));
        var migration = new MigrationModel([Base()], 100, 200, 300);
        Assert.Throws<InvalidDataException>(() => migration.ReleaseSource(true, Segment));
        migration.Copy(Base()); migration.Select();
        Assert.Throws<InvalidDataException>(() => migration.ReleaseSource(true, Transfer));
        migration.ReleaseSource(true, Segment); migration.ReleaseSource(true, Segment);
        Assert.Equal(200, migration.Charge); // Same persisted release is idempotent.
    }

    [Theory]
    [InlineData("missing-ack")]
    [InlineData("changed-bytes")]
    [InlineData("missing-base")]
    public void Migration_selection_mutants_cannot_drop_witnesses(string mutation)
    {
        History b = Base(), d = Delta(b);
        var migration = new MigrationModel([b, d], 100, 200, 300);
        if (mutation != "missing-base") migration.Copy(mutation == "changed-bytes" ? b with { Bytes = "changed" } : b);
        if (mutation != "missing-ack") migration.Copy(d);
        Assert.Throws<InvalidDataException>(migration.Select);
        Assert.Equal(300, migration.Charge);
        Assert.Equal(0, migration.SelectedProjection.Debt);
    }

    [Theory]
    [InlineData("identity")]
    [InlineData("incarnation")]
    [InlineData("claim")]
    [InlineData("reader")]
    [InlineData("section")]
    [InlineData("operation")]
    [InlineData("persistence")]
    [InlineData("promoted")]
    public void Physical_release_mutants_retain_charge_and_slot(string mutation)
    {
        var current = new ReleaseClaim(Segment, 3, 9, 0, 0, 0, true, false);
        ReleaseClaim proof = mutation switch
        {
            "identity" => current with { Identity = Transfer },
            "incarnation" => current with { Incarnation = 2 },
            "claim" => current with { Revision = 8 },
            "reader" => current with { Readers = 1 },
            "section" => current with { Sections = 1 },
            "operation" => current with { Operations = 1 },
            "persistence" => current with { Persisted = false },
            _ => current with { PublicPromotion = true }
        };
        Assert.False(CanRelease(current, proof));
        Assert.True(CanRelease(current, current));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void Public_custody_receipt_has_exact_layout_and_survives_unsigned_identity_bits(int proofKind)
    {
        byte[] completion = PublicCompletion(proofKind);
        ValidatePublicEncoding(completion, completion: true);
        Assert.Equal(2048, completion.Length);
        Assert.Equal(2732, Convert.ToBase64String(completion).Length);
        Assert.Equal(ulong.MaxValue, BinaryPrimitives.ReadUInt64LittleEndian(completion.AsSpan(168)));
        var model = new PublicTransferModel(proofKind);
        model.NativeSuccess(); model.CompleteJournal(); model.PersistBudget(); model.Adopt();
        Assert.Equal(17408, model.Charge); // Stage remains: 4*4096 + metadata 1024.
        Assert.Throws<InvalidDataException>(model.NativeSuccess);
        Assert.Equal(1, model.Copies); Assert.Equal(1, model.Renames);
        ValidatePublicEncoding(model.Receipt!, completion: false);
    }

    [Fact]
    public void Public_transfer_maximum_leaf_and_canonical_SID_fit_exact_binary_carriers()
    {
        byte[] b = PublicCompletion(1);
        string sid = "S-1-281474976710655" + string.Concat(Enumerable.Repeat("-4294967295", 15));
        Assert.Equal(184, sid.Length);
        Carrier(b, 292, 384, new string('a', 255));
        Carrier(b, 1332, 1336, new string('a', 255));
        Carrier(b, 296, 896, sid);
        ValidatePublicEncoding(b, completion: true);
        Assert.Equal(2732, Convert.ToBase64String(b).Length);
    }

    [Theory]
    [InlineData(16)] // receipt ID
    [InlineData(32)] // installation
    [InlineData(48)] // driver
    [InlineData(64)] // transfer
    [InlineData(80)] // allocation generation
    [InlineData(88)] // destination generation
    [InlineData(96)] // original stage identity
    [InlineData(120)] // slot
    [InlineData(124)] // role
    [InlineData(128)] // incarnation
    [InlineData(136)] // claim ID
    [InlineData(152)] // claim revision
    [InlineData(160)] // acceptance revision must be current R+1
    [InlineData(168)] // delivered identity serial
    [InlineData(176)] // delivered identity low
    [InlineData(184)] // delivered identity high
    [InlineData(192)] // delivered volume root
    [InlineData(216)] // delivered parent
    [InlineData(240)] // mount GUID
    [InlineData(256)] // case mode
    [InlineData(260)] // transfer kind
    [InlineData(264)] // proof record ID
    [InlineData(280)] // proof record revision
    [InlineData(288)] // proof kind
    [InlineData(304)] // native operation ID
    [InlineData(352)] // owner epoch
    [InlineData(368)] // authorization witness
    [InlineData(384)] // delivered leaf
    [InlineData(896)] // original SID
    [InlineData(1264)] // original destination root
    [InlineData(1288)] // original destination parent
    [InlineData(1312)] // original mount
    [InlineData(1328)] // original case mode
    [InlineData(1336)] // original leaf
    [InlineData(1848)] // drain witness
    public void Public_transfer_binding_mutants_cannot_release_a_different_custody_claim(int offset)
    {
        var model = new PublicTransferModel(1);
        model.NativeSuccess(); model.CompleteJournal();
        byte[] forged = model.ExpectedReceipt(); forged[offset] ^= 1;
        Assert.Throws<InvalidDataException>(() => model.PersistBudget(forged));
        Assert.Equal(66560, model.Charge);
        Assert.Null(model.Receipt);
    }

    [Theory]
    [InlineData("size")]
    [InlineData("version")]
    [InlineData("magic")]
    [InlineData("reserved")]
    [InlineData("flags")]
    [InlineData("carrier-padding")]
    [InlineData("odd-leaf")]
    [InlineData("bad-utf16")]
    [InlineData("short")]
    [InlineData("extra")]
    [InlineData("zero-acceptance")]
    [InlineData("stage-role")]
    [InlineData("predecessor-without-flag")]
    public void Public_transfer_encoding_mutants_fail_strict_decoding(string mutation)
    {
        byte[] receipt = PublicCompletion(1);
        BinaryPrimitives.WriteInt64LittleEndian(receipt.AsSpan(160), 10);
        switch (mutation)
        {
            case "size": receipt[12] ^= 1; break;
            case "version": receipt[8] = 2; break;
            case "magic": receipt[0] ^= 1; break;
            case "reserved": receipt[1864] = 1; break;
            case "flags": receipt[344] = 2; break;
            case "carrier-padding": receipt[894] = 1; break;
            case "odd-leaf": receipt[292] |= 1; break;
            case "bad-utf16": receipt[384] = 0; receipt[385] = 0xd8; break;
            case "short": receipt = receipt[..^1]; break;
            case "extra": receipt = [.. receipt, 0]; break;
            case "zero-acceptance": receipt.AsSpan(160, 8).Clear(); break;
            case "stage-role": receipt[124] = 1; break;
            case "predecessor-without-flag": receipt[320] = 1; break;
        }
        Assert.ThrowsAny<Exception>(() => ValidatePublicEncoding(receipt, completion: false));
    }

    [Theory]
    [InlineData(1, "reply-lost")]
    [InlineData(2, "reply-lost")]
    [InlineData(3, "reply-lost")]
    [InlineData(1, "journal-reply-lost")]
    [InlineData(2, "journal-reply-lost")]
    [InlineData(3, "journal-reply-lost")]
    [InlineData(1, "before-budget")]
    [InlineData(2, "before-budget")]
    [InlineData(3, "before-budget")]
    [InlineData(1, "before-adoption")]
    [InlineData(2, "before-adoption")]
    [InlineData(3, "before-adoption")]
    [InlineData(1, "duplicate")]
    [InlineData(2, "duplicate")]
    [InlineData(3, "duplicate")]
    public void Public_transfer_crash_recovery_only_finishes_unperformed_bookkeeping(int kind, string crash)
    {
        var model = new PublicTransferModel(kind);
        model.NativeSuccess();
        if (crash != "reply-lost") model.CompleteJournal();
        if (crash is "before-adoption" or "duplicate") model.PersistBudget();
        if (crash == "duplicate") model.Adopt();
        model = model.Restart();
        if (crash == "reply-lost" && kind != 1)
        {
            // No surviving exact result: name/digest/old Verified cannot replace it.
            Assert.Throws<InvalidDataException>(model.CompleteJournal);
            Assert.Throws<InvalidDataException>(() => model.PersistBudget());
            Assert.Equal(66560, model.Charge);
        }
        else
        {
            model.CompleteJournal(); model.PersistBudget(); model.Adopt();
            model.PersistBudget(); model.Adopt();
            Assert.Equal(17408, model.Charge);
            Assert.Equal(1, model.BudgetCommits);
        }
        Assert.Equal(1, model.Copies); Assert.Equal(1, model.Renames);
    }

    [Theory]
    [InlineData("path-only")]
    [InlineData("digest-only")]
    [InlineData("private-name-missing")]
    [InlineData("failed")]
    [InlineData("uncertain")]
    [InlineData("authority")]
    [InlineData("drain")]
    [InlineData("native-facts")]
    [InlineData("ambiguous-persistence")]
    public void Public_transfer_failure_mutants_retain_FullDebitHeld(string mutation)
    {
        var model = new PublicTransferModel(1);
        if (mutation is not ("path-only" or "digest-only" or "private-name-missing" or "failed" or "uncertain"))
        { model.NativeSuccess(); model.CompleteJournal(); }
        model.Authority = mutation != "authority";
        model.Drained = mutation != "drain";
        model.ExactNativeFacts = mutation != "native-facts";
        model.AmbiguousPersistence = mutation == "ambiguous-persistence";
        Assert.Throws<InvalidDataException>(() => model.PersistBudget());
        Assert.True(model.FullDebitHeld);
        Assert.Equal(66560, model.Charge);
        Assert.Null(model.Receipt);
    }

    [Fact]
    public void Public_receipt_replay_after_slot_reuse_cannot_refund_the_new_incarnation()
    {
        var model = new PublicTransferModel(1);
        model.NativeSuccess(); model.CompleteJournal(); model.PersistBudget(); model.Adopt();
        byte[] oldReceipt = model.Receipt!.ToArray();
        model.ReuseSlot();
        int before = model.Charge;
        model.PersistBudget(oldReceipt); model.Adopt();
        Assert.Equal(before, model.Charge);
        Assert.Equal(1, model.BudgetCommits);
        byte[] alias = oldReceipt.ToArray(); alias[16] ^= 1;
        Assert.Throws<InvalidDataException>(() => model.PersistBudget(alias));
        Assert.Equal(before, model.Charge);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void Public_old_receipt_after_restart_preserves_new_slot_inventory(int kind)
    {
        var model = new PublicTransferModel(kind);
        model.NativeSuccess(); model.CompleteJournal(); model.PersistBudget(); model.Adopt(); model.ReuseSlot();
        byte[] receipt = model.Receipt!.ToArray();
        model = model.Restart();
        model.PersistBudget(receipt); model.Adopt();
        Assert.Equal(33792, model.Charge);
        Assert.Equal(1, model.BudgetCommits);
    }

    [Fact]
    public void Public_transfer_does_not_clear_unrelated_hold_or_claim_physical_release()
    {
        var model = new PublicTransferModel(3) { OtherHold = true };
        model.NativeSuccess(); model.CompleteJournal(); model.PersistBudget(); model.Adopt();
        Assert.NotNull(model.Receipt);
        Assert.True(model.FullDebitHeld);
        Assert.Equal(66560, model.Charge);
        Assert.False(CanRelease(new ReleaseClaim(Segment, 3, 9, 0, 0, 0, true, true),
            new ReleaseClaim(Segment, 3, 9, 0, 0, 0, true, true)));
    }

    [Fact]
    public void Durable_approval_roundtrip_preserves_two_policy_fingerprints_at_same_version()
    {
        string first = new('A', 64), second = new('B', 64);
        // Exact review counterexample: the existing JsonIgnore-style projection collides.
        Assert.Equal(JsonSerializer.SerializeToUtf8Bytes(new IgnoredFingerprintFixture(7) { PolicyContentFingerprint = first }),
            JsonSerializer.SerializeToUtf8Bytes(new IgnoredFingerprintFixture(7) { PolicyContentFingerprint = second }));
        byte[] a = WriteApproval(Approval(first)), b = WriteApproval(Approval(second));
        Assert.False(a.AsSpan().SequenceEqual(b));
        Assert.Equal(first, ReadApproval(a).Inspection.PolicyContentFingerprint);
        Assert.Equal(second, ReadApproval(b).Inspection.PolicyContentFingerprint);
        Assert.Equal(a, WriteApproval(ReadApproval(a))); Assert.Equal(b, WriteApproval(ReadApproval(b)));
    }

    [Theory]
    [InlineData("missing-fingerprint")]
    [InlineData("ignored-fingerprint")]
    [InlineData("mismatched-current-policy")]
    [InlineData("mismatched-operation")]
    [InlineData("mismatched-version")]
    [InlineData("unknown")]
    [InlineData("duplicate")]
    public void Durable_approval_serialization_mutants_reject_missing_or_changed_authority(string mutation)
    {
        DurableApproval a = Approval(new string('A', 64));
        string bytes = Encoding.UTF8.GetString(WriteApproval(a));
        switch (mutation)
        {
            case "missing-fingerprint":
                string token = ",\"PolicyContentFingerprint\":\"" + new string('A', 64) + "\"";
                int first = bytes.IndexOf(token, StringComparison.Ordinal); Need(first >= 0);
                bytes = bytes.Remove(first, token.Length); break; // Keep PolicyCheck fingerprint intact.
            case "ignored-fingerprint": bytes = bytes.Replace("\"PolicyContentFingerprint\"", "\"IgnoredFingerprint\"", StringComparison.Ordinal); break;
            case "mismatched-current-policy": a = a with { PolicyCheck = a.PolicyCheck with { PolicyContentFingerprint = new string('B', 64) } }; break;
            case "mismatched-operation": a = a with { PolicyCheck = a.PolicyCheck with { Operation = a.Operation with { ProcessId = 8 } } }; break;
            case "mismatched-version": a = a with { Inspection = a.Inspection with { PolicyVersion = 8 } }; break;
            case "unknown": bytes = bytes.Replace("\"Version\":1", "\"Version\":1,\"Extra\":0", StringComparison.Ordinal); break;
            case "duplicate": bytes = bytes.Replace("\"Version\":1", "\"Version\":1,\"Version\":1", StringComparison.Ordinal); break;
        }
        if (mutation.StartsWith("mismatched-", StringComparison.Ordinal)) bytes = Encoding.UTF8.GetString(JsonSerializer.SerializeToUtf8Bytes(a, ApprovalJson));
        Assert.ThrowsAny<Exception>(() => ReadApproval(Encoding.UTF8.GetBytes(bytes)));
    }

    [Theory]
    [InlineData("fingerprint")]
    [InlineData("blocked-fingerprint")]
    [InlineData("binding")]
    [InlineData("override")]
    [InlineData("expired-at-consumption")]
    [InlineData("space-failure")]
    public void Justification_approval_mutants_cannot_change_the_checked_policy_or_version(string mutation)
    {
        DurableApproval a = Approval(new string('A', 64), true);
        Assert.True(ReadApproval(WriteApproval(a)).Justified);
        a = mutation switch
        {
            "fingerprint" => a with { Justification = a.Justification! with { PolicyContentFingerprint = new string('B', 64) } },
            "blocked-fingerprint" => a with { Justification = a.Justification! with { BlockedPolicyFingerprint = new string('B', 64) } },
            "binding" => a with { Justification = a.Justification! with { Binding = a.Binding with { DestinationGeneration = 6 } } },
            "override" => a with { PolicyCheck = a.PolicyCheck with { OverrideAllowed = false } },
            "expired-at-consumption" => a with { Justification = a.Justification! with { ConsumedAtUtcTicks = 2 } },
            _ => a with { Inspection = a.Inspection with { Reason = "not_enough_staging_space" } }
        };
        Assert.Throws<InvalidDataException>(() => WriteApproval(a));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void Durable_MayHaveIssued_refuses_the_review_second_native_mutation_after_restart(int kind)
    {
        var m = new PublicTransferModel(kind); m.NativeSuccess(); m = m.Restart();
        Assert.Throws<InvalidDataException>(m.NativeSuccess); // Review's exact NativeSuccess/Restart/NativeSuccess sequence.
        Assert.Equal(1, m.Copies); Assert.Equal(1, m.Renames);
        Assert.Equal(kind == 1 ? "CompleteJournalOnly" : "Hold", m.RecoveryDecision);
        if (kind == 1) { m.CompleteJournal(); m.PersistBudget(); }
        else Assert.Throws<InvalidDataException>(m.CompleteJournal);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void MayHaveIssued_without_any_native_result_survives_restart_and_holds(int kind)
    {
        var m = new PublicTransferModel(kind); m.MayHaveIssuedBeforeNativeReturn(); m = m.Restart();
        Assert.Equal("Hold", m.RecoveryDecision); Assert.Throws<InvalidDataException>(m.NativeSuccess);
        Assert.Equal(0, m.Renames); Assert.True(m.FullDebitHeld);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void Zero_acceptance_completion_replays_after_unrelated_budget_revision_and_slot_reuse(int kind)
    {
        var m = new PublicTransferModel(kind); m.NativeSuccess(); m.CompleteJournal();
        byte[] source = m.OriginalCompletion;
        m.AdvanceUnrelatedBudgetRevision(); m.AdvanceUnrelatedBudgetRevision();
        Assert.Equal(11, m.CurrentBudgetRevision);
        m.PersistBudget(source); m.Adopt();
        Assert.Equal(12, BinaryPrimitives.ReadInt64LittleEndian(m.Receipt!.AsSpan(160)));
        m.ReuseSlot(); m.AdvanceUnrelatedBudgetRevision(); m = m.Restart();
        m.PersistBudget(source); m.Adopt();
        Assert.Equal(33792, m.Charge); Assert.Equal(14, m.CurrentBudgetRevision); Assert.Equal(1, m.BudgetCommits);
        Assert.Equal(0, BinaryPrimitives.ReadInt64LittleEndian(source.AsSpan(160)));
    }

    [Fact]
    public void Held_reader_with_zero_reader_witness_is_not_a_storage_release()
    {
        var held = new ReleaseClaim(Segment, 3, 9, 1, 0, 0, false, false);
        var forged = held with { Readers = 0, Persisted = true };
        Assert.False(CanRelease(held, forged)); // Exact review counterexample.
        var owners = new OwnerInventory(); int reader = owners.Admit(OwnerKind.Reader);
        owners.Cancel(); owners.CloseAdmission();
        Assert.False(owners.CanRelease(forged)); Assert.Throws<InvalidDataException>(() => owners.PersistWitness());
        owners = owners.Restart(); Assert.False(owners.CanRelease(forged));
        owners.Complete(reader); Assert.True(owners.CanRelease(owners.PersistWitness()));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public void Actual_owner_drain_and_admission_fence_are_independent_of_persisted_zero_counts(int kind)
    {
        var owners = new OwnerInventory(); int owner = owners.Admit((OwnerKind)kind);
        owners.Cancel(); Assert.False(owners.AdmissionClosed);
        owners.CloseAdmission();
        var falseWitness = new ReleaseClaim(Segment, 3, 9, 0, 0, 0, true, false);
        Assert.False(owners.CanRelease(falseWitness));
        Assert.Throws<InvalidDataException>(() => owners.Admit(OwnerKind.Reader));
        owners.Complete(owner); // A late native operation completes its old owner, never admits a new one.
        Assert.True(owners.CanRelease(owners.PersistWitness()));
        Assert.Throws<InvalidDataException>(() => owners.Admit(OwnerKind.Operation));
    }

    [Fact]
    public void Zero_owner_count_without_closed_admission_is_not_a_drain_boundary()
    {
        var owners = new OwnerInventory();
        Assert.False(owners.CanRelease(new(Segment, 3, 9, 0, 0, 0, true, false)));
        Assert.Throws<InvalidDataException>(() => owners.PersistWitness());
        owners.CloseAdmission(); Assert.True(owners.CanRelease(owners.PersistWitness()));
    }

    [Fact]
    public void Public_transfer_cannot_use_asserted_Drained_while_a_reader_survives_cancellation()
    {
        var m = new PublicTransferModel(1); int reader = m.Owners.Admit(OwnerKind.Reader);
        m.NativeSuccess(); m.Owners.Cancel();
        Assert.True(m.Drained); Assert.Throws<InvalidDataException>(m.CompleteJournal);
        Assert.Throws<InvalidDataException>(() => m.PersistBudget()); Assert.True(m.FullDebitHeld);
        m.Owners.Complete(reader); m.CompleteJournal(); m.PersistBudget(); m.Adopt(); Assert.False(m.FullDebitHeld);
    }

    private static (byte[] Slot0, byte[] Slot1, byte[] Frames, byte[] Candidate, AppendPlan Plan) RecoveryScenario(int expectedSequence)
    {
        byte[] prior = expectedSequence == 1 ? [] : Frame([7, 8], 4096);
        if (prior.Length > 0) Transfer.TryWriteBytes(prior.AsSpan(12, 16));
        byte[] candidate = Frame([1, 2], 4096);
        var plan = new AppendPlan((ulong)expectedSequence, 8192 + prior.Length, (ulong)expectedSequence + 1,
            8192 + prior.Length + candidate.Length, Transaction);
        byte[] old = Slot(4096, (ulong)expectedSequence, plan.ExpectedEnd, expectedSequence == 1 ? Guid.Empty : Segment);
        byte[] target = Slot(4096, plan.TargetSequence, plan.TargetEnd, Transaction);
        return expectedSequence == 1 ? (old, target, [.. prior, .. candidate], candidate, plan) :
            (target, old, [.. prior, .. candidate], candidate, plan);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public void Valid_target_frontier_with_zero_candidate_is_held_in_both_parities(int expectedSequence)
    {
        var x = RecoveryScenario(expectedSequence);
        Assert.Equal("Hold", Recover(x.Slot0, x.Slot1, x.Frames, x.Plan, new byte[4096]));
    }

    [Theory]
    [InlineData(1, "payload")]
    [InlineData(1, "hash")]
    [InlineData(1, "padding")]
    [InlineData(2, "payload")]
    [InlineData(2, "hash")]
    [InlineData(2, "padding")]
    [InlineData(2, "earlier-prefix-payload")]
    [InlineData(2, "earlier-prefix-padding")]
    public void Valid_frontier_never_hides_independently_corrupt_selected_frame(int expectedSequence, string mutation)
    {
        var x = RecoveryScenario(expectedSequence); byte[] observed = x.Frames.ToArray();
        int offset = mutation.StartsWith("earlier-", StringComparison.Ordinal) ? 0 : x.Plan.ExpectedEnd - 8192;
        observed[offset + (mutation.EndsWith("padding", StringComparison.Ordinal) ? 62 : mutation == "hash" ? 28 : 60)] ^= 1;
        Assert.Equal("Hold", Recover(x.Slot0, x.Slot1, observed, x.Plan, x.Candidate));
        Assert.Equal("BookkeepingOnly", Recover(x.Slot0, x.Slot1, x.Frames, x.Plan, x.Candidate));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public void Repeated_interrupted_frontier_recovery_validates_prefix_and_never_issues_another_append(int expectedSequence)
    {
        var x = RecoveryScenario(expectedSequence); byte[][] slots = [x.Slot0, x.Slot1];
        int targetIndex = (int)((x.Plan.TargetSequence - 1) % 2);
        byte[] torn = slots[targetIndex].ToArray(); torn[96] ^= 1;
        slots[targetIndex] = torn;
        for (int attempt = 0; attempt < 2; attempt++) Assert.Equal("FrontierOnly", Recover(slots[0], slots[1], x.Frames, x.Plan, x.Candidate));
        slots[targetIndex] = Slot(4096, x.Plan.TargetSequence, x.Plan.TargetEnd, Transaction);
        for (int attempt = 0; attempt < 2; attempt++) Assert.Equal("BookkeepingOnly", Recover(slots[0], slots[1], x.Frames, x.Plan, x.Candidate));
    }

    private static byte[] Decode64(string value, int length)
    {
        byte[] bytes = Convert.FromBase64String(value);
        Need(bytes.Length == length && Convert.ToBase64String(bytes) == value);
        return bytes;
    }
    private static byte[] Envelope(string entry, string closure, int kind = 1)
    {
        using var memory = new MemoryStream();
        using (var w = new Utf8JsonWriter(memory))
        {
            w.WriteStartObject(); w.WriteNumber("FormatVersion", 2); w.WriteNumber("ResourceSchema", 3);
            w.WriteString("InstallationId", Installation); w.WriteNumber("RecordKind", kind);
            w.WriteString("RecordId", RecordId); w.WriteString("TransferId", Transfer); w.WriteNumber("RecordRevision", 1);
            w.WriteNull("PreviousRecordId"); w.WritePropertyName("Entry"); w.WriteRawValue(entry);
            w.WritePropertyName("ResourceClosure"); w.WriteRawValue(closure);
            w.WriteNull("OrdinaryDiscardDisposal"); w.WriteNull("ResolutionDelta");
            w.WritePropertyName("LegacySource"); w.WriteRawValue(kind == 4 ? "{}" : "null"); w.WriteEndObject();
        }
        return memory.ToArray();
    }
    private static void ValidateEnvelope(byte[] bytes)
    {
        Need(bytes.Length is > 0 and <= EnvelopeLimit);
        _ = new UTF8Encoding(false, true).GetString(bytes);
        using JsonDocument doc = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 16 });
        Unique(doc.RootElement);
        JsonElement root = doc.RootElement;
        Need(root.ValueKind == JsonValueKind.Object);
        Need(root.EnumerateObject().Select(p => p.Name).ToHashSet().SetEquals(Properties));
        Need(Integer(root.GetProperty("FormatVersion")) == 2 && Integer(root.GetProperty("ResourceSchema")) == 3);
        Need(Integer(root.GetProperty("RecordKind")) is >= 1 and <= 4 && Integer(root.GetProperty("RecordRevision")) > 0);
        foreach (string key in new[] { "InstallationId", "RecordId", "TransferId" })
        {
            string value = root.GetProperty(key).GetString()!;
            Need(Guid.TryParseExact(value, "D", out Guid id) && id != Guid.Empty && id.ToString("D") == value);
        }
        int entry = Encoding.UTF8.GetByteCount(root.GetProperty("Entry").GetRawText());
        int closure = Encoding.UTF8.GetByteCount(root.GetProperty("ResourceClosure").GetRawText());
        Need(closure <= ControlLimit && bytes.Length - entry - closure <= 8192);
    }
    private static long Integer(JsonElement element)
    {
        string raw = element.GetRawText();
        Need(element.ValueKind == JsonValueKind.Number && raw.All(c => c is >= '0' and <= '9'));
        Need(element.TryGetInt64(out long value)); return value;
    }
    private static void Unique(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (JsonProperty p in element.EnumerateObject()) { Need(names.Add(p.Name)); Unique(p.Value); }
        }
        if (element.ValueKind == JsonValueKind.Array) foreach (JsonElement item in element.EnumerateArray()) Unique(item);
    }
    private static int Round(int value, int alignment) => checked((value + alignment - 1) / alignment * alignment);
    private static byte[] Frame(byte[] payload, int alignment)
    {
        byte[] frame = new byte[Round(60 + payload.Length, alignment)];
        BinaryPrimitives.WriteUInt32LittleEndian(frame, 0x414a5553);
        BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(4), 3);
        BinaryPrimitives.WriteInt32LittleEndian(frame.AsSpan(8), payload.Length);
        RecordId.TryWriteBytes(frame.AsSpan(12)); SHA256.HashData(payload).CopyTo(frame.AsSpan(28));
        payload.CopyTo(frame.AsSpan(60)); return frame;
    }
    private static byte[] ReadFrame(byte[] frame, int alignment, Guid id)
    {
        Need(frame.Length >= 60 && BinaryPrimitives.ReadUInt32LittleEndian(frame) == 0x414a5553 &&
            BinaryPrimitives.ReadUInt32LittleEndian(frame.AsSpan(4)) == 3);
        int length = BinaryPrimitives.ReadInt32LittleEndian(frame.AsSpan(8));
        Need(length is > 0 and <= EnvelopeLimit && frame.Length == Round(60 + length, alignment));
        Need(new Guid(frame.AsSpan(12, 16)) == id);
        byte[] payload = frame.AsSpan(60, length).ToArray();
        Need(SHA256.HashData(payload).AsSpan().SequenceEqual(frame.AsSpan(28, 32)) &&
            frame.AsSpan(60 + length).IndexOfAnyExcept((byte)0) < 0);
        return payload;
    }
    private static void ReadEnvelopeFrame(byte[] frame)
    {
        byte[] payload = ReadFrame(frame, 4096, new Guid(frame.AsSpan(12, 16)));
        ValidateEnvelope(payload);
        using JsonDocument doc = JsonDocument.Parse(payload);
        Need(doc.RootElement.GetProperty("RecordId").GetGuid() == new Guid(frame.AsSpan(12, 16)));
    }
    private sealed record Frontier(ulong Sequence, int End, Guid Transaction);
    private static byte[] Slot(int alignment, ulong sequence, int end, Guid transaction)
    {
        byte[] b = new byte[alignment]; Encoding.ASCII.GetBytes("SAFEND03").CopyTo(b, 0);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(8), 3); BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(12), 128);
        Installation.TryWriteBytes(b.AsSpan(16)); Segment.TryWriteBytes(b.AsSpan(32, 16)); // synthetic full identity[24]
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(56), (uint)alignment);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(60), (uint)((sequence - 1) % 2));
        BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(64), sequence);
        BinaryPrimitives.WriteInt64LittleEndian(b.AsSpan(72), end); transaction.TryWriteBytes(b.AsSpan(80));
        SHA256.HashData(b.AsSpan(0, 96)).CopyTo(b.AsSpan(96)); return b;
    }
    private static Frontier ReadSlot(byte[] b, int alignment, int index)
    {
        Need(b.Length == alignment && b.AsSpan(0, 8).SequenceEqual("SAFEND03"u8));
        Need(BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(8)) == 3 && BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(12)) == 128);
        Need(new Guid(b.AsSpan(16, 16)) == Installation && b.AsSpan(32, 24).SequenceEqual(Slot(alignment, 1, 2 * alignment, Guid.Empty).AsSpan(32, 24)));
        Need(BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(56)) == alignment && BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(60)) == index);
        ulong sequence = BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(64));
        long end = BinaryPrimitives.ReadInt64LittleEndian(b.AsSpan(72)); Guid tx = new(b.AsSpan(80, 16));
        Need(sequence > 0 && (sequence - 1) % 2 == (ulong)index && end >= 2 * alignment && end <= SegmentLimit && end % alignment == 0);
        Need(sequence == 1 ? end == 2 * alignment && tx == Guid.Empty : tx != Guid.Empty);
        Need(SHA256.HashData(b.AsSpan(0, 96)).AsSpan().SequenceEqual(b.AsSpan(96, 32)) && b.AsSpan(128).IndexOfAnyExcept((byte)0) < 0);
        return new(sequence, (int)end, tx);
    }
    private static Frontier SelectSlots(byte[] first, byte[] second)
    {
        Frontier a = ReadSlot(first, 4096, 0);
        if (second.AsSpan().IndexOfAnyExcept((byte)0) < 0) { Need(a.Sequence == 1); return a; }
        Frontier b = ReadSlot(second, 4096, 1);
        Frontier low = a.Sequence < b.Sequence ? a : b, high = a.Sequence < b.Sequence ? b : a;
        Need(high.Sequence == checked(low.Sequence + 1) && high.End > low.End && high.Transaction != low.Transaction);
        return high;
    }
    private sealed record AppendPlan(ulong ExpectedSequence, int ExpectedEnd, ulong TargetSequence, int TargetEnd, Guid Transaction);
    private static void ValidateSelectedPrefix(byte[] frames, int committedBytes)
    {
        Need(committedBytes >= 0 && committedBytes <= frames.Length);
        int offset = 0;
        while (offset < committedBytes)
        {
            Need(committedBytes - offset >= 60);
            int length = BinaryPrimitives.ReadInt32LittleEndian(frames.AsSpan(offset + 8));
            Need(length is > 0 and <= EnvelopeLimit);
            int stride = Round(checked(60 + length), 4096);
            Need(stride <= committedBytes - offset);
            Guid id = new(frames.AsSpan(offset + 12, 16)); Need(id != Guid.Empty);
            _ = ReadFrame(frames.AsSpan(offset, stride).ToArray(), 4096, id);
            offset = checked(offset + stride);
        }
        Need(offset == committedBytes);
    }
    // Slots are physical slot 0/1. Frames contain independent observed bytes from
    // segment offset 2*A to EOF, including the selected prefix and any actual tail.
    private static string Recover(byte[] slot0, byte[] slot1, byte[] frames, AppendPlan? plan, byte[] candidate)
    {
        try
        {
            byte[][] slots = [slot0, slot1];
            if (plan is null)
            {
                Frontier selected = SelectSlots(slot0, slot1);
                Need(frames.Length == selected.End - 8192);
                ValidateSelectedPrefix(frames, frames.Length); return "Idle";
            }
            Need(plan.ExpectedSequence > 0 && plan.TargetSequence == checked(plan.ExpectedSequence + 1) && plan.Transaction != Guid.Empty);
            int expectedIndex = (int)((plan.ExpectedSequence - 1) % 2), targetIndex = 1 - expectedIndex;
            Frontier expected = ReadSlot(slots[expectedIndex], 4096, expectedIndex);
            Need(expected.Sequence == plan.ExpectedSequence && expected.End == plan.ExpectedEnd);
            _ = ReadFrame(candidate, 4096, RecordId); // A zero candidate is never completion evidence.
            Need(plan.TargetEnd == checked(expected.End + candidate.Length) && plan.TargetEnd <= SegmentLimit);
            byte[] other = slots[targetIndex];
            Need(other.Length == 4096);
            bool zero = other.AsSpan().IndexOfAnyExcept((byte)0) < 0, torn = zero && expected.Sequence != 1;
            Frontier? next = null;
            if (!zero)
            {
                try { next = ReadSlot(other, 4096, targetIndex); }
                catch (InvalidDataException)
                {
                    // A checksummed conflicting slot is corruption, not a tear to overwrite.
                    Need(!SHA256.HashData(other.AsSpan(0, 96)).AsSpan().SequenceEqual(other.AsSpan(96, 32)));
                    torn = true;
                }
            }
            int oldBytes = checked(expected.End - 8192);
            ValidateSelectedPrefix(frames, oldBytes);
            if (next is not null && next.Sequence == plan.TargetSequence)
            {
                Need(next.End == plan.TargetEnd && next.Transaction == plan.Transaction && next.Transaction != expected.Transaction);
                Need(frames.Length == next.End - 8192);
                ValidateSelectedPrefix(frames, frames.Length); // Before BookkeepingOnly, not after.
                Need(frames.AsSpan(oldBytes).SequenceEqual(candidate));
                return "BookkeepingOnly";
            }
            if (next is not null) Need(next.Sequence + 1 == expected.Sequence && next.End < expected.End && next.Transaction != expected.Transaction);
            if (frames.Length == oldBytes) return torn ? "Hold" : "IssueOnce";
            Need(frames.AsSpan(oldBytes).SequenceEqual(candidate));
            ValidateSelectedPrefix(frames, frames.Length);
            return "FrontierOnly";
        }
        catch (InvalidDataException) { return "Hold"; }
        catch (OverflowException) { return "Hold"; }
    }
    private sealed record Candidate(Guid? Identity, Guid Record, string Leaf, int Phase, byte[] Bytes);
    private static bool CandidateMatches(Candidate c, Guid identity, Guid record, byte[] bytes) =>
        c.Identity == identity && c.Record == record && c.Leaf == record.ToString("N") + ".resource" && c.Phase == 1 && c.Bytes.AsSpan().SequenceEqual(bytes);
    private sealed record History(Guid Id, Guid Transfer, int Kind, long Revision, Guid? Previous, int State,
        string Original, Guid Fence, ulong Cookie, bool Authenticated, long EffectiveGeneration, long AllocationGeneration, string Bytes);
    private sealed record Projection(int Debt, long EffectiveGeneration, long AllocationGeneration);
    private static History Base() => new(RecordId, Transfer, 1, 9, null, 5, "original", Transaction, ulong.MaxValue, true, 19, 23, "base-bytes");
    private static History Delta(History b) => b with { Id = Installation, Kind = 3, Revision = b.Revision + 1, Previous = b.Id, State = 6, Bytes = "delta-bytes" };
    private static Projection Project(IEnumerable<History> input)
    {
        var byId = new Dictionary<Guid, History>();
        foreach (History r in input) { if (byId.TryGetValue(r.Id, out History? previous)) Need(previous == r); else byId.Add(r.Id, r); }
        int debt = 0; long effective = 0, allocation = 0;
        foreach (var group in byId.Values.GroupBy(r => r.Transfer))
        {
            History[] bases = group.Where(r => r.Kind is 1 or 2 or 4).ToArray(); Need(bases.Length == 1);
            History b = bases[0]; Need(b.Revision > 0 && b.Previous is null && b.State is 5 or 6 or 7);
            History[] deltas = group.Where(r => r.Kind == 3).ToArray(); Need(group.Count() == 1 + deltas.Length && deltas.Length <= 1);
            foreach (History d in deltas) Need(b.State == 5 && b.Kind != 4 && d.State == 6 && d.Authenticated && d.Previous == b.Id &&
                d.Revision == checked(b.Revision + 1) && d.Original == b.Original && d.Fence == b.Fence && d.Cookie == b.Cookie &&
                d.EffectiveGeneration == b.EffectiveGeneration && d.AllocationGeneration == b.AllocationGeneration);
            if (b.Kind != 4 && b.State == 5 && deltas.Length == 0) debt++;
            effective = Math.Max(effective, b.EffectiveGeneration); allocation = Math.Max(allocation, b.AllocationGeneration);
        }
        return new(debt, effective, allocation);
    }
    private static bool Equivalent(History[] old, History[] next)
    {
        try
        {
            return Project(old) == Project(next) && old.Distinct().OrderBy(r => r.Id).SequenceEqual(next.Distinct().OrderBy(r => r.Id));
        }
        catch (InvalidDataException) { return false; }
    }
    private static (uint First, uint End) Select(uint first, uint end, uint sources, uint targets)
    {
        Need(first > 0 && end >= first && sources is > 0 and <= 32 && targets is > 0 and <= 32 && sources <= (ulong)end - first + 1);
        return (checked(first + sources), checked(end + targets));
    }
    private static byte[] LegacySegment(byte[][] payloads)
    {
        int end = checked(4096 + payloads.Sum(p => 60 + p.Length));
        byte[] b = new byte[end];
        BinaryPrimitives.WriteUInt32LittleEndian(b, 0x43415553); BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(4), 1);
        BinaryPrimitives.WriteInt64LittleEndian(b.AsSpan(8), end); SHA256.HashData(b.AsSpan(0, 16)).CopyTo(b.AsSpan(16));
        int offset = 4096, ordinal = 0;
        foreach (byte[] payload in payloads)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(offset), 0x414a5553);
            BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(offset + 4), 1);
            BinaryPrimitives.WriteInt32LittleEndian(b.AsSpan(offset + 8), payload.Length);
            byte[] id = Transfer.ToByteArray(); id[15] ^= checked((byte)ordinal++);
            id.CopyTo(b.AsSpan(offset + 12)); SHA256.HashData(payload).CopyTo(b.AsSpan(offset + 28));
            payload.CopyTo(b.AsSpan(offset + 60)); offset += 60 + payload.Length;
        }
        return b;
    }
    private static byte[][] ReadLegacy(byte[] b)
    {
        Need(b.Length is >= 4096 and <= SegmentLimit && BinaryPrimitives.ReadUInt32LittleEndian(b) == 0x43415553 &&
            BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(4)) == 1);
        long end = BinaryPrimitives.ReadInt64LittleEndian(b.AsSpan(8));
        Need(end == b.Length && SHA256.HashData(b.AsSpan(0, 16)).AsSpan().SequenceEqual(b.AsSpan(16, 32)));
        var payloads = new List<byte[]>(); var ids = new HashSet<Guid>(); int offset = 4096;
        while (offset < end)
        {
            Need(end - offset >= 60 && BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(offset)) == 0x414a5553 &&
                BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(offset + 4)) == 1);
            int length = BinaryPrimitives.ReadInt32LittleEndian(b.AsSpan(offset + 8));
            Need(length is > 0 and <= EnvelopeLimit && (long)offset + 60 + length <= end);
            Guid id = new(b.AsSpan(offset + 12, 16)); Need(id != Guid.Empty && ids.Add(id));
            byte[] payload = b.AsSpan(offset + 60, length).ToArray();
            Need(SHA256.HashData(payload).AsSpan().SequenceEqual(b.AsSpan(offset + 28, 32)));
            payloads.Add(payload); offset += 60 + length;
        }
        return payloads.ToArray();
    }
    private sealed class LegacyCursorModel(byte[] original)
    {
        private Guid? _pending;
        private byte[]? _frame;
        private bool _frontier;
        public bool Finished { get; private set; }
        public int NativeCopies { get; private set; }
        public int AssignedIds { get; private set; }
        public byte[] StoredEntry => _frame ?? throw new InvalidOperationException();
        public Guid Prepare()
        {
            Need(!Finished);
            if (_pending is null) { _pending = RecordId; AssignedIds++; }
            return _pending.Value;
        }
        public void Append()
        {
            Need(_pending is not null && !Finished);
            if (_frame is not null) { Need(_frame.AsSpan().SequenceEqual(original)); return; }
            _frame = original.ToArray(); NativeCopies++;
        }
        public void CommitFrontier() { Need(_frame is not null); _frontier = true; }
        public void Advance() { Need(_frontier); Finished = true; _pending = null; }
        public LegacyCursorModel Restart() => new(original.ToArray())
        {
            _pending = _pending, _frame = _frame?.ToArray(), _frontier = _frontier,
            Finished = Finished, NativeCopies = NativeCopies, AssignedIds = AssignedIds
        };
    }
    private sealed class MigrationModel
    {
        private readonly History[] _source;
        private readonly Dictionary<Guid, History> _target = new();
        private readonly int _oldCharge, _targetCharge;
        private bool _selected, _released;
        public int NativeCopies { get; private set; }
        public int Charge => _targetCharge + (_released ? 0 : _oldCharge);
        public Projection SelectedProjection => Project(_selected ? _target.Values : _source);
        public MigrationModel(History[] source, int oldCharge, int targetCharge, int allowance)
        {
            Need(oldCharge >= 0 && targetCharge >= 0 && checked(oldCharge + targetCharge) <= allowance);
            _source = source; _oldCharge = oldCharge; _targetCharge = targetCharge;
        }
        public void Copy(History record)
        {
            Need(!_selected);
            if (_target.TryGetValue(record.Id, out History? existing)) { Need(existing == record); return; }
            _target.Add(record.Id, record); NativeCopies++;
        }
        public void Select() { Need(Equivalent(_source, _target.Values.ToArray())); _selected = true; }
        public void ReleaseSource(bool persisted, Guid identity)
        { Need(_selected && persisted && identity == Segment); _released = true; }
        public MigrationModel Restart()
        {
            var restored = new MigrationModel(_source, _oldCharge, _targetCharge, _oldCharge + _targetCharge)
            { _selected = _selected, _released = _released, NativeCopies = NativeCopies };
            foreach (var row in _target) restored._target.Add(row.Key, row.Value);
            return restored;
        }
    }
    private static byte[] PublicCompletion(int kind)
    {
        byte[] b = new byte[2048]; "SAFCST03"u8.CopyTo(b);
        Put32(b, 8, 3); Put32(b, 12, 2048);
        foreach (int offset in new[] { 16, 32, 48, 64, 136, 240, 264, 304, 352, 368, 1312, 1848 })
            RecordId.TryWriteBytes(b.AsSpan(offset, 16));
        foreach (int offset in new[] { 80, 88, 128, 152, 280 }) Put64(b, offset, 9);
        foreach (int offset in new[] { 96, 168, 192, 216, 1264, 1288 })
        {
            BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(offset), ulong.MaxValue);
            BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(offset + 8), (ulong)offset);
            BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(offset + 16), ulong.MaxValue - (ulong)offset);
        }
        // Publication delivers to the original destination; hand-back captures another parent.
        b.AsSpan(192, 24).CopyTo(b.AsSpan(1264, 24));
        if (kind != 3) b.AsSpan(216, 24).CopyTo(b.AsSpan(1288, 24));
        Put32(b, 120, 2); Put32(b, 124, kind == 3 ? 4 : 3);
        Put32(b, 260, kind == 3 ? 2 : 1); Put32(b, 288, kind);
        Carrier(b, 292, 384, "saved.txt"); Carrier(b, 296, 896, "S-1-5-21-100-200-300-1001");
        Carrier(b, 1332, 1336, "saved.txt");
        return b;
    }
    private static void Put32(byte[] b, int offset, int value) => BinaryPrimitives.WriteInt32LittleEndian(b.AsSpan(offset), value);
    private static void Put64(byte[] b, int offset, long value) => BinaryPrimitives.WriteInt64LittleEndian(b.AsSpan(offset), value);
    private static void Carrier(byte[] b, int lengthOffset, int carrierOffset, string value)
    {
        byte[] encoded = Encoding.Unicode.GetBytes(value);
        Put32(b, lengthOffset, encoded.Length); encoded.CopyTo(b.AsSpan(carrierOffset));
    }
    private static string ReadCarrier(byte[] b, int lengthOffset, int offset, int capacity, int maximum)
    {
        int length = BinaryPrimitives.ReadInt32LittleEndian(b.AsSpan(lengthOffset));
        Need(length >= 2 && length <= maximum && length % 2 == 0);
        Need(b.AsSpan(offset + length, capacity - length).IndexOfAnyExcept((byte)0) < 0);
        string value = new UnicodeEncoding(false, false, true).GetString(b, offset, length);
        Need(!value.Contains('\0')); return value;
    }
    private static void ValidatePublicEncoding(byte[] b, bool completion)
    {
        Need(b.Length == 2048 && b.AsSpan(0, 8).SequenceEqual("SAFCST03"u8));
        Need(BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(8)) == 3 && BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(12)) == 2048);
        foreach (int offset in new[] { 16, 32, 48, 64, 136, 240, 264, 304, 352, 368, 1312, 1848 }) Need(new Guid(b.AsSpan(offset, 16)) != Guid.Empty);
        foreach (int offset in new[] { 80, 88, 128, 152, 280 }) Need(BinaryPrimitives.ReadInt64LittleEndian(b.AsSpan(offset)) > 0);
        long revision = BinaryPrimitives.ReadInt64LittleEndian(b.AsSpan(160)); Need(completion ? revision == 0 : revision > 0);
        foreach (int offset in new[] { 96, 168, 192, 216, 1264, 1288 })
            Need((BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(offset + 8)) | BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(offset + 16))) != 0);
        uint slot = BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(120)), role = BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(124));
        uint kind = BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(260)), proof = BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(288));
        Need(slot < 4 && (role == 3 && kind == 1 && proof is 1 or 2 || role == 4 && kind == 2 && proof == 3));
        Need(BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(256)) <= 1 && BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(1328)) <= 1);
        uint flags = BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(344)); Need(flags <= 1 && (kind != 2 || flags == 0));
        bool predecessor = b.AsSpan(320, 24).IndexOfAnyExcept((byte)0) >= 0;
        Need(predecessor == (flags == 1));
        if (predecessor) Need((BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(328)) | BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(336))) != 0 && b.AsSpan(320, 8).SequenceEqual(b.AsSpan(168, 8)));
        Need(b.AsSpan(300, 4).IndexOfAnyExcept((byte)0) < 0 && b.AsSpan(348, 4).IndexOfAnyExcept((byte)0) < 0 && b.AsSpan(1864).IndexOfAnyExcept((byte)0) < 0);
        string leaf = ReadCarrier(b, 292, 384, 512, 510), original = ReadCarrier(b, 1332, 1336, 512, 510);
        foreach (string value in new[] { leaf, original }) Need(value is not ("." or "..") && !value.EndsWith('.') && !value.EndsWith(' ') && !value.Any(c => c < 32 || "<>:\"/\\|?*".Contains(c)));
        string sid = ReadCarrier(b, 296, 896, 368, 368);
        string[] words = sid.Split('-');
        Need(words.Length is >= 3 and <= 18 && words[0] == "S" && words[1] == "1");
        Need(ulong.TryParse(words[2], out ulong authority) && authority <= 281474976710655 && authority.ToString(System.Globalization.CultureInfo.InvariantCulture) == words[2]);
        foreach (string word in words.Skip(3)) Need(uint.TryParse(word, out uint value) && value.ToString(System.Globalization.CultureInfo.InvariantCulture) == word);
        Need(b.AsSpan(168, 8).SequenceEqual(b.AsSpan(192, 8)) && b.AsSpan(192, 8).SequenceEqual(b.AsSpan(216, 8)) &&
            b.AsSpan(96, 8).SequenceEqual(b.AsSpan(1264, 8)) && b.AsSpan(1264, 8).SequenceEqual(b.AsSpan(1288, 8)));
        if (kind == 1) Need(b.AsSpan(192, 64).SequenceEqual(b.AsSpan(1264, 64)) &&
            b.AsSpan(256, 4).SequenceEqual(b.AsSpan(1328, 4)) && leaf == original);
    }
    private sealed record ApprovalIdentity(ulong VolumeSerialNumber, ulong FileIdLow, ulong FileIdHigh);
    private sealed record ApprovalBinding(Guid OperationId, Guid TransferId, long AllocationGeneration, long DestinationGeneration,
        ApprovalIdentity StageIdentity, ApprovalIdentity SnapshotIdentity, long Length, string Sha256, string RequestorSid, uint SessionId);
    private sealed record ApprovalOperation(string FilePath, string FileName, string Extension, long SizeBytes, long LastWriteUtcTicks,
        string ProcessName, int ProcessId, string DestinationPath, int Destination);
    private sealed record ApprovalFinding(int Category, string MaskedSnippet, string? MemberName);
    private sealed record ApprovalInspection(int Verdict, ApprovalFinding[] Findings, string? Reason, long ElapsedMs,
        bool FromCache, int PolicyVersion, bool InScope, string PolicyContentFingerprint);
    private sealed record ApprovalPolicyCheck(ApprovalOperation Operation, int PolicyVersion, string PolicyContentFingerprint,
        bool ProcessExcluded, bool DestinationMonitored, bool ExtensionMonitored, bool OverrideAllowed);
    private sealed record ApprovalJustification(Guid ReceiptId, ApprovalBinding Binding, int PolicyVersion,
        string PolicyContentFingerprint, int BlockedPolicyVersion, string BlockedPolicyFingerprint,
        long ConsumedAtUtcTicks, long ExpiresAtUtcTicks);
    private sealed record DurableApproval(int Version, ApprovalBinding Binding, ApprovalOperation Operation,
        ApprovalInspection Inspection, ApprovalPolicyCheck PolicyCheck, bool Justified, ApprovalJustification? Justification);
    private sealed record IgnoredFingerprintFixture(int PolicyVersion)
    {
        [System.Text.Json.Serialization.JsonIgnore] public string? PolicyContentFingerprint { get; init; }
    }
    private static readonly JsonSerializerOptions ApprovalJson = new()
    {
        MaxDepth = 16, RespectRequiredConstructorParameters = true,
        UnmappedMemberHandling = System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow
    };
    private static DurableApproval Approval(string fingerprint, bool justified = false)
    {
        var identity = new ApprovalIdentity(ulong.MaxValue, 9, ulong.MaxValue);
        var binding = new ApprovalBinding(Transaction, Transfer, 4, 5, identity, identity, 123,
            new string('C', 64), "S-1-5-21-1-2-3-1001", 1);
        var op = new ApprovalOperation("private", "saved.txt", ".txt", 123, 1, "app.exe", 7, "destination", 2);
        return new(1, binding, op, new(justified ? 1 : 0, [], null, 1, false, 7, true, fingerprint),
            new(op, 7, fingerprint, false, true, true, justified), justified,
            justified ? new(RecordId, binding, 7, fingerprint, 7, fingerprint, 1, 2) : null);
    }
    private static bool Hex64(string? value) => value is { Length: 64 } && value.All(c => c is >= '0' and <= '9' or >= 'A' and <= 'F');
    private static void ValidateApproval(DurableApproval a)
    {
        Need(a.Version == 1 && a.Binding is not null && a.Operation is not null && a.Inspection is not null && a.PolicyCheck is not null);
        var b = a.Binding!; var op = a.Operation!; var i = a.Inspection!; var c = a.PolicyCheck!;
        Need(b.OperationId != Guid.Empty && b.TransferId != Guid.Empty && b.AllocationGeneration > 0 && b.DestinationGeneration > 0 &&
            b.StageIdentity is not null && b.SnapshotIdentity is not null && (b.StageIdentity.FileIdLow | b.StageIdentity.FileIdHigh) != 0 &&
            (b.SnapshotIdentity.FileIdLow | b.SnapshotIdentity.FileIdHigh) != 0 && b.Length >= 0 && Hex64(b.Sha256) && !string.IsNullOrEmpty(b.RequestorSid));
        Need(op.SizeBytes == b.Length && op.LastWriteUtcTicks >= 0 && op.LastWriteUtcTicks <= DateTime.MaxValue.Ticks && op.ProcessId > 0 &&
            op.FilePath is { Length: > 0 and <= 512 } && op.DestinationPath is { Length: > 0 and <= 512 } &&
            op.FileName is { Length: > 0 and <= 255 } && op.Extension is { Length: <= 255 } &&
            op.ProcessName is { Length: > 0 and <= 512 } && op.Destination is >= 0 and <= 4);
        foreach (string value in new[] { op.FilePath, op.FileName, op.Extension, op.ProcessName, op.DestinationPath })
        { Need(!value.Contains('\0')); _ = new UnicodeEncoding(false, false, true).GetByteCount(value); }
        Need(i.InScope && i.ElapsedMs >= 0 && i.PolicyVersion > 0 && Hex64(i.PolicyContentFingerprint) && i.Findings is not null);
        foreach (var f in i.Findings!) Need(f.Category is >= 0 and <= 4 && f.MaskedSnippet is not null);
        Need(c.Operation == op && c.PolicyVersion == i.PolicyVersion && c.PolicyContentFingerprint == i.PolicyContentFingerprint &&
            !c.ProcessExcluded && c.DestinationMonitored && (op.SizeBytes == 0 && !a.Justified || c.ExtensionMonitored));
        if (!a.Justified) Need(i.Verdict == 0 && a.Justification is null);
        else
        {
            var j = a.Justification;
            Need(i.Verdict == 1 && i.Reason != "not_enough_staging_space" && c.OverrideAllowed && j is not null);
            Need(j!.ReceiptId != Guid.Empty && j.Binding == b && j.PolicyVersion == i.PolicyVersion &&
                j.PolicyContentFingerprint == i.PolicyContentFingerprint && j.BlockedPolicyVersion == i.PolicyVersion &&
                j.BlockedPolicyFingerprint == i.PolicyContentFingerprint && j.ConsumedAtUtcTicks >= 0 &&
                j.ConsumedAtUtcTicks < j.ExpiresAtUtcTicks && j.ExpiresAtUtcTicks <= DateTime.MaxValue.Ticks);
        }
    }
    private static byte[] WriteApproval(DurableApproval a)
    { ValidateApproval(a); byte[] b = JsonSerializer.SerializeToUtf8Bytes(a, ApprovalJson); Need(b.Length <= ControlLimit); return b; }
    private static DurableApproval ReadApproval(byte[] bytes)
    {
        Need(bytes.Length is > 0 and <= ControlLimit); _ = new UTF8Encoding(false, true).GetString(bytes);
        using JsonDocument d = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 16 }); Unique(d.RootElement);
        DurableApproval result = JsonSerializer.Deserialize<DurableApproval>(bytes, ApprovalJson) ?? throw new InvalidDataException();
        ValidateApproval(result); return result;
    }
    private enum PublicIssueState { ReservedNotIssued = 1, MayHaveIssued = 2, Completed = 3 }
    private sealed class PublicTransferModel(int kind)
    {
        private readonly byte[] _binding = PublicCompletion(kind);
        private bool _liveSuccess, _boundFacts, _journal, _applied, _reused;
        private PublicIssueState _issue = PublicIssueState.ReservedNotIssued; // Durable claim, never reset by restart.
        public OwnerInventory Owners { get; private set; } = new();
        public long CurrentBudgetRevision { get; private set; } = 9;
        public byte[] OriginalCompletion => _binding.ToArray();
        public byte[]? Receipt { get; private set; }
        public bool Authority = true, Drained = true, ExactNativeFacts = true, AmbiguousPersistence, OtherHold;
        public int Copies { get; private set; }
        public int Renames { get; private set; }
        public int BudgetCommits { get; private set; }
        public int Charge { get; private set; } = 66560;
        public bool FullDebitHeld => !_applied || OtherHold;
        public string RecoveryDecision => Receipt is not null ? "AdoptOnly" : _journal ? "PersistBudgetOnly" :
            _issue == PublicIssueState.MayHaveIssued ? (_liveSuccess || _boundFacts && ExactNativeFacts ? "CompleteJournalOnly" : "Hold") : "IssuePermitted";
        public void MayHaveIssuedBeforeNativeReturn()
        {
            Need(RecoveryDecision == "IssuePermitted" && _issue == PublicIssueState.ReservedNotIssued);
            _issue = PublicIssueState.MayHaveIssued; // Persist before invoking copy/rename.
        }
        public void NativeSuccess()
        {
            Need(RecoveryDecision == "IssuePermitted");
            int operation = Owners.Admit(OwnerKind.Operation);
            MayHaveIssuedBeforeNativeReturn();
            Copies++; Renames++; _liveSuccess = true; _boundFacts = kind == 1;
            Owners.CloseAdmission(); Owners.Complete(operation);
        }
        public void CompleteJournal()
        {
            if (_journal) return;
            Need(RecoveryDecision == "CompleteJournalOnly" && Owners.ActuallyDrained);
            _journal = true; _issue = PublicIssueState.Completed;
        }
        public void AdvanceUnrelatedBudgetRevision() => CurrentBudgetRevision = checked(CurrentBudgetRevision + 1);
        public byte[] ExpectedReceipt()
        {
            if (Receipt is not null) return Receipt.ToArray();
            byte[] b = _binding.ToArray(); Put64(b, 160, checked(CurrentBudgetRevision + 1)); return b;
        }
        public void PersistBudget(byte[]? bytes = null)
        {
            bytes ??= OriginalCompletion; // Actual API input is the zero-acceptance journal completion.
            byte[] normalized = bytes.ToArray();
            Need(normalized.Length == 2048);
            long suppliedRevision = BinaryPrimitives.ReadInt64LittleEndian(bytes.AsSpan(160));
            Put64(normalized, 160, 0);
            if (Receipt is not null)
            {
                byte[] acceptedSource = Receipt.ToArray(); Put64(acceptedSource, 160, 0);
                Need(normalized.AsSpan().SequenceEqual(acceptedSource) && (suppliedRevision == 0 || bytes.AsSpan().SequenceEqual(Receipt)));
                return; // Before inspecting a possibly reused current slot/revision.
            }
            Need(_journal && _issue == PublicIssueState.Completed && Authority && Drained && Owners.ActuallyDrained &&
                ExactNativeFacts && !AmbiguousPersistence && !_reused);
            ValidatePublicEncoding(normalized, completion: true);
            Need(normalized.AsSpan().SequenceEqual(_binding));
            long accepted = checked(CurrentBudgetRevision + 1);
            Need(suppliedRevision == 0 || suppliedRevision == accepted);
            Receipt = normalized; Put64(Receipt, 160, accepted);
            CurrentBudgetRevision = accepted; BudgetCommits++;
        }
        public void Adopt()
        {
            Need(Receipt is not null);
            if (_applied) return;
            _applied = true; Charge = OtherHold ? 66560 : _reused ? 33792 : 17408;
        }
        public void ReuseSlot() { Need(_applied); _reused = true; AdvanceUnrelatedBudgetRevision(); Charge = OtherHold ? 66560 : 33792; }
        public PublicTransferModel Restart()
        {
            var next = new PublicTransferModel(kind)
            {
                _issue = _issue, _boundFacts = _boundFacts, _journal = _journal, Receipt = Receipt?.ToArray(), _reused = _reused,
                Owners = Owners.Restart(), CurrentBudgetRevision = CurrentBudgetRevision,
                Authority = Authority, Drained = Drained, ExactNativeFacts = ExactNativeFacts, OtherHold = OtherHold,
                Copies = Copies, Renames = Renames, BudgetCommits = BudgetCommits
            };
            if (next.Receipt is not null) next.Adopt();
            return next;
        }
    }
    private enum OwnerKind { Reader, Section, Operation }
    private sealed class OwnerInventory
    {
        private readonly Dictionary<int, OwnerKind> _active = new();
        private int _next;
        public bool AdmissionClosed { get; private set; }
        public bool CancellationRequested { get; private set; }
        public bool ActuallyDrained => AdmissionClosed && _active.Count == 0;
        public int Admit(OwnerKind kind)
        {
            Need(!AdmissionClosed);
            int id = checked(++_next); _active.Add(id, kind); return id;
        }
        public void Cancel() => CancellationRequested = true; // Does not close admission or dispose any owner.
        public void CloseAdmission() => AdmissionClosed = true;
        public void Complete(int id) { Need(_active.Remove(id)); }
        public ReleaseClaim Held => new(Segment, 3, 9, _active.Values.Count(k => k == OwnerKind.Reader),
            _active.Values.Count(k => k == OwnerKind.Section), _active.Values.Count(k => k == OwnerKind.Operation), false, false);
        public ReleaseClaim PersistWitness()
        { Need(ActuallyDrained); return Held with { Persisted = true }; }
        public bool CanRelease(ReleaseClaim proof) => ActuallyDrained && GrowthArchiveContractModelTests.CanRelease(Held, proof);
        public OwnerInventory Restart()
        {
            var result = new OwnerInventory { _next = _next, AdmissionClosed = AdmissionClosed, CancellationRequested = CancellationRequested };
            foreach (var p in _active) result._active.Add(p.Key, p.Value); // Independent retained owners; restart proves no close.
            return result;
        }
    }
    private sealed record ReleaseClaim(Guid Identity, long Incarnation, long Revision, int Readers, int Sections,
        int Operations, bool Persisted, bool PublicPromotion);
    private static bool CanRelease(ReleaseClaim held, ReleaseClaim proof) => held.Identity == proof.Identity &&
        held.Incarnation == proof.Incarnation && held.Revision == proof.Revision && held.Readers == 0 && held.Sections == 0 && held.Operations == 0 && proof.Readers == 0 && proof.Sections == 0 &&
        proof.Operations == 0 && proof.Persisted && !proof.PublicPromotion;
    private static void Need(bool condition) { if (!condition) throw new InvalidDataException("Reference contract refused input"); }
}
#endif
