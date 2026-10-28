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
        Assert.Equal("BookkeepingOnly", Recover(old, target, [], plan, frame));
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
    public void Release_mutants_retain_charge_and_slot(string mutation)
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
    private static string Recover(byte[] old, byte[] other, byte[] tail, AppendPlan? plan, byte[] candidate)
    {
        try
        {
            Frontier expected = ReadSlot(old, 4096, 0);
            bool zero = other.AsSpan().IndexOfAnyExcept((byte)0) < 0;
            bool torn = false;
            Frontier? next = null;
            if (!zero)
            {
                try { next = ReadSlot(other, 4096, 1); }
                catch (InvalidDataException)
                {
                    // A fully checksummed conflicting slot is corruption, not a torn write.
                    Need(other.Length == 4096 && !SHA256.HashData(other.AsSpan(0, 96)).AsSpan().SequenceEqual(other.AsSpan(96, 32)));
                    torn = true;
                }
            }
            if (plan is null) return !torn && zero && expected.Sequence == 1 && tail.Length == 0 ? "Idle" : "Hold";
            Need(plan.ExpectedSequence == expected.Sequence && plan.ExpectedEnd == expected.End &&
                plan.TargetSequence == checked(expected.Sequence + 1) && plan.Transaction != Guid.Empty);
            Need(plan.TargetEnd == checked(expected.End + candidate.Length) && plan.TargetEnd <= SegmentLimit);
            if (next is not null)
            {
                Need(next.Sequence == plan.TargetSequence && next.End == plan.TargetEnd && next.Transaction == plan.Transaction && tail.Length == 0);
                return "BookkeepingOnly";
            }
            if (tail.Length == 0) return torn ? "Hold" : "IssueOnce";
            Need(tail.AsSpan().SequenceEqual(candidate)); _ = ReadFrame(tail, 4096, RecordId);
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
    private sealed record ReleaseClaim(Guid Identity, long Incarnation, long Revision, int Readers, int Sections,
        int Operations, bool Persisted, bool PublicPromotion);
    private static bool CanRelease(ReleaseClaim held, ReleaseClaim proof) => held.Identity == proof.Identity &&
        held.Incarnation == proof.Incarnation && held.Revision == proof.Revision && proof.Readers == 0 && proof.Sections == 0 &&
        proof.Operations == 0 && proof.Persisted && !proof.PublicPromotion;
    private static void Need(bool condition) { if (!condition) throw new InvalidDataException("Reference contract refused input"); }
}
#endif
