namespace SafeUpload.Agent.Service.Interception;

// Comparison only, never a descriptor constructor or an access grant. The
// caller must obtain both descriptors from the exact native objects. A hash,
// path or process SID is not evidence that a file has the moved-save shape.
internal static class StagedPublicationSecurity
{
    internal static bool Equivalent(ReadOnlySpan<byte> expected, ReadOnlySpan<byte> stored,
        bool provedMovedFileSave = false)
    {
        byte[] reference = StagedSecurityDescriptor.Canonicalize(expected);
        byte[] actual = StagedSecurityDescriptor.Canonicalize(stored);
        if (reference.AsSpan().SequenceEqual(actual)) return true;
        if (!provedMovedFileSave || reference.Length != actual.Length ||
            (reference[3] & 4) == 0 || (actual[3] & 4) != 0) return false;
        // Owner-approved exception is directional and shape-specific. In
        // particular SACL auto-inheritance (0x0800), protection/defaulted/
        // request bits, RM byte and every ordered ACE remain byte-exact.
        reference[3] &= 0xfb;
        return reference.AsSpan().SequenceEqual(actual);
    }
}
