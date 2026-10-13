using System.Globalization;
using System.Text.RegularExpressions;
using SafeUpload.Agent.Core.Domain.Validators;

namespace SafeUpload.Agent.Core.Domain;

/// <summary>Complete bounded passes over the same immutable text; only masked findings escape.</summary>
public static class StreamingContentScanner
{
    private const int BufferCharacters = 8192;
    private const int FixedPatternOverlap = 260; // Max fixed match + preceding boundary character.
    internal const int MaximumCandidates = 16_384;
    private readonly record struct Range(long Start, long End);
    private readonly record struct Located(long Start, Finding Finding);
    private readonly record struct Secret(long Start, long End, string Kind);

    /// <summary>The factory rewinds the same immutable source. Readers are disposed after every pass.</summary>
    public static async Task<IReadOnlyList<Finding>> ScanAsync(Func<Task<TextReader>> openReader,
        IReadOnlySet<Category> active, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(openReader);
        ArgumentNullException.ThrowIfNull(active);
        token.ThrowIfCancellationRequested();
        var state = new ScanState();
        bool read = false;
        foreach (var (category, count) in new[] { (Category.PaymentCard, 16), (Category.Cnpj, 14), (Category.Cpf, 11) })
            if (active.Contains(category))
            {
                await ReadPassAsync(openReader, new NumericPass(state, category, count), token).ConfigureAwait(false);
                read = true;
            }

        if (active.Contains(Category.Secret))
        {
            read = true;
            await ScanBoundedSecretsAsync(openReader, state, token).ConfigureAwait(false);
            await ReadPassAsync(openReader, new TokenPass(state, jwt: false), token).ConfigureAwait(false);
            await ReadPassAsync(openReader, new TokenPass(state, jwt: true), token).ConfigureAwait(false);
            // All numeric rules finish before secrets; earlier outer secret
            // matches win even when an inner fixed token ended much sooner.
            state.Secrets.Sort(static (left, right) => left.Start.CompareTo(right.Start));
            foreach (var secret in state.Secrets)
                if (!state.Overlaps(secret.Start, secret.End))
                    state.Add(secret.Start, secret.End, new(Category.Secret, Masking.MaskSecret(secret.Kind)));
            state.Secrets.Clear();
        }
        if (active.Contains(Category.Password))
        {
            await ReadPassAsync(openReader, new PasswordPass(state), token).ConfigureAwait(false);
            read = true;
        }
        if (!read)
        {
            // Extraction still validates the complete encoding even when no
            // recognized category needs a detector pass.
            using var reader = await openReader().ConfigureAwait(false);
            var buffer = new char[BufferCharacters];
            while (await reader.ReadAsync(buffer.AsMemory(), token).ConfigureAwait(false) != 0)
                token.ThrowIfCancellationRequested();
        }
        state.Found.Sort(static (left, right) => left.Start.CompareTo(right.Start));
        return state.Found.ConvertAll(static value => value.Finding);
    }

    private interface ICharacterPass
    {
        void Push(char value, long position);
        void Finish(long length);
    }

    private static async Task ReadPassAsync(Func<Task<TextReader>> openReader, ICharacterPass pass, CancellationToken token)
    {
        using var reader = await openReader().ConfigureAwait(false);
        var buffer = new char[BufferCharacters]; long position = 0;
        int count;
        while ((count = await reader.ReadAsync(buffer.AsMemory(), token).ConfigureAwait(false)) != 0)
        {
            token.ThrowIfCancellationRequested();
            for (int i = 0; i < count; i++) pass.Push(buffer[i], checked(position++));
        }
        pass.Finish(position);
    }

    private sealed class ScanState
    {
        private readonly List<Range> _consumed = [];
        public List<Located> Found { get; } = [];
        public List<Secret> Secrets { get; } = [];
        private int Insertion(long start)
        {
            int low = 0, high = _consumed.Count;
            while (low < high)
            {
                int middle = low + (high - low) / 2;
                if (_consumed[middle].Start < start) low = middle + 1; else high = middle;
            }
            return low;
        }
        public bool Overlaps(long start, long end)
        {
            int index = Insertion(start);
            return index > 0 && _consumed[index - 1].End >= start ||
                index < _consumed.Count && _consumed[index].Start <= end;
        }
        public void Add(long start, long end, Finding finding)
        {
            if (Found.Count == MaximumCandidates) throw new InspectionLimitException();
            long findingStart = start;
            int first = Insertion(start);
            if (first > 0 && _consumed[first - 1].End >= start) first--;
            int last = first;
            while (last < _consumed.Count && _consumed[last].Start <= end)
            {
                start = Math.Min(start, _consumed[last].Start);
                end = Math.Max(end, _consumed[last].End);
                last++;
            }
            if (last != first) _consumed.RemoveRange(first, last - first);
            _consumed.Insert(first, new(start, end));
            Found.Add(new(findingStart, finding));
        }
        public void AddSecret(long start, long end, string kind)
        {
            if (Overlaps(start, end)) return;
            if (Secrets.Count == MaximumCandidates) throw new InspectionLimitException();
            Secrets.Add(new(start, end, kind));
        }
    }

    private sealed class NumericPass(ScanState state, Category category, int width) : ICharacterPass
    {
        private readonly long[] _positions = new long[width];
        private readonly char[] _digits = new char[width];
        private readonly char[] _candidate = new char[width];
        private int _next, _count;
        private bool _separator;
        public void Push(char value, long position)
        {
            if (!char.IsAsciiDigit(value))
            {
                if (_count != 0 && !_separator && value is '.' or '-' or '/' or ' ') { _separator = true; return; }
                _next = _count = 0; _separator = false; return;
            }
            _separator = false;
            _positions[_next] = position; _digits[_next] = value;
            _next = (_next + 1) % width;
            if (_count < width) _count++;
            if (_count != width || state.Overlaps(_positions[_next], position)) return;
            _digits.AsSpan(_next).CopyTo(_candidate);
            _digits.AsSpan(0, _next).CopyTo(_candidate.AsSpan(width - _next));
            bool valid = category switch
            {
                Category.PaymentCard => LuhnValidator.IsValid(_candidate),
                Category.Cnpj => CnpjValidator.IsValid(_candidate),
                _ => CpfValidator.IsValid(_candidate)
            };
            if (valid) state.Add(_positions[_next], position, new(category, Masking.Mask(new string(_candidate))));
        }
        public void Finish(long length) { }
    }

    private static async Task ScanBoundedSecretsAsync(Func<Task<TextReader>> openReader, ScanState state, CancellationToken token)
    {
        using var reader = await openReader().ConfigureAwait(false);
        var rules = SecretDetector.BoundedRules.ToArray(); var ends = new long[rules.Length];
        var buffer = new char[BufferCharacters]; string carry = ""; long length = 0;
        int count;
        while ((count = await reader.ReadAsync(buffer.AsMemory(), token).ConfigureAwait(false)) != 0)
        {
            token.ThrowIfCancellationRequested();
            string window = carry + new string(buffer, 0, count); long start = length - carry.Length;
            length = checked(length + count);
            ScanWindow(window, start, eof: false);
            carry = window.Length <= FixedPatternOverlap ? window : window[^FixedPatternOverlap..];
        }
        ScanWindow(carry, length - carry.Length, eof: true);

        void ScanWindow(string window, long start, bool eof)
        {
            for (int i = 0; i < rules.Length; i++)
            {
                int offset = (int)Math.Clamp(ends[i] - start, 0, window.Length);
                foreach (Match match in rules[i].Pattern.Matches(window, offset))
                {
                    // Retain actual left/right boundary context. End-of-window
                    // is not EOF; a following word char can revoke a token match.
                    if (match.Index == 0 && start != 0 || !eof && match.Index + match.Length == window.Length) continue;
                    long begin = start + match.Index, end = begin + match.Length;
                    ends[i] = end;
                    state.AddSecret(begin, end - 1, rules[i].Kind);
                }
            }
        }
    }

    // Regex \b includes Unicode marks/connectors and both zero-width joiners.
    // Mirror .NET's boundary categories, not ASCII or letter/digit alone.
    private static bool BoundaryWord(char value) => value is '\u200C' or '\u200D' ||
        char.GetUnicodeCategory(value) is UnicodeCategory.UppercaseLetter or UnicodeCategory.LowercaseLetter or
        UnicodeCategory.TitlecaseLetter or UnicodeCategory.ModifierLetter or UnicodeCategory.OtherLetter or
        UnicodeCategory.NonSpacingMark or UnicodeCategory.DecimalDigitNumber or UnicodeCategory.ConnectorPunctuation;
    private static bool AlphaNumeric(char value) => value is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9';

    private sealed class PrefixWindow(int capacity)
    {
        private readonly char[] _values = new char[capacity];
        private readonly bool[] _boundaries = new bool[capacity];
        private int _next, _count;
        private bool _previousWord;
        public void Push(char value)
        {
            _values[_next] = value; _boundaries[_next] = !_previousWord;
            _next = (_next + 1) % capacity; if (_count < capacity) _count++;
            _previousWord = BoundaryWord(value);
        }
        public string? Suffix(int length)
        {
            if (_count < length) return null;
            int first = (_next + capacity - length) % capacity;
            if (!_boundaries[first]) return null;
            var value = new char[length];
            for (int i = 0; i < length; i++) value[i] = _values[(first + i) % capacity];
            return new(value);
        }
    }

    private sealed class TokenPass(ScanState state, bool jwt) : ICharacterPass
    {
        private readonly PrefixWindow _prefix = new(5);
        private long _start, _count;
        private int _segment;
        public void Push(char value, long position)
        {
            _prefix.Push(value);
            if (_segment != 0)
            {
                bool member = AlphaNumeric(value) || value == '-' || jwt && value == '_';
                if (member) { _count++; return; }
                if (jwt && value == '.' && _segment < 3 && _count >= 8)
                { _segment++; _count = 0; return; }
                Complete(position);
            }
            if (jwt && value == 'J' && _prefix.Suffix(3) == "eyJ")
            { _start = position - 2; _segment = 1; _count = 0; }
            else if (!jwt && value == '-' && _prefix.Suffix(5) is { } prefix &&
                prefix[..3] == "xox" && prefix[3] is 'b' or 'a' or 'p' or 'r' or 's')
            { _start = position - 4; _segment = 1; _count = 0; }
        }
        private void Complete(long position)
        {
            if (jwt ? _segment == 3 && _count >= 8 : _segment == 1 && _count >= 10)
                state.AddSecret(_start, position - 1, jwt ? "JSON Web Token" : "token do Slack");
            _segment = 0; _count = 0;
        }
        public void Finish(long length) => Complete(length);
    }

    private sealed class PasswordPass(ScanState state) : ICharacterPass
    {
        private static readonly int[] LabelWidths = [3, 5, 6, 8];
        private readonly PrefixWindow _prefix = new(8);
        private int _phase;
        private long _start, _secretStart, _count;
        private string _label = "";
        public void Push(char value, long position)
        {
            _prefix.Push(value);
            if (_phase == 1)
            {
                if (char.IsWhiteSpace(value)) return;
                if (value is ':' or '=') { _phase = 2; return; }
                _phase = 0;
            }
            if (_phase == 2)
            {
                if (char.IsWhiteSpace(value)) return;
                _phase = 3; _secretStart = position; _count = 1; return;
            }
            if (_phase == 3)
            {
                if (!char.IsWhiteSpace(value)) { _count++; return; }
                Complete(position);
            }
            if (char.ToUpperInvariant(value) is not ('D' or 'A')) return;
            foreach (int width in LabelWidths)
                if (_prefix.Suffix(width) is { } label && PasswordHeuristic.IsLabel(label))
                { _label = label; _start = position - width + 1; _phase = 1; return; }
        }
        private void Complete(long position)
        {
            if (_phase == 3 && _count >= 4 && !state.Overlaps(_secretStart, position - 1))
                state.Add(_start, position - 1, new(Category.Password, Masking.MaskSecret(_label)));
            _phase = 0; _count = 0;
        }
        public void Finish(long length) => Complete(length);
    }
}

/// <summary>A bounded analysis cannot complete; no partial result is approval evidence.</summary>
public sealed class InspectionLimitException : Exception
{
    public InspectionLimitException() : base("The bounded inspection candidate limit was reached.") { }
}
