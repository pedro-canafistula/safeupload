using System.Text;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Tests;

public class NumericWindowTests
{
    public static IEnumerable<object[]> NumericCategorySets()
    {
        for (var bits = 0; bits < 8; bits++)
        {
            yield return [bits, false];
            yield return [bits, true];
        }
    }

    [Theory]
    [MemberData(nameof(NumericCategorySets))]
    public void Numeric_window_matches_prior_full_run_semantics(int bits, bool separated)
    {
        var categories = Active(bits);
        var random = new Random(426713);
        var input = new StringBuilder();
        for (var run = 0; run < 24; run++)
        {
            input.Append("\nedge:");
            for (var digit = 0; digit < 25 + run; digit++)
            {
                input.Append((char)('0' + random.Next(10)));
                if (separated)
                {
                    input.Append(".-/ "[random.Next(4)]);
                }
            }

            // Valid values cross ring wraps and accepted single separators;
            // doubled separators and field boundaries break the run instead.
            input.Append("52998224725 11222333000181 4111111111111111");
            input.Append(" 529.982.247-25;11.222.333/0001-81;4111 1111 1111 1111");
            input.Append(" 529..982.247-25 11222333,000181 41111111\n11111111");
            input.Append(" \t٠١٢٣٤٥٦٧٨٩ 529/982/247/25 ");
        }

        var text = input.ToString();
        var expected = NumericWindowReferenceScanner.Scan(text, categories);
        var actual = ContentScanner.Scan(text, categories);
        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData("52998224725", Category.Cpf)]
    [InlineData("11.222.333/0001-81", Category.Cnpj)]
    [InlineData("4111 1111 1111 1111", Category.PaymentCard)]
    public void Numeric_window_preserves_consumed_source_interval_for_passwords(string value, Category category)
    {
        var findings = ContentScanner.Scan("prefix senha = " + value, Enum.GetValues<Category>().ToHashSet());
        Assert.Equal(category, Assert.Single(findings).Category);
    }

    [Fact]
    public void Numeric_scan_of_long_clean_runs_does_not_allocate_per_digit()
    {
        var categories = Active(7);
        // Input allocation is outside the measured scanner interval. This is
        // only numeric scratch-space qualification, not whole-file streaming.
        // Ones, not zeros: every 13-19 digit window of zeros passes Luhn, so a
        // zero run is a (correct) payment-card match; a run of ones fails Luhn
        // at every length and CPF/CNPJ reject repeated digits.
        var text = new string('1', 2 * 1024 * 1024);
        Assert.Empty(ContentScanner.Scan(new string('1', 128), categories));
        var before = GC.GetAllocatedBytesForCurrentThread();
        var findings = ContentScanner.Scan(text, categories);
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.Empty(findings);
        Assert.True(allocated < 128 * 1024, $"Numeric scratch allocations: {allocated}");
    }

    private static IReadOnlySet<Category> Active(int bits)
    {
        var categories = new HashSet<Category>();
        if ((bits & 1) != 0) categories.Add(Category.Cpf);
        if ((bits & 2) != 0) categories.Add(Category.Cnpj);
        if ((bits & 4) != 0) categories.Add(Category.PaymentCard);
        return categories;
    }
}
