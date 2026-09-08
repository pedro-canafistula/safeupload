// Builds a SAFEUPLOAD_POLICY_MESSAGE, including the path conversion that
// is the easiest thing to get wrong on this contract.
//
// The kernel compares against the names the Filter Manager gives it, and
// those are always in device form: \Device\HarddiskVolume3\pasta\arquivo.
// A prefix pushed as "C:\pasta" matches nothing, the driver inspects
// nothing, and every test still passes because allowing is the safe
// default. Nothing reports this - the only visible symptom is a scope
// counter that stays at zero.

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace SafeUpload.Agent.Minifilter;

public sealed class PolicyBuilder
{
    private readonly List<string> _extensions = new();
    private readonly List<string> _destinationPrefixes = new();
    private readonly List<string> _sourcePrefixes = new();
    private readonly List<string> _excludedImages = new();

    private PolicyFlags _flags = PolicyFlags.None;

    private uint _verdictTimeoutMs;

    /// <summary>Extension including the dot, e.g. ".docx".</summary>
    public PolicyBuilder WithExtension(string extension)
    {
        _extensions.Add(extension);
        return this;
    }

    /// <summary>DOS path, e.g. @"C:\Users\vitor\OneDrive". Converted here.</summary>
    public PolicyBuilder WithDestination(string dosPath)
    {
        _destinationPrefixes.Add(ToNtPath(dosPath));
        return this;
    }

    public PolicyBuilder WithSource(string dosPath)
    {
        _sourcePrefixes.Add(ToNtPath(dosPath));
        return this;
    }

    /// <summary>Image name only, no path, e.g. "MsMpEng.exe".</summary>
    public PolicyBuilder WithExcludedImage(string imageName)
    {
        _excludedImages.Add(imageName);
        return this;
    }

    /// <summary>
    /// Treat every removable or network volume as a monitored destination,
    /// with no path matching at all. This is the case that matters most:
    /// a pen drive is where a refusal has to leave nothing behind, and the
    /// volume kind answers it without resolving a single name.
    /// </summary>
    public PolicyBuilder WithVolumeKinds(bool removable, bool network)
    {
        if (removable) { _flags |= PolicyFlags.Removable; }
        if (network) { _flags |= PolicyFlags.Network; }
        return this;
    }

    /// <summary>
    /// Quanto o kernel deve esperar por um veredito.
    ///
    /// Deriva da RN-012, e a razao de passar isto adiante em vez de deixar
    /// o driver com uma constante: o prazo e o do motor, e quem sabe quanto
    /// o motor precisa e o motor. Nao chamar deixa o padrao do driver.
    /// </summary>
    /// <summary>
    /// Liga o modo auditoria: nada e negado, tudo e contado.
    ///
    /// E como se implanta DLP sem ser desinstalado na primeira semana - e,
    /// aqui, e a unica forma de medir a taxa de falso positivo da
    /// contaminacao antes de decidir se ela vale.
    /// </summary>
    public PolicyBuilder WithAuditOnly(bool auditOnly)
    {
        if (auditOnly)
        {
            _flags |= PolicyFlags.AuditOnly;
        }
        else
        {
            _flags &= ~PolicyFlags.AuditOnly;
        }

        return this;
    }

    /// <summary>
    /// Liga o modo que deixa o usuario justificar uma recusa e seguir.
    /// </summary>
    public PolicyBuilder WithOverrideAllowed(bool allowed)
    {
        if (allowed)
        {
            _flags |= PolicyFlags.AllowOverride;
        }
        else
        {
            _flags &= ~PolicyFlags.AllowOverride;
        }

        return this;
    }

    public PolicyBuilder WithVerdictTimeout(TimeSpan timeout)
    {
        _verdictTimeoutMs = (uint) Math.Clamp(timeout.TotalMilliseconds, 100, 10_000);
        return this;
    }

    public unsafe SafeUploadPolicyMessage Build()
    {
        Require(_extensions.Count, Contract.MaxExtensions, nameof(_extensions));
        Require(_destinationPrefixes.Count, Contract.MaxPrefixes, nameof(_destinationPrefixes));
        Require(_sourcePrefixes.Count, Contract.MaxSourcePrefixes, nameof(_sourcePrefixes));
        Require(_excludedImages.Count, Contract.MaxImages, nameof(_excludedImages));

        SafeUploadPolicyMessage message = default;

        message.ExtensionCount = (uint) _extensions.Count;
        message.PrefixCount = (uint) _destinationPrefixes.Count;
        message.SourcePrefixCount = (uint) _sourcePrefixes.Count;
        message.ImageCount = (uint) _excludedImages.Count;
        message.Flags = (uint) _flags;
        message.VerdictTimeoutMs = _verdictTimeoutMs;

        Fill(message.Extensions, _extensions, Contract.MaxExtensionChars);
        Fill(message.Prefixes, _destinationPrefixes, Contract.MaxPrefixChars);
        Fill(message.SourcePrefixes, _sourcePrefixes, Contract.MaxPrefixChars);
        Fill(message.Images, _excludedImages, Contract.MaxImageChars);

        return message;
    }

    private static void Require(int count, int max, string what)
    {
        if (count > max)
        {
            throw new ArgumentException($"{what}: {count} entradas, o maximo e {max}.");
        }
    }

    // Each entry occupies a fixed slot and must stay null-terminated: the
    // driver measures the string, so an entry written to the last char of
    // its slot would run into the next one.
    private static unsafe void Fill(char* table, List<string> values, int slotChars)
    {
        for (int i = 0; i < values.Count; i += 1)
        {
            string value = values[i];

            if (value.Length >= slotChars)
            {
                throw new ArgumentException(
                    $"\"{value}\" tem {value.Length} caracteres; o limite do slot e {slotChars - 1}.");
            }

            char* slot = table + (i * slotChars);

            for (int c = 0; c < value.Length; c += 1)
            {
                slot[c] = value[c];
            }

            slot[value.Length] = '\0';
        }
    }

    /// <summary>
    /// Converts C:\pasta into \Device\HarddiskVolumeN\pasta.
    ///
    /// Only the drive letter is translated; the rest of the path is
    /// appended as given. A UNC path has no DOS device to resolve and is
    /// returned unchanged - network destinations are meant to be covered
    /// by the volume-kind flag, not by a prefix.
    /// </summary>
    public static string ToNtPath(string dosPath)
    {
        if (string.IsNullOrEmpty(dosPath))
        {
            throw new ArgumentException("Caminho vazio.", nameof(dosPath));
        }

        if (dosPath.StartsWith(@"\\", StringComparison.Ordinal) ||
            dosPath.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
        {
            return dosPath;
        }

        if (dosPath.Length < 2 || dosPath[1] != ':')
        {
            throw new ArgumentException($"\"{dosPath}\" nao comeca com letra de unidade.", nameof(dosPath));
        }

        var device = new StringBuilder(1024);
        string drive = dosPath.Substring(0, 2);

        if (QueryDosDeviceW(drive, device, device.Capacity) == 0)
        {
            throw new ArgumentException(
                $"QueryDosDevice falhou para \"{drive}\": {Marshal.GetLastWin32Error()}.", nameof(dosPath));
        }

        return device.ToString() + dosPath.Substring(2);
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint QueryDosDeviceW(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);
}
