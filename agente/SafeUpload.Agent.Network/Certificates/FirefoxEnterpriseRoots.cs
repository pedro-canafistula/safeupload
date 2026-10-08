using Microsoft.Win32;

namespace SafeUpload.Agent.Network.Certificates;

/// <summary>
/// Faz o Firefox confiar na CA de inspeção.
///
/// Chrome e Edge usam a lista de raízes do Windows, então para eles basta a CA
/// em LocalMachine\Root. O Firefox tem uma lista própria e, por padrão, ignora
/// a do sistema. A política corporativa ImportEnterpriseRoots manda o Firefox
/// também aceitar as raízes do Windows.
///
/// O plano falava em <c>policies.json</c>; aqui a política vai pelo registro
/// (HKLM\SOFTWARE\Policies\Mozilla\Firefox), que o Firefox lê da mesma forma.
/// O registro não depende de onde o Firefox foi instalado, não é sobrescrito
/// quando ele se atualiza e já existe antes de o Firefox ser instalado.
/// </summary>
public static class FirefoxEnterpriseRoots
{
    private const string PolicyKey = @"SOFTWARE\Policies\Mozilla\Firefox\Certificates";
    private const string ValueName = "ImportEnterpriseRoots";

    /// <summary>Liga a política. Exige administrador ou SYSTEM.</summary>
    public static void Enable()
    {
        using RegistryKey key = Registry.LocalMachine.CreateSubKey(PolicyKey, writable: true);
        key.SetValue(ValueName, 1, RegistryValueKind.DWord);
    }

    /// <summary>
    /// Desliga a política, na desinstalação. Remove só o valor que este agente
    /// grava; as demais políticas do Firefox na máquina ficam como estão.
    /// </summary>
    public static void Disable()
    {
        using RegistryKey? key = Registry.LocalMachine.OpenSubKey(PolicyKey, writable: true);
        key?.DeleteValue(ValueName, throwOnMissingValue: false);
    }

    /// <summary>Indica se a política está ligada.</summary>
    public static bool IsEnabled()
    {
        using RegistryKey? key = Registry.LocalMachine.OpenSubKey(PolicyKey);
        return key?.GetValue(ValueName) is int value && value == 1;
    }
}
