using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.X509;
using Ed25519 = Org.BouncyCastle.Math.EC.Rfc8032.Ed25519;

namespace SafeUpload.Agent.Core.Infrastructure;

/// <summary>RFC 8032 Ed25519, not Ed25519ph. No dependency on Windows CNG curve availability.</summary>
internal static class Ed25519AgentKey
{
    internal static byte[] GenerateSeed() => RandomNumberGenerator.GetBytes(32);

    internal static string PublicKey(byte[] seed)
    {
        if (seed.Length != 32) throw new CryptographicException();
        byte[] publicKey = new byte[32];
        Ed25519.GeneratePublicKey(seed, 0, publicKey, 0);
        return Convert.ToBase64String(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(
            new Ed25519PublicKeyParameters(publicKey, 0)).GetDerEncoded());
    }

    internal static string SignHost(byte[] seed, int hostId)
    {
        if (seed.Length != 32) throw new CryptographicException();
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(hostId);
        byte[] message = Encoding.UTF8.GetBytes(hostId.ToString(CultureInfo.InvariantCulture));
        byte[] signature = new byte[64];
        Ed25519.Sign(seed, 0, message, 0, message.Length, signature, 0);
        return Convert.ToBase64String(signature);
    }
}
