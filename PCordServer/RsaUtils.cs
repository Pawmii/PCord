using System.Security.Cryptography;
using System.Text;

namespace PCordServer;

public static class RsaUtils
{
    public static bool VerifyMessage(string message, string signatureBase64, string publicKeyBase64)
    {
        using var rsa = RSA.Create();

        byte[] publicKeyBytes = Convert.FromBase64String(publicKeyBase64);
        rsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);

        byte[] data = Encoding.UTF8.GetBytes(message);
        byte[] signature = Convert.FromBase64String(signatureBase64);

        return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }
}