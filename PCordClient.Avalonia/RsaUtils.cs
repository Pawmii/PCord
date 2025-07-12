using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace PCordClient.Avalonia;

public static class RsaUtils
{
    private static RSA? _rsa;
    private static string? _privateKeyBase64;
    private static string? _publicKeyBase64;

    public static void GenerateKeys()
    {
        _rsa = RSA.Create(2048);

        byte[] privateKeyBytes = _rsa.ExportPkcs8PrivateKey();
        _privateKeyBase64 = Convert.ToBase64String(privateKeyBytes);

        byte[] publicKeyBytes = _rsa.ExportSubjectPublicKeyInfo();
        _publicKeyBase64 = Convert.ToBase64String(publicKeyBytes);

        SaveKeysToFiles();
    }

    public static string GetPublicKey() => _publicKeyBase64 ?? string.Empty;

    public static string SignMessage(string message)
    {
        if (_privateKeyBase64 == null)
            throw new InvalidOperationException("Ключи не сгенерированы");

        using var rsa = RSA.Create();

        byte[] privateKeyBytes = Convert.FromBase64String(_privateKeyBase64);
        rsa.ImportPkcs8PrivateKey(privateKeyBytes, out _);

        byte[] data = Encoding.UTF8.GetBytes(message);
        byte[] signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        return Convert.ToBase64String(signature);
    }

    public static void SaveKeysToFiles(string privatePath = "private.key", string publicPath = "public.key")
    {
        try
        {
            if (_privateKeyBase64 != null)
                File.WriteAllText(privatePath, _privateKeyBase64);

            if (_publicKeyBase64 != null)
                File.WriteAllText(publicPath, _publicKeyBase64);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Ошибка при сохранении ключей: {ex.Message}");
        }
    }

    public static bool LoadKeysFromFiles(string privatePath = "private.key", string publicPath = "public.key")
    {
        try
        {
            if (File.Exists(privatePath))
                _privateKeyBase64 = File.ReadAllText(privatePath);

            if (File.Exists(publicPath))
                _publicKeyBase64 = File.ReadAllText(publicPath);

            return !string.IsNullOrEmpty(_privateKeyBase64) && !string.IsNullOrEmpty(_publicKeyBase64);
        }
        catch
        {
            _privateKeyBase64 = null;
            _publicKeyBase64 = null;
            return false;
        }
    }
}