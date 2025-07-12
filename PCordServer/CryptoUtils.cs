using System.Security.Cryptography;

namespace PCordServer;

public static class CryptoUtils
{
    private static readonly byte[] Salt = "3h37Adm28jH2h9TUifAA7ff6zE4BLfV4"u8.ToArray();

    private static void GenerateKeyFromPassword(string password, out byte[] key, out byte[] iv)
    {
        using var keyDerivationFunction = new Rfc2898DeriveBytes(password, Salt, 10000);
        key = keyDerivationFunction.GetBytes(32);
        iv = keyDerivationFunction.GetBytes(16);
    }

    public static string EncryptString(string plainText, string password)
    {
        GenerateKeyFromPassword(password, out var key, out var iv);

        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        aes.Padding = PaddingMode.PKCS7;

        using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
        using var ms = new MemoryStream();
        using (var cryptoStream = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
        using (var sw = new StreamWriter(cryptoStream))
        {
            sw.Write(plainText);
        }

        var encryptedBytes = ms.ToArray();
        return Convert.ToBase64String(encryptedBytes);
    }
    
    public static string DecryptString(string cipherText, string password)
    {
        GenerateKeyFromPassword(password, out var key, out var iv);

        var cipherBytes = Convert.FromBase64String(cipherText);

        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        aes.Padding = PaddingMode.PKCS7;

        using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
        using var ms = new MemoryStream(cipherBytes);
        using var cryptoStream = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
        using var sr = new StreamReader(cryptoStream);

        return sr.ReadToEnd();
    }
}