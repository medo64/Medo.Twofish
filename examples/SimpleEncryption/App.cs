using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Medo.Security.Cryptography;

namespace SimpleEncryption;

internal static class App {

    public static void Main() {
        // setup algorithm
        using var algorithm = new Twofish() {
            KeySize = 256,
            Mode = CipherMode.CBC,
            Padding = PaddingMode.PKCS7
        };

        // generate key and IV (you probably want to use PBKDF2 instead of random key generated here)
        algorithm.GenerateKey();
        algorithm.GenerateIV();
        //algorithm.Key =
        //algorithm.IV =


        // setup encryption input and output streams - e.g. from memory or file
        var inPlainTextStream = new MemoryStream(Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog"));
        var outCipherTextStream = new MemoryStream();

        // encrypt
        using var encryptor = algorithm.CreateEncryptor();
        using (var csWrite = new CryptoStream(outCipherTextStream, encryptor, CryptoStreamMode.Write)) {
            inPlainTextStream.CopyTo(csWrite);
        }


        // setup decryption input and output streams - e.g. from memory or file
        var inCipherTextStream = new MemoryStream(outCipherTextStream.ToArray());
        var outPlainTextStream = new MemoryStream();

        // decrypt
        using var decryptor = algorithm.CreateDecryptor();
        using (var csRead = new CryptoStream(inCipherTextStream, decryptor, CryptoStreamMode.Read)) {
            csRead.CopyTo(outPlainTextStream);
        }

        Console.WriteLine("Input:");
        DumpStream(inPlainTextStream);
        Console.WriteLine();

        Console.WriteLine("Encrypted:");
        DumpStream(outCipherTextStream);
        Console.WriteLine();

        Console.WriteLine("Decrypted:");
        DumpStream(outPlainTextStream);
        Console.WriteLine();
    }


    private static void DumpStream(MemoryStream memory) {
        var bytes = memory.ToArray();

        var outText = new StringBuilder("  ");
        var outHex = new StringBuilder(" ");

        foreach (var b in bytes) {
            outText.Append(' ');
            if (b is >= 32 and < 127) {
                outText.Append((char)b);
            } else {
                outText.Append('·');
            }
            outText.Append(' ');

            outHex.Append(' ');
            outHex.Append(b.ToString("X2"));
        }

        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine(outHex);
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine(outText);
        Console.ResetColor();
    }

}
