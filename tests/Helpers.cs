using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;

namespace Tests;

internal static class Helpers {

    public static List<TestBlock> GetTestBlocks(Stream fileStream) {
        var result = new List<TestBlock>();

        using (var s = new StreamReader(fileStream)) {
            int? keySize = null, i = null;
            byte[] key = null, iv = null, ct = null, pt = null;

            while (!s.EndOfStream) {
                var line = s.ReadLine();
                if (line.StartsWith("KEYSIZE=", StringComparison.Ordinal)) {
                    keySize = int.Parse(line[8..], CultureInfo.InvariantCulture);
                    i = null;
                } else if (line.StartsWith("I=", StringComparison.Ordinal)) {
                    if (keySize == null) { continue; }
                    i = int.Parse(line[2..], CultureInfo.InvariantCulture);
                } else if (line.StartsWith("KEY=", StringComparison.Ordinal)) {
                    key = ParseBytes(line[4..]);
                } else if (line.StartsWith("IV=", StringComparison.Ordinal)) {
                    iv = ParseBytes(line[3..]);
                } else if (line.StartsWith("PT=", StringComparison.Ordinal)) {
                    pt = ParseBytes(line[3..]);
                } else if (line.StartsWith("CT=", StringComparison.Ordinal)) {
                    ct = ParseBytes(line[3..]);
                } else if (line.Equals("", StringComparison.Ordinal)) {
                    if (i == null) { continue; }
                    result.Add(new TestBlock(keySize.Value, i.Value, key, iv, pt, ct));
                    i = null; key = null; iv = null; ct = null; pt = null;
                }
            }
        }

        return result;
    }

    public static byte[] ParseBytes(string hex) {
        Trace.Assert((hex.Length % 2) == 0);
        var result = new byte[hex.Length / 2];
        for (var i = 0; i < hex.Length; i += 2) {
            result[i / 2] = byte.Parse(hex.AsSpan(i, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        }
        return result;
    }

    [DebuggerDisplay("{KeySize}:{Index}")]
    public readonly struct TestBlock {
        internal TestBlock(int keySize, int index, byte[] key, byte[] iv, byte[] plainText, byte[] cipherText) {
            KeySize = keySize;
            Index = index;
            Key = key;
            IV = iv;
            PlainText = plainText;
            CipherText = cipherText;
        }
        internal int KeySize { get; }
        internal int Index { get; }
        internal byte[] Key { get; }
        internal byte[] IV { get; }
        internal byte[] PlainText { get; }
        internal byte[] CipherText { get; }
    }


    public static byte[] Encrypt(SymmetricAlgorithm algorithm, byte[] key, byte[] iv, byte[] pt) {
        using var ms = new MemoryStream();
        using (var transform = algorithm.CreateEncryptor(key, iv)) {
            using var cs = new CryptoStream(ms, transform, CryptoStreamMode.Write);
            cs.Write(pt, 0, pt.Length);
        }
        return ms.ToArray();
    }

    public static byte[] Decrypt(SymmetricAlgorithm algorithm, byte[] key, byte[] iv, byte[] ct) {
        using var ctStream = new MemoryStream(ct);
        using var transform = algorithm.CreateDecryptor(key, iv);
        using var cs = new CryptoStream(ctStream, transform, CryptoStreamMode.Read);
        using var ms = new MemoryStream();
        cs.CopyTo(ms);
        return ms.ToArray();
    }


    public static Stream GetResourceStream(string relativePath) {
        if (relativePath == null) { return null; }
        var helperType = typeof(Helpers).GetTypeInfo();
        var assembly = helperType.Assembly;
        return assembly.GetManifestResourceStream(helperType.Namespace + ".Resources." + relativePath);
    }

}
