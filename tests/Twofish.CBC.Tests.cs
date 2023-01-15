using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Medo.Security.Cryptography;

using static Tests.Helpers;

namespace Tests;

[TestClass]
public class Twofish_CBC_Tests {

    [TestMethod]
    public void Twofish_CBC_MonteCarlo_Encrypt_One() {
        var tests = GetTestBlocks(GetResourceStream("CBC_E_M.TXT"));
        var test = tests[Random.Shared.Next(tests.Count)];
        MonteCarlo_CBC_E(test);
    }

    [TestMethod]
    public void Twofish_CBC_MonteCarlo_Decrypt_One() {
        var tests = GetTestBlocks(GetResourceStream("CBC_D_M.TXT"));
        var test = tests[Random.Shared.Next(tests.Count)];
        MonteCarlo_CBC_D(test);
    }


    [Ignore]
    [TestMethod]
    public void Twofish_CBC_MonteCarlo_Encrypt() { //takes ages
        var tests = GetTestBlocks(GetResourceStream("CBC_E_M.TXT"));
        var sw = Stopwatch.StartNew();
        foreach (var test in tests) {
            MonteCarlo_CBC_E(test);
        }
        sw.Stop();
        Debug.WriteLine("Duration: " + sw.ElapsedMilliseconds.ToString() + " ms");
    }

    [Ignore]
    [TestMethod]
    public void Twofish_CBC_MonteCarlo_Decrypt() { //takes ages
        var tests = GetTestBlocks(GetResourceStream("CBC_D_M.TXT"));
        var sw = Stopwatch.StartNew();
        foreach (var test in tests) {
            MonteCarlo_CBC_D(test);
        }
        sw.Stop();
        Debug.WriteLine("Duration: " + sw.ElapsedMilliseconds.ToString() + " ms");
    }


    [DataTestMethod]
    [DataRow(PaddingMode.None)]
    [DataRow(PaddingMode.PKCS7)]
    [DataRow(PaddingMode.Zeros)]
    [DataRow(PaddingMode.ANSIX923)]
    [DataRow(PaddingMode.ISO10126)]
    public void Twofish_CBC_Randomised(PaddingMode padding) {
        for (var n = 0; n < 1000; n++) {
            var crypto = new Twofish() { Padding = padding };
            crypto.GenerateKey();
            crypto.GenerateIV();
            var data = new byte[Random.Shared.Next(100)];
            if (padding is PaddingMode.None) { data = new byte[data.Length / 16 * 16]; }  // make it rounded number if no padding
            RandomNumberGenerator.Fill(data);
            if ((padding == PaddingMode.Zeros) && (data.Length > 0)) { data[^1] = 1; }  // zero padding needs to have the last number non-zero

            var ct = Encrypt(crypto, crypto.Key, crypto.IV, data);
            if (padding is PaddingMode.None or PaddingMode.Zeros) {
                Assert.IsTrue(data.Length <= ct.Length);
            } else {
                Assert.IsTrue(data.Length < ct.Length);
            }

            var pt = Decrypt(crypto, crypto.Key, crypto.IV, ct);
            Assert.AreEqual(data.Length, pt.Length);
            Assert.AreEqual(BitConverter.ToString(data), BitConverter.ToString(pt));
        }
    }

    [DataTestMethod]
    [DataRow(PaddingMode.None)]
    [DataRow(PaddingMode.PKCS7)]
    [DataRow(PaddingMode.Zeros)]
    [DataRow(PaddingMode.ANSIX923)]
    [DataRow(PaddingMode.ISO10126)]
    public void Twofish_CBC_EncryptDecrypt(PaddingMode padding) {
        var crypto = new Twofish() { Padding = padding };
        crypto.GenerateKey();
        crypto.GenerateIV();
        var bytes = RandomNumberGenerator.GetBytes(1024);
        var bytesEnc = new byte[bytes.Length];
        var bytesDec = new byte[bytes.Length];

        var sw = Stopwatch.StartNew();
        using var encryptor = crypto.CreateEncryptor();
        using var decryptor = crypto.CreateDecryptor();
        for (var n = 0; n < 1024; n++) {
            encryptor.TransformBlock(bytes, 0, bytes.Length, bytesEnc, 0);
            decryptor.TransformBlock(bytesEnc, 0, bytesEnc.Length, bytesDec, 0);
        }

        if (padding is PaddingMode.None) {  // has to be a full block if no padding
            var lastBytesEnc = encryptor.TransformFinalBlock(new byte[16], 0, 16);
            var lastBytesDec = decryptor.TransformFinalBlock(lastBytesEnc, 0, lastBytesEnc.Length);
        } else {
            var lastBytesEnc = encryptor.TransformFinalBlock(new byte[10], 0, 10);
            var lastBytesDec = decryptor.TransformFinalBlock(lastBytesEnc, 0, lastBytesEnc.Length);
        }
        sw.Stop();

        Debug.WriteLine($"Duration: {sw.ElapsedMilliseconds} ms");
    }


    #region Multiblock

    [TestMethod]
    public void Twofish_CBC_MultiBlock_128_Encrypt() {
        var key = ParseBytes("00000000000000000000000000000000");
        var iv = ParseBytes("00000000000000000000000000000000");
        var pt = ParseBytes("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        using var algorithm = new Twofish() { KeySize = 128, Mode = CipherMode.CBC, Padding = PaddingMode.None };
        var ct = Encrypt(algorithm, key, iv, pt);
        Assert.AreEqual("9F589F5CF6122C32B6BFEC2F2AE8C35AD491DB16E7B1C39E86CB086B789F541905EF8C61A811582634BA5CB7106AA641", BitConverter.ToString(ct).Replace("-", ""));
    }

    [TestMethod]
    public void Twofish_CBC_MultiBlock_128_Decrypt() {
        var key = ParseBytes("00000000000000000000000000000000");
        var iv = ParseBytes("00000000000000000000000000000000");
        var ct = ParseBytes("9F589F5CF6122C32B6BFEC2F2AE8C35AD491DB16E7B1C39E86CB086B789F541905EF8C61A811582634BA5CB7106AA641");
        var algorithm = new Twofish() { KeySize = 128, Mode = CipherMode.CBC, Padding = PaddingMode.None };
        var pt = Decrypt(algorithm, key, iv, ct);
        Assert.AreEqual("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", BitConverter.ToString(pt).Replace("-", ""));
    }


    [TestMethod]
    public void Twofish_CBC_MultiBlock_192_Encrypt() {
        var key = ParseBytes("000000000000000000000000000000000000000000000000");
        var iv = ParseBytes("00000000000000000000000000000000");
        var pt = ParseBytes("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        var algorithm = new Twofish() { KeySize = 192, Mode = CipherMode.CBC, Padding = PaddingMode.None };
        var ct = Encrypt(algorithm, key, iv, pt);
        Assert.AreEqual("EFA71F788965BD4453F860178FC1910188B2B2706B105E36B446BB6D731A1E88F2DD994D2C4E64517CC9DB9AED2D5909", BitConverter.ToString(ct).Replace("-", ""));
    }

    [TestMethod]
    public void Twofish_CBC_MultiBlock_192_Decrypt() {
        var key = ParseBytes("000000000000000000000000000000000000000000000000");
        var iv = ParseBytes("00000000000000000000000000000000");
        var ct = ParseBytes("EFA71F788965BD4453F860178FC1910188B2B2706B105E36B446BB6D731A1E88F2DD994D2C4E64517CC9DB9AED2D5909");
        var algorithm = new Twofish() { KeySize = 192, Mode = CipherMode.CBC, Padding = PaddingMode.None };
        var pt = Decrypt(algorithm, key, iv, ct);
        Assert.AreEqual("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", BitConverter.ToString(pt).Replace("-", ""));
    }


    [TestMethod]
    public void Twofish_CBC_MultiBlock_256_Encrypt() {
        var key = ParseBytes("0000000000000000000000000000000000000000000000000000000000000000");
        var iv = ParseBytes("00000000000000000000000000000000");
        var pt = ParseBytes("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        var algorithm = new Twofish() { KeySize = 256, Mode = CipherMode.CBC, Padding = PaddingMode.None };
        var ct = Encrypt(algorithm, key, iv, pt);
        Assert.AreEqual("57FF739D4DC92C1BD7FC01700CC8216FD43BB7556EA32E46F2A282B7D45B4E0D2804E32925D62BAE74487A06B3CD2D46", BitConverter.ToString(ct).Replace("-", ""));
    }

    [TestMethod]
    public void Twofish_CBC_MultiBlock_256_Decrypt() {
        var key = ParseBytes("0000000000000000000000000000000000000000000000000000000000000000");
        var iv = ParseBytes("00000000000000000000000000000000");
        var ct = ParseBytes("57FF739D4DC92C1BD7FC01700CC8216FD43BB7556EA32E46F2A282B7D45B4E0D2804E32925D62BAE74487A06B3CD2D46");
        var algorithm = new Twofish() { KeySize = 256, Mode = CipherMode.CBC, Padding = PaddingMode.None };
        var pt = Decrypt(algorithm, key, iv, ct);
        Assert.AreEqual("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", BitConverter.ToString(pt).Replace("-", ""));
    }


    [TestMethod]
    public void Twofish_CBC_MultiBlockNonFinal_256_Encrypt() {
        var key = ParseBytes("0000000000000000000000000000000000000000000000000000000000000000");
        var iv = ParseBytes("00000000000000000000000000000000");
        var pt = ParseBytes("9F589F5CF6122C32B6BFEC2F2AE8C35A9F589F5CF6122C32B6BFEC2F2AE8C35A9F589F5CF6122C32B6BFEC2F2AE8C35A");
        using var algorithm = new Twofish() { KeySize = 256, Mode = CipherMode.CBC, Padding = PaddingMode.None };
        algorithm.Key = key;
        algorithm.IV = iv;
        var ct = new byte[pt.Length];
        using (var transform = algorithm.CreateEncryptor()) {
            transform.TransformBlock(pt, 0, pt.Length, ct, 0);
            transform.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        }
        Assert.AreEqual("61B5BC459C4E9491DD9E6ACB7478813047BE7250D34F792C17F0C23583C0B040B95C9FAE11107EE9BAC3D79BBFE019EE", BitConverter.ToString(ct).Replace("-", ""));
    }

    [TestMethod]
    public void Twofish_CBC_MultiBlockNonFinal_256_Decrypt() {
        var key = ParseBytes("0000000000000000000000000000000000000000000000000000000000000000");
        var iv = ParseBytes("00000000000000000000000000000000");
        var ct = ParseBytes("61B5BC459C4E9491DD9E6ACB7478813047BE7250D34F792C17F0C23583C0B040B95C9FAE11107EE9BAC3D79BBFE019EE");
        using var algorithm = new Twofish() { KeySize = 256, Mode = CipherMode.CBC, Padding = PaddingMode.None };
        algorithm.Key = key;
        algorithm.IV = iv;
        var pt = new byte[ct.Length]; pt[ct.Length - 1] = 0xFF;
        using (var transform = algorithm.CreateDecryptor()) {
            transform.TransformBlock(ct, 0, ct.Length, pt, 0);
            transform.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        }
        Assert.AreEqual("9F589F5CF6122C32B6BFEC2F2AE8C35A9F589F5CF6122C32B6BFEC2F2AE8C35A9F589F5CF6122C32B6BFEC2F2AE8C35A", BitConverter.ToString(pt).Replace("-", ""));
    }


    [TestMethod]
    public void Twofish_CBC_MultiBlockFinal_256_Encrypt() {
        var key = ParseBytes("0000000000000000000000000000000000000000000000000000000000000000");
        var iv = ParseBytes("00000000000000000000000000000000");
        var pt = ParseBytes("9F589F5CF6122C32B6BFEC2F2AE8C35A9F589F5CF6122C32B6BFEC2F2AE8C35A9F589F5CF6122C32B6BFEC2F2AE8C35A");
        using var algorithm = new Twofish() { KeySize = 256, Mode = CipherMode.CBC, Padding = PaddingMode.None };
        algorithm.Key = key;
        algorithm.IV = iv;
        var ct = algorithm.CreateEncryptor().TransformFinalBlock(pt, 0, pt.Length);
        Assert.AreEqual("61B5BC459C4E9491DD9E6ACB7478813047BE7250D34F792C17F0C23583C0B040B95C9FAE11107EE9BAC3D79BBFE019EE", BitConverter.ToString(ct).Replace("-", ""));
    }

    [TestMethod]
    public void Twofish_CBC_MultiBlockFinal_256_Decrypt() {
        var key = ParseBytes("0000000000000000000000000000000000000000000000000000000000000000");
        var iv = ParseBytes("00000000000000000000000000000000");
        var ct = ParseBytes("61B5BC459C4E9491DD9E6ACB7478813047BE7250D34F792C17F0C23583C0B040B95C9FAE11107EE9BAC3D79BBFE019EE");
        using var algorithm = new Twofish() { KeySize = 256, Mode = CipherMode.CBC, Padding = PaddingMode.None };
        algorithm.Key = key;
        algorithm.IV = iv;
        var pt = algorithm.CreateDecryptor().TransformFinalBlock(ct, 0, ct.Length);
        Assert.AreEqual("9F589F5CF6122C32B6BFEC2F2AE8C35A9F589F5CF6122C32B6BFEC2F2AE8C35A9F589F5CF6122C32B6BFEC2F2AE8C35A", BitConverter.ToString(pt).Replace("-", ""));
    }

    #endregion

    #region Other

    [TestMethod]
    public void Twofish_CBC_TransformBlock_Encrypt_UseSameArray() {
        var key = ParseBytes("00000000000000000000000000000000");
        var iv = ParseBytes("00000000000000000000000000000000");
        var ctpt = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog once");
        using (var twofish = new Twofish() { Mode = CipherMode.CBC, Padding = PaddingMode.None, KeySize = 128, Key = key, IV = iv }) {
            using var transform = twofish.CreateEncryptor();
            transform.TransformBlock(ctpt, 0, 48, ctpt, 0);
        }
        Assert.AreEqual("B0DD30E9AB1F1329C1BEE154DDBE88AF8C47A4FE24D56DC027ED503652C9D164CE26E0C6E32BCA8756482B99988E8C79", BitConverter.ToString(ctpt).Replace("-", ""));
    }

    [TestMethod]
    public void Twofish_CBC_TransformBlock_Decrypt_UseSameArray() {
        var key = ParseBytes("00000000000000000000000000000000");
        var iv = ParseBytes("00000000000000000000000000000000");
        var ctpt = ParseBytes("B0DD30E9AB1F1329C1BEE154DDBE88AF8C47A4FE24D56DC027ED503652C9D164CE26E0C6E32BCA8756482B99988E8C79");
        using (var twofish = new Twofish() { Mode = CipherMode.CBC, Padding = PaddingMode.None, KeySize = 128, Key = key, IV = iv }) {
            using var transform = twofish.CreateDecryptor();
            transform.TransformBlock(ctpt, 0, 48, ctpt, 0); //no caching last block if Padding is none
        }
        Assert.AreEqual("The quick brown fox jumps over the lazy dog once", Encoding.UTF8.GetString(ctpt));
    }

    #endregion



    #region Private: Monte carlo
    // http://www.ntua.gr/cryptix/old/cryptix/aes/docs/katmct.html

    private static void MonteCarlo_CBC_E(TestBlock test) {
        using var algorithm = new Twofish() { KeySize = test.KeySize, Mode = CipherMode.CBC, Padding = PaddingMode.None };
        var key = test.Key;
        var cv = test.IV;
        var pt = test.PlainText;
        byte[] ct = null;
        for (var j = 0; j < 10000; j++) {
            var ob = Encrypt(algorithm, key, cv, pt);
            pt = (j == 0) ? cv : ct;
            ct = ob;
            cv = ct;
        }
        Assert.AreEqual(BitConverter.ToString(test.CipherText), BitConverter.ToString(ct));
    }

    private static void MonteCarlo_CBC_D(TestBlock test) {
        using var algorithm = new Twofish() { KeySize = test.KeySize, Mode = CipherMode.CBC, Padding = PaddingMode.None };
        var key = test.Key;
        var cv = test.IV;
        var ct = test.CipherText;
        byte[] pt = null;
        for (var j = 0; j < 10000; j++) {
            pt = Decrypt(algorithm, key, cv, ct);
            cv = ct;
            ct = pt;
        }
        Assert.AreEqual(BitConverter.ToString(test.PlainText), BitConverter.ToString(pt));
    }

    #endregion

}
