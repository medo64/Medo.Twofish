using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Medo.Security.Cryptography;

namespace Tests;

[TestClass]
public class Twofish_Exceptions_Tests {

    [DataTestMethod]
    [DataRow(CipherMode.CFB)]
    [DataRow(CipherMode.CTS)]
    public void Twofish_Exceptions_OnlyCbcAndEbcSupported(CipherMode mode) {
        Assert.ThrowsException<CryptographicException>(() => {
            var _ = new Twofish() { Mode = mode };
        });
    }

}
