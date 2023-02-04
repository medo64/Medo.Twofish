Medo.Twofish
=====-----==

C# implementation of [Twofish][twofish] algorithm. Supports CBC and ECB cipher
modes.

Twofish is a symmetric key block cipher that was one of the five finalists in
the Advanced Encryption Standard (AES) competition, and was designed by [Bruce Schneier][schneier]
and a team of designers at Counterpane Systems. Twofish has a block size of 128
bits and supports key sizes of 128, 192, and 256 bits.

It is considered to be a highly secure and flexible algorithm and is still
widely used in various encryption applications today. The algorithm is based on
the substitution-permutation network (SPN) structure and uses a combination of
substitution and permutation operations to encrypt and decrypt data.

Twofish is a Feistel network cipher, which means that it divides the plaintext
into two equal-sized blocks and then applies a complex function to one of the
blocks before recombining them. This provides a high level of diffusion, which
makes it difficult for an attacker to deduce the original plaintext from the
ciphertext.


## NuGet

Project can be found on [NuGet][nuget].

To install, use the following command:

    dotnet add package Twofish



[twofish]: https://www.schneier.com/academic/twofish/
[schneier]: https://www.schneier.com/
[nuget]: https://www.nuget.org/packages/TwoFish/