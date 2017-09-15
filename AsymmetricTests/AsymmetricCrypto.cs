using System;
using System.IO;
using System.Security.Cryptography;

namespace AsymmetricTests
{
    public class AsymmetricCrypto
    {
        public static void GenerateRSAKeyPair()
        {
            AsymmetricAlgorithm rsa = new RSACryptoServiceProvider(2048); // 2048 bit key size

            // The true here means that I am going to include the private parameters
            string encodedKey = rsa.ToXmlString(true); // Convert key to XML string that contains Modules, Exponent and D

            //encodedKey.Should().Contain("<Modulus>");
            //encodedKey.Should().Contain("<Exponent>AQAB</Exponent>");
            //encodedKey.Should().Contain("<D>"); // D is the private key - Decrypting Exponent
        }

        public static void ShareAPublicKey()
        {
            AsymmetricAlgorithm rsa = new RSACryptoServiceProvider(2048);

            string encodedKey = rsa.ToXmlString(false);

            //encodedKey.Should().Contain("<Modulus>");
            //encodedKey.Should().Contain("<Exponent>AQAB</Exponent>");
            //encodedKey.Should().NotContain("<D>");
        }

        public static void ExponentIsAlways65537()
        {
            byte[] exponent = Convert.FromBase64String("AQAB");

            //exponent.Length.Should().Be(3);

            long number =
                ((long)exponent[2] << 16) +
                ((long)exponent[1] << 8) +
                ((long)exponent[0]);

            //number.Should().Be(65537);
        }

        public static void EncryptASymmetricKeyWithRSA()
        {
            var rsa = new RSACryptoServiceProvider(2048);

            byte[] blob = rsa.ExportCspBlob(false);

            var publicKey = new RSACryptoServiceProvider();
            publicKey.ImportCspBlob(blob);

            var aes = new AesCryptoServiceProvider();
            aes.KeySize = 256;

            // Now I will encrypt the key for a certain recipient using their public key.
            // This encryptedKey I can send at the other party that I want to communicate with securely.
            byte[] encryptedKey = publicKey.Encrypt(aes.Key, true);

            // The other party now will use their private key to decrypt the encryptedKey.
            // So now the decryptedKey here should be equal to aes.Key which was encrypted earlier.
            byte[] decryptedKey = rsa.Decrypt(encryptedKey, true);

            //Enumerable.SequenceEqual(decryptedKey, aes.Key).Should().BeTrue();
        }

        public static void SignAMessage()
        {
            var rsa = new RSACryptoServiceProvider(2048);

            byte[] blob = rsa.ExportCspBlob(false);

            // Take the public key here only in order to share it with someone else
            var publicKey = new RSACryptoServiceProvider();
            publicKey.ImportCspBlob(blob);

            string message = "Alice knows Bob's secret.";

            var memory = new MemoryStream();

            using(var writer = new StreamWriter(memory))
            {
                writer.Write(message);
            }

            var hashFunction = new SHA256CryptoServiceProvider();

            // Using my private key I am going to sign some data that will be my memory buffer and the hash
            // algorithm I am going to use is my SHA256 function, so that will give me a signature and so now
            // somebody holding my public key can verify that the message actually came from me.
            byte[] signature = rsa.SignData(memory.ToArray(), hashFunction);

            bool verified = publicKey.VerifyData(memory.ToArray(), hashFunction, signature);

            //verified.Should().Be(true);
        }
    }
}
