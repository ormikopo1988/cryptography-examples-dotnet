using System.Security.Cryptography;
using SymmetricTests;
using AsymmetricTests;
using System;
using CryptographicRandomNumbers;
using HashingTests;
using HMAC;
using System.Text;
using HashPasswords;
using PBKDF;
using System.Diagnostics;
using DES;
using TripleDES;
using AES;
using RSA;
using Hybrid;
using HybridWithIntegrityCheck;
using DigitalSignature;
using HybridWithIntegrityAndSignatures;

namespace CryptographyAPITestsClient
{
    class Program
    {
        static void Main(string[] args)
        {
            //TestSymmetricCryptoAPI();

            //TestAsymmetricCryptoAPI();

            //TestRandomNumberGenerator();

            //TestHashingAPI();

            //TestHMACAPI();

            //TestHashPasswords();

            //TestPBKDF();

            //TestDES();

            //TestTripleDES();

            //TestAES();

            //TestRSAWithRSAParameterKey();

            //TestRSAWithXMLKey();

            //TestRSAWithCSPKey();

            //TestHybrid();

            //TestHybridWithIntegrityCheck();

            //TestDigitalSignature();

            TestHybridWithIntegrityAndSignatures();

            Console.ReadKey();
        }
       
        private static void TestHybridWithIntegrityAndSignatures()
        {
            const string original = "Very secret and important information that must not fall in the hands of the enemy.";

            var rsaParams = new RSAWithRSAParameterKey();
            rsaParams.AssignNewKey();

            var fullHybridEncryption = new FullHybridEncryption();

            var digitalSignature = new DigitalSignatureFuncs();
            digitalSignature.AssignNewKey();

            try
            {
                var encryptedBlock = fullHybridEncryption.EncryptData(Encoding.UTF8.GetBytes(original), rsaParams, digitalSignature);
                var decryptedBlock = fullHybridEncryption.DecryptData(encryptedBlock, rsaParams, digitalSignature);

                Console.WriteLine($"Original Message: {original}");
                Console.WriteLine($"Encrypted Block Data: {Convert.ToBase64String(encryptedBlock.EncryptedData)}");
                Console.WriteLine($"Decrypted Block: {Convert.ToBase64String(decryptedBlock)}");
                Console.WriteLine($"Decrypted Message: {Encoding.UTF8.GetString(decryptedBlock)}");
            }
            catch (CryptographicException ex)
            {
                Console.WriteLine($"Cryptographic Exception occured: {ex.Message}");
            }
        }

        private static void TestDigitalSignature()
        {
            var document = Encoding.UTF8.GetBytes("Document to Sign");

            byte[] hashedDocument;

            using(var sha256 = SHA256.Create())
            {
                hashedDocument = sha256.ComputeHash(document);
            }

            var digitalSignature = new DigitalSignatureFuncs();
            digitalSignature.AssignNewKey();

            var signature = digitalSignature.SignData(hashedDocument);
            var verified = digitalSignature.VerifySignature(hashedDocument, signature);

            Console.WriteLine($"Original Text: {Encoding.Default.GetString(document)}");
            Console.WriteLine($"Digital Signature: {Convert.ToBase64String(signature)}");
            Console.WriteLine(verified ? "The digital signature has been verified." : "The digital signature has NOT been verified.");
        }

        private static void TestHybridWithIntegrityCheck()
        {
            const string original = "Very secret and important information that must not fall in the hands of the enemy.";

            var rsaParams = new RSAWithRSAParameterKey();
            rsaParams.AssignNewKey();

            var hybridWithIntegrityCheck = new HybridEncryptionWithIntegrityCheck();

            try
            {
                var encryptedBlock = hybridWithIntegrityCheck.EncryptData(Encoding.UTF8.GetBytes(original), rsaParams);
                var decryptedBlock = hybridWithIntegrityCheck.DecryptData(encryptedBlock, rsaParams);

                Console.WriteLine($"Original Message: {original}");
                Console.WriteLine($"Encrypted Block Data: {Convert.ToBase64String(encryptedBlock.EncryptedData)}");
                Console.WriteLine($"Decrypted Block: {Convert.ToBase64String(decryptedBlock)}");
                Console.WriteLine($"Decrypted Message: {Encoding.UTF8.GetString(decryptedBlock)}");
            }
            catch(CryptographicException ex)
            {
                Console.WriteLine($"Cryptographic Exception occured: {ex.Message}");
            }
        }

        private static void TestHybrid()
        {
            const string original = "Very secret and important information that must not fall in the hands of the enemy.";

            var rsaParams = new RSAWithRSAParameterKey();
            rsaParams.AssignNewKey();

            var hybrid = new HybridEncryption();

            var encryptedBlock = hybrid.EncryptData(Encoding.UTF8.GetBytes(original), rsaParams);
            var decryptedBlock = hybrid.DecryptData(encryptedBlock, rsaParams);

            Console.WriteLine($"Original Message: {original}");
            Console.WriteLine($"Encrypted Block Data: {Convert.ToBase64String(encryptedBlock.EncryptedData)}");
            Console.WriteLine($"Decrypted Block: {Convert.ToBase64String(decryptedBlock)}");
            Console.WriteLine($"Decrypted Message: {Encoding.UTF8.GetString(decryptedBlock)}");
        }

        private static void TestRSAWithCSPKey()
        {
            var rsaCsp = new RSAWithCSPKey();

            const string original = "Text to encrypt";

            rsaCsp.AssignNewKey();

            var encryptedCsp = rsaCsp.EncryptData(Encoding.UTF8.GetBytes(original));
            var decryptedCsp = rsaCsp.DecryptData(encryptedCsp);

            rsaCsp.DeleteKeyInCsp();

            Console.WriteLine($"Original Text: {original}");
            Console.WriteLine($"Encrypted Csp: {Convert.ToBase64String(encryptedCsp)}");
            Console.WriteLine($"Decrypted Csp: {Convert.ToBase64String(decryptedCsp)}");
            Console.WriteLine($"Decrypted Text: {Encoding.Default.GetString(decryptedCsp)}");
        }

        private static void TestRSAWithXMLKey()
        {
            var rsa = new RSAWithXMLKey();

            const string original = "Text to encrypt";

            const string publicKeyPath = "C:\\Temp\\RSAExample\\publicKey.xml";
            const string privateKeyPath = "C:\\Temp\\RSAExample\\privateKey.xml";

            rsa.AssignNewKey(publicKeyPath, privateKeyPath);

            var encryptedRSAParams = rsa.EncryptData(publicKeyPath, Encoding.UTF8.GetBytes(original));
            var decryptedRSAParams = rsa.DecryptData(privateKeyPath, encryptedRSAParams);

            Console.WriteLine($"Original Text: {original}");
            Console.WriteLine($"Encrypted RSA: {Convert.ToBase64String(encryptedRSAParams)}");
            Console.WriteLine($"Decrypted RSA: {Convert.ToBase64String(decryptedRSAParams)}");
            Console.WriteLine($"Decrypted Text: {Encoding.Default.GetString(decryptedRSAParams)}");
        }

        private static void TestRSAWithRSAParameterKey()
        {
            var rsaParams = new RSAWithRSAParameterKey();

            const string original = "Text to encrypt";

            rsaParams.AssignNewKey();

            var encryptedRSAParams = rsaParams.EncryptData(Encoding.UTF8.GetBytes(original));
            var decryptedRSAParams = rsaParams.DecryptData(encryptedRSAParams);

            Console.WriteLine($"Original Text: {original}");
            Console.WriteLine($"Encrypted RSA Params: {Convert.ToBase64String(encryptedRSAParams)}");
            Console.WriteLine($"Decrypted RSA Params: {Convert.ToBase64String(decryptedRSAParams)}");
            Console.WriteLine($"Decrypted Text: {Encoding.Default.GetString(decryptedRSAParams)}");
        }

        private static void TestAES()
        {
            var aes = new AesEncryption();

            var key = aes.GenerateRandomNumber(32);
            var iv = aes.GenerateRandomNumber(16);

            const string originalText = "Text to encrypt";

            var encrypted = aes.Encrypt(Encoding.UTF8.GetBytes(originalText), key, iv);
            var decrypted = aes.Decrypt(encrypted, key, iv);

            var decryptedMessage = Encoding.UTF8.GetString(decrypted);

            Console.WriteLine($"Original Text: {originalText}");
            Console.WriteLine($"Encrypted value: {Convert.ToBase64String(encrypted)}");
            Console.WriteLine($"Decrypted Value: {Convert.ToBase64String(decrypted)}");
            Console.WriteLine($"Decrypted Text: {decryptedMessage}");
        }

        private static void TestTripleDES()
        {
            var trippleDes = new TripleDesEncryption();

            // encrypt with key 1, then encrypt with key 2 and finally encrypt with key 3
            var key = trippleDes.GenerateRandomNumber(24);

            // encrypt with key 1, then encrypt with key 2 and finally encrypt again with key 1
            //var key = trippleDes.GenerateRandomNumber(16);

            var iv = trippleDes.GenerateRandomNumber(8);

            const string originalText = "Text to encrypt";

            var encrypted = trippleDes.Encrypt(Encoding.UTF8.GetBytes(originalText), key, iv);
            var decrypted = trippleDes.Decrypt(encrypted, key, iv);

            var decryptedMessage = Encoding.UTF8.GetString(decrypted);

            Console.WriteLine($"Original Text: {originalText}");
            Console.WriteLine($"Encrypted value: {Convert.ToBase64String(encrypted)}");
            Console.WriteLine($"Decrypted Value: {Convert.ToBase64String(decrypted)}");
            Console.WriteLine($"Decrypted Text: {decryptedMessage}");
        }

        private static void TestDES()
        {
            var des = new DesEncryption();

            var key = des.GenerateRandomNumber(8);
            var iv = des.GenerateRandomNumber(8);

            const string originalText = "Text to encrypt";

            var encrypted = des.Encrypt(Encoding.UTF8.GetBytes(originalText), key, iv);
            var decrypted = des.Decrypt(encrypted, key, iv);

            var decryptedMessage = Encoding.UTF8.GetString(decrypted);

            Console.WriteLine($"Original Text: {originalText}");
            Console.WriteLine($"Encrypted value: {Convert.ToBase64String(encrypted)}");
            Console.WriteLine($"Decrypted Value: {Convert.ToBase64String(decrypted)}");
            Console.WriteLine($"Decrypted Text: {decryptedMessage}");
        }

        private static void TestPBKDF()
        {
            const string password = "V3ryC0mpl3xP@55w0rd";

            HashPasswordFromTestPBKDF(password, 100);
            HashPasswordFromTestPBKDF(password, 1000);
            HashPasswordFromTestPBKDF(password, 10000);
            HashPasswordFromTestPBKDF(password, 50000);
            HashPasswordFromTestPBKDF(password, 100000);
            HashPasswordFromTestPBKDF(password, 200000);
            HashPasswordFromTestPBKDF(password, 500000);
        }

        private static void HashPasswordFromTestPBKDF(string passwordToHash, int numberOfIterations)
        {
            var sw = new Stopwatch();

            sw.Start();

            var hashedPassword = PBKDF2.HashPasswordWithPBKDF(
                                    Encoding.UTF8.GetBytes(passwordToHash),
                                    PBKDF2.GenerateSalt(),
                                    numberOfIterations
                                );

            sw.Stop();

            Console.WriteLine();
            Console.WriteLine($"Password to hash: {passwordToHash}");
            Console.WriteLine($"Hashed Password: {Convert.ToBase64String(hashedPassword)}");
            Console.WriteLine($"Iterations <{numberOfIterations}> | Elapsed Time: {sw.ElapsedMilliseconds}");
        }

        private static void TestHashPasswords()
        {
            const string password = "V3ryC0mpl3xP@55w0rd";

            byte[] salt = Hash.GenerateSalt();

            Console.WriteLine($"Password: {password} | Salt: {Convert.ToBase64String(salt)}");
            Console.WriteLine();

            var hashedPassword = Hash.HashPasswordWithSalt(Encoding.UTF8.GetBytes(password), salt);

            Console.WriteLine($"Hashed Password: {Convert.ToBase64String(hashedPassword)}");
            Console.WriteLine();
        }

        private static void TestHMACAPI()
        {
            const string originalMessage = "Original message to hash";
            const string originalMessage2 = "Or1ginal message to hash";

            Console.WriteLine($"Original Message 1: {originalMessage}");
            Console.WriteLine($"Original Message 2: {originalMessage2}");
            Console.WriteLine();

            var key = HMac.GenerateKey();

            var hmacMd5Message = HMac.ComputeHMACMD5(Encoding.UTF8.GetBytes(originalMessage), key);
            var hmacMd5Message2 = HMac.ComputeHMACMD5(Encoding.UTF8.GetBytes(originalMessage2), key);

            var hmacSha1Message = HMac.ComputeHMACSha1(Encoding.UTF8.GetBytes(originalMessage), key);
            var hmacSha1Message2 = HMac.ComputeHMACSha1(Encoding.UTF8.GetBytes(originalMessage2), key);

            var hmacSha256Message = HMac.ComputeHMACSha256(Encoding.UTF8.GetBytes(originalMessage), key);
            var hmacSha256Message2 = HMac.ComputeHMACSha256(Encoding.UTF8.GetBytes(originalMessage2), key);

            var hmacSha512Message = HMac.ComputeHMACSha512(Encoding.UTF8.GetBytes(originalMessage), key);
            var hmacSha512Message2 = HMac.ComputeHMACSha512(Encoding.UTF8.GetBytes(originalMessage2), key);

            Console.WriteLine();
            Console.WriteLine($"MD5 HMAC Message 1: {Convert.ToBase64String(hmacMd5Message)}");
            Console.WriteLine($"MD5 HMAC Message 2: {Convert.ToBase64String(hmacMd5Message2)}");
            Console.WriteLine();

            Console.WriteLine();
            Console.WriteLine($"SHA1 HMAC Message 1: {Convert.ToBase64String(hmacSha1Message)}");
            Console.WriteLine($"SHA1 HMAC Message 2: {Convert.ToBase64String(hmacSha1Message2)}");
            Console.WriteLine();

            Console.WriteLine();
            Console.WriteLine($"SHA256 HMAC Message 1: {Convert.ToBase64String(hmacSha256Message)}");
            Console.WriteLine($"SHA256 HMAC Message 2: {Convert.ToBase64String(hmacSha256Message2)}");
            Console.WriteLine();

            Console.WriteLine();
            Console.WriteLine($"SHA512 HMAC Message 1: {Convert.ToBase64String(hmacSha512Message)}");
            Console.WriteLine($"SHA512 HMAC Message 2: {Convert.ToBase64String(hmacSha512Message2)}");
            Console.WriteLine();
        }

        private static void TestHashingAPI()
        {
            const string originalMessage = "Original message to hash";
            const string originalMessage2 = "Or1ginal message to hash";

            Console.WriteLine($"Original Message 1: {originalMessage}");
            Console.WriteLine($"Original Message 2: {originalMessage2}");
            Console.WriteLine();

            var mdHashedMessage = HashData.ComputeHashMd5(Encoding.UTF8.GetBytes(originalMessage));
            var mdHashedMessage2 = HashData.ComputeHashMd5(Encoding.UTF8.GetBytes(originalMessage2));

            var sha1HashedMessage = HashData.ComputeHashSha1(Encoding.UTF8.GetBytes(originalMessage));
            var sha1HashedMessage2 = HashData.ComputeHashSha1(Encoding.UTF8.GetBytes(originalMessage2));

            var sha256HashedMessage = HashData.ComputeHashSha256(Encoding.UTF8.GetBytes(originalMessage));
            var sha256HashedMessage2 = HashData.ComputeHashSha256(Encoding.UTF8.GetBytes(originalMessage2));

            var sha512HashedMessage = HashData.ComputeHashSha512(Encoding.UTF8.GetBytes(originalMessage));
            var sha512HashedMessage2 = HashData.ComputeHashSha512(Encoding.UTF8.GetBytes(originalMessage2));

            Console.WriteLine();
            Console.WriteLine($"MD5 Message 1: {Convert.ToBase64String(mdHashedMessage)}");
            Console.WriteLine($"MD5 Message 2: {Convert.ToBase64String(mdHashedMessage2)}");
            Console.WriteLine();

            Console.WriteLine();
            Console.WriteLine($"SHA1 Message 1: {Convert.ToBase64String(sha1HashedMessage)}");
            Console.WriteLine($"SHA1 Message 2: {Convert.ToBase64String(sha1HashedMessage2)}");
            Console.WriteLine();

            Console.WriteLine();
            Console.WriteLine($"SHA256 Message 1: {Convert.ToBase64String(sha256HashedMessage)}");
            Console.WriteLine($"SHA256 Message 2: {Convert.ToBase64String(sha256HashedMessage2)}");
            Console.WriteLine();

            Console.WriteLine();
            Console.WriteLine($"SHA512 Message 1: {Convert.ToBase64String(sha512HashedMessage)}");
            Console.WriteLine($"SHA512 Message 2: {Convert.ToBase64String(sha512HashedMessage2)}");
            Console.WriteLine();

        }

        private static void TestRandomNumberGenerator()
        {
            for(var i=0; i<10; i++)
            {
                Console.WriteLine($"Random Number {i}: {Convert.ToBase64String(RNGCryptoServiceProviderRandomGenerator.GenerateRandomNumber(32))}");
            }
        }

        private static void TestAsymmetricCryptoAPI()
        {
            AsymmetricCrypto.GenerateRSAKeyPair();
            AsymmetricCrypto.ShareAPublicKey();
            AsymmetricCrypto.ExponentIsAlways65537();
            AsymmetricCrypto.EncryptASymmetricKeyWithRSA();
            AsymmetricCrypto.SignAMessage();
        }

        private static void TestSymmetricCryptoAPI()
        {
            string messageToEncrypt1 = "Alice knows Bob's secret.";
            string messageToEncrypt2 = "Alice knows Bob's favorite color.";

            SymmetricAlgorithm aes = new AesCryptoServiceProvider();
            aes.KeySize = 256;

            byte[] key = aes.Key; // The symmetric key used for encrypt - decrypt - same for both messages

            byte[] encryptedMessage1 = SymmetricCrypto.EncryptWithAes(messageToEncrypt1, aes);

            byte[] iv1 = aes.IV;

            string decryptedMessage1 = SymmetricCrypto.DecryptMessageWithAES(key, iv1, encryptedMessage1);

            aes = new AesCryptoServiceProvider();
            aes.KeySize = 256;
            aes.Key = key;

            byte[] encryptedMessage2 = SymmetricCrypto.EncryptWithAes(messageToEncrypt2, aes);

            byte[] iv2 = aes.IV;

            string decryptedMessage2 = SymmetricCrypto.DecryptMessageWithAES(key, iv2, encryptedMessage2);
        }
    }
}
