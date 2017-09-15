using System.IO;
using System.Security.Cryptography;

namespace SymmetricTests
{
    public class SymmetricCrypto
    {
        public static void GenerateRandomAESKey()
        {
            SymmetricAlgorithm aes = new AesCryptoServiceProvider();

            aes.KeySize = 256;

            //aes.Key.Length.Should().Be(32); // 256 / 8 = 32 bytes
            //aes.IV.Length.Should().Be(16); // 128 / 8 = 16 bytes as the block size in the algorithm
        }
        
        public static byte[] EncryptWithAes(string message, SymmetricAlgorithm aes)
        {
            MemoryStream memoryStream = new MemoryStream();

            // I want to write that message into the memoryStream
            // First I am going to decorate the stream with a CryptoStream
            // This utility class will run the block cipher in Cipher Block Chain mode
            // and write the results into the stream that I am decorating, so I will write them
            // into the memory stream and then I will create an encrypter, that will be the
            // algorithm that I give to the CryptoStream and then my CryptoStream mode will be 
            // for writing. This will be a stream that I can write to and then it will in turn write to this
            // MemoryStream.
            var cryptoStream = new CryptoStream(
                memoryStream,
                aes.CreateEncryptor(),
                CryptoStreamMode.Write
            );

            // Create a writer to operate on the cryptoStream and then I will simply write my message into the writer
            // so this being inside the using statement that will close the writer, which will in turn close the stream
            // and that will flush everything to the MemoryStream, so by the time I get here on memoryStream.ToArray()
            // and read the array I will have the fully encrypted array of bytes, so that should be my encrypted stream.
            using(var writer = new StreamWriter(cryptoStream))
            {
                writer.Write(message);
            }

            return memoryStream.ToArray();
        }

        public static string DecryptMessageWithAES(byte[] key, byte[] iv, byte[] encryptedMessage)
        {
            SymmetricAlgorithm provider = new AesCryptoServiceProvider();

            MemoryStream memoryStream = new MemoryStream(encryptedMessage);

            var cryptoStream = new CryptoStream(
                memoryStream,
                provider.CreateDecryptor(key, iv),
                CryptoStreamMode.Read
            );

            using(var reader = new StreamReader(cryptoStream))
            {
                return reader.ReadToEnd();
            }
        }
    }
}
