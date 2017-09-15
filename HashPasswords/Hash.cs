using CryptographicRandomNumbers;
using System;
using System.Security.Cryptography;

namespace HashPasswords
{
    public class Hash
    {
        public static byte[] GenerateSalt()
        {
            // The salt will be of length 32 bytes => 256 bits
            const int saltLength = 32;

            return RNGCryptoServiceProviderRandomGenerator.GenerateRandomNumber(saltLength);
        }

        public static byte[] HashPasswordWithSalt(byte[] toBeHashed, byte[] salt)
        {
            using(var sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(Combine(toBeHashed, salt));
            }
        }

        // Use this to combine the byte arrays of password and salt into one byte array
        private static byte[] Combine(byte[] first, byte[] second)
        {
            var ret = new byte[first.Length + second.Length];

            Buffer.BlockCopy(first, 0, ret, 0, first.Length);
            Buffer.BlockCopy(second, 0, ret, 0, second.Length);

            return ret;
        }
    }
}
