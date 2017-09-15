using CryptographicRandomNumbers;
using System.Security.Cryptography;

namespace HMAC
{
    public class HMac
    {
        private const int keySize = 32;

        public static byte[] GenerateKey()
        {
            return RNGCryptoServiceProviderRandomGenerator.GenerateRandomNumber(keySize);
        }

        public static byte[] ComputeHMACMD5(byte[] toBeHashed, byte[] key)
        {
            using (var hmac = new HMACMD5(key))
            {
                return hmac.ComputeHash(toBeHashed);
            }
        }

        public static byte[] ComputeHMACSha512(byte[] toBeHashed, byte[] key)
        {
            using (var hmac = new HMACSHA512(key))
            {
                return hmac.ComputeHash(toBeHashed);
            }
        }

        public static byte[] ComputeHMACSha256(byte[] toBeHashed, byte[] key)
        {
            using(var hmac = new HMACSHA256(key))
            {
                return hmac.ComputeHash(toBeHashed);
            }
        }

        public static byte[] ComputeHMACSha1(byte[] toBeHashed, byte[] key)
        {
            using (var hmac = new HMACSHA1(key))
            {
                return hmac.ComputeHash(toBeHashed);
            }
        }
    }
}
