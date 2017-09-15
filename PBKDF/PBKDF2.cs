using CryptographicRandomNumbers;
using System.Security.Cryptography;

namespace PBKDF
{
    public class PBKDF2
    {
        public static byte[] GenerateSalt()
        {
            return RNGCryptoServiceProviderRandomGenerator.GenerateRandomNumber(32);
        }

        public static byte[] HashPasswordWithPBKDF(byte[] toBeHashed, byte[] salt, int numberOfIterations)
        {
            using (var rfc2898 = new Rfc2898DeriveBytes(toBeHashed, salt, numberOfIterations))
            {
                return rfc2898.GetBytes(32);
            }
        }
    }
}
