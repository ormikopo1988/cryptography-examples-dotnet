using RSA;
using AES;
using HMAC;
using System.Security.Cryptography;

namespace HybridWithIntegrityCheck
{
    public class HybridEncryptionWithIntegrityCheck
    {
        private readonly AesEncryption _aes = new AesEncryption();

        public EncryptedPacket EncryptData(byte[] original, RSAWithRSAParameterKey rsaParams)
        {
            // Generate our session key
            var sessionKey = _aes.GenerateRandomNumber(32);

            // Create the encrypted packet and generate the IV
            var encryptedPacket = new EncryptedPacket
            {
                IV = _aes.GenerateRandomNumber(16)
            };

            // Encrypt our data with AES
            encryptedPacket.EncryptedData = _aes.Encrypt(original, sessionKey, encryptedPacket.IV);

            // Encrypt the session key with RSA
            encryptedPacket.EncryptedSessionKey = rsaParams.EncryptData(sessionKey);

            // Calculate a HMAC 
            encryptedPacket.HMAC = HMac.ComputeHMACSha256(encryptedPacket.EncryptedData, sessionKey);

            return encryptedPacket;
        }

        public byte[] DecryptData(EncryptedPacket encryptedPacket, RSAWithRSAParameterKey rsaParams)
        {
            // Decrypt AES Key with RSA
            var decryptedSessionKey = rsaParams.DecryptData(encryptedPacket.EncryptedSessionKey);

            // Integrity Check
            var hmacToCheck = HMac.ComputeHMACSha256(encryptedPacket.EncryptedData, decryptedSessionKey);

            if(!Compare(encryptedPacket.HMAC, hmacToCheck))
            {
                throw new CryptographicException("HMAC for decryption does not match encrypted package HMAC code received. This means the message has been tampered with.");
            }

            // Decrypt our data with AES using the decryptedSessionKey
            return _aes.Decrypt(encryptedPacket.EncryptedData, decryptedSessionKey, encryptedPacket.IV);
        }

        private static bool Compare(byte[] array1, byte[] array2)
        {
            var result = array1.Length == array2.Length;

            for(var i = 0; i < array1.Length && i < array2.Length; i++)
            {
                result &= array1[i] == array2[i];
            }

            return result;
        }

        // Do not use this method for comparing byte arrays.
        // Although more efficient and more correct it is vulnerable
        // to Side-Channel Timing Attacks. Use the above Compare for cryptographic operations.
        private static bool CompareUnSecure(byte[] array1, byte[] array2)
        {
            if(array1.Length != array2.Length)
            {
                return false;
            }

            for (var i = 0; i < array1.Length; i++)
            {
                if(array1[i] != array2[i])
                {
                    return false;
                }
            }

            return true;
        }
    }
}
