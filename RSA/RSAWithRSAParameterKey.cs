using System.Security.Cryptography;

namespace RSA
{
    // First example - Using in-memory keys
    public class RSAWithRSAParameterKey
    {
        private RSAParameters _publicKey;
        private RSAParameters _privateKey;

        public void AssignNewKey()
        {
            using(var rsa = new RSACryptoServiceProvider(2048))
            {
                // do not use the key container
                rsa.PersistKeyInCsp = false;

                _publicKey = rsa.ExportParameters(false);
                _privateKey = rsa.ExportParameters(true);
            }
        }

        public byte[] EncryptData(byte[] dataToEncrypt)
        {
            byte[] cipherBytes;

            using(var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;

                rsa.ImportParameters(_publicKey);

                cipherBytes = rsa.Encrypt(dataToEncrypt, true);
            }

            return cipherBytes;
        }

        public byte[] DecryptData(byte[] dataToDecrypt)
        {
            byte[] plain;

            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;

                rsa.ImportParameters(_privateKey);

                plain = rsa.Decrypt(dataToDecrypt, true);
            }

            return plain;
        }
    }
}
