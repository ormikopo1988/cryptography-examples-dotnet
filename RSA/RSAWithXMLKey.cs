using System.Security.Cryptography;
using System.IO;

namespace RSA
{
    // Second Example - Store keys in XML files
    public class RSAWithXMLKey
    {
        public void AssignNewKey(string publicKeyPath, string privateKeyPath)
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                // do not use the key container
                rsa.PersistKeyInCsp = false;

                if (File.Exists(publicKeyPath))
                {
                    File.Delete(publicKeyPath);
                }

                if (File.Exists(privateKeyPath))
                {
                    File.Delete(privateKeyPath);
                }

                var publicKeyFolder = Path.GetDirectoryName(publicKeyPath);
                var privateKeyFolder = Path.GetDirectoryName(privateKeyPath);

                if (!Directory.Exists(publicKeyFolder))
                {
                    Directory.CreateDirectory(publicKeyFolder);
                }

                if (!Directory.Exists(privateKeyFolder))
                {
                    Directory.CreateDirectory(privateKeyFolder);
                }

                File.WriteAllText(publicKeyPath, rsa.ToXmlString(false));
                File.WriteAllText(privateKeyPath, rsa.ToXmlString(true));
            }
        }

        public byte[] EncryptData(string publicKeyPath, byte[] dataToEncrypt)
        {
            byte[] cipherBytes;

            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;

                rsa.FromXmlString(File.ReadAllText(publicKeyPath));

                cipherBytes = rsa.Encrypt(dataToEncrypt, false);
            }

            return cipherBytes;
        }

        public byte[] DecryptData(string privateKeyPath, byte[] dataToDecrypt)
        {
            byte[] plain;

            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;

                rsa.FromXmlString(File.ReadAllText(privateKeyPath));

                plain = rsa.Decrypt(dataToDecrypt, false);
            }

            return plain;
        }
    }
}
