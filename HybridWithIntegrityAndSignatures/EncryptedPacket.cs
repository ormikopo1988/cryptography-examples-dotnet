namespace HybridWithIntegrityAndSignatures
{
    public class EncryptedPacket
    {
        public byte[] EncryptedSessionKey;
        public byte[] EncryptedData;
        public byte[] IV;
        public byte[] HMAC;
        public byte[] Signature;
    }
}
