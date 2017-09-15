namespace HybridWithIntegrityCheck
{
    public class EncryptedPacket
    {
        public byte[] EncryptedSessionKey;
        public byte[] EncryptedData;
        public byte[] IV;
        public byte[] HMAC;
    }
}
