using System;
using System.Buffers;

namespace Leto.BulkCiphers
{
    public interface IBulkCipherKeyProvider : IDisposable
    {
        T GetCipher<T>(BulkCipherType cipherType, OwnedMemory<byte> keyStorage) where T : AeadBulkCipher, new();
        ISymmetricalCipher GetCipherKey(BulkCipherType cipherType, OwnedMemory<byte> keyStorag);
        (int keySize, int ivSize) GetCipherSize(BulkCipherType cipherType);
    }
}