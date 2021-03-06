using Leto.RecordLayer;
using System;
using System.IO.Pipelines;

namespace Leto.BulkCiphers
{
    public abstract class AeadBulkCipher : IDisposable
    {
        protected const int AdditionalInfoHeaderSize = 13;
        protected ulong _sequenceNumber;
        protected ISymmetricalCipher _key;
                
        public int Overhead => _key.TagSize;

        public abstract void Decrypt(ref ReadableBuffer messageBuffer, RecordType recordType, TlsVersion tlsVersion);
        public abstract void Encrypt(ref WritableBuffer writer, ReadableBuffer plainText, RecordType recordType, TlsVersion tlsVersion);
        public abstract void Encrypt(ref WritableBuffer writer, Span<byte> plainText, RecordType recordType, TlsVersion tlsVersion);
        public void SetKey(ISymmetricalCipher key) => _key = key;
        public virtual void IncrementSequence() => _sequenceNumber++;

        protected void WriteTag(ref WritableBuffer writer)
        {
            writer.Ensure(_key.TagSize);
            _key.GetTag(writer.Buffer.Span.Slice(0, _key.TagSize));
            writer.Advance(_key.TagSize);
        }

        protected void Decrypt(ref ReadableBuffer messageBuffer)
        {
            if (messageBuffer.IsSingleSpan)
            {
                _key.Finish(messageBuffer.First.Span);
                IncrementSequence();
                return;
            }
            var bytesRemaining = messageBuffer.Length;
            foreach (var b in messageBuffer)
            {
                if (b.Length == 0) continue;
                bytesRemaining -= b.Length;
                if (bytesRemaining == 0)
                {
                    _key.Finish(b.Span);
                    break;
                }
                _key.Update(b.Span);
            }
            IncrementSequence();
        }

        public void Dispose()
        {
            _key?.Dispose();
            _key = null;
            GC.SuppressFinalize(this);
        }

        ~AeadBulkCipher() => Dispose();
    }
}
