using Leto.Hashes;
using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Runtime.CompilerServices;
using System.Text;

namespace Leto.Internal
{
    public struct WriterWrapper
    {
        private WritableBuffer _innerBuffer;
        private IHash _handshakeHash;
        private int _bytesWritten;
        private int _bytesRemaining;

        public WriterWrapper(WritableBuffer buffer, IHash handshakeHash)
        {
            _bytesWritten = 0;
            _bytesRemaining = 0;
            _handshakeHash = handshakeHash;
            _innerBuffer = buffer;
        }

        public void Commit() => _innerBuffer.Commit();

        public int BytesWritten => _bytesWritten;

        public Span<byte> Span => _innerBuffer.Buffer.Span;

        public void WriteBigEndian<T>(T value) where T : struct
        {
            var size = Unsafe.SizeOf<T>();
            if(_bytesRemaining < size)
            {
                _innerBuffer.Ensure(size);
                _bytesRemaining = _innerBuffer.Buffer.Length;
            }
            var s = _innerBuffer.Buffer.Span;
            size = s.WriteBigEndian(value);
            _handshakeHash?.HashData(s.Slice(0, size));
            _innerBuffer.Advance(size);
            _bytesWritten += size;
            _bytesRemaining -= size;
        }

        public void Write(ReadOnlySpan<byte> input)
        {
            _innerBuffer.Ensure(input.Length);
            _innerBuffer.Write(input);
            _handshakeHash?.HashData(input);
            _bytesWritten += input.Length;
            _bytesRemaining = _innerBuffer.Buffer.Length;
        }

        public WritableBufferAwaitable FlushAsync() => _innerBuffer.FlushAsync();

        internal void Enusure(int messageLength)
        {
            _innerBuffer.Ensure(messageLength);
            _bytesRemaining = _innerBuffer.Buffer.Length;
        }
    }
}
