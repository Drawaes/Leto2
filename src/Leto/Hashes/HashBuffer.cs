using System;
using System.Collections.Generic;
using System.Text;

namespace Leto.Hashes
{
    public class HashBuffer : IHash
    {
        private Memory<byte> _buffer;
        private Memory<byte> _originalBuffer;

        public HashBuffer(Memory<byte> buffer)
        {
            _buffer = buffer;
            _originalBuffer = _buffer;
        }

        public int HashSize => throw new NotImplementedException();
                
        public void Dispose()
        {
        }

        public int FinishHash(Span<byte> output)
        {
            throw new NotImplementedException();
        }

        public void HashData(ReadOnlySpan<byte> data)
        {
            data.CopyTo(_buffer.Span);
            _buffer = _buffer.Slice(data.Length);
        }

        public int InterimHash(Span<byte> output)
        {
            throw new NotImplementedException();
        }

        internal ReadOnlySpan<byte> GetBufferedData() => _originalBuffer.Span;
    }
}
