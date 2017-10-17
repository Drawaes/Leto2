using Leto.Hashes;
using System;
using System.IO.Pipelines;
using System.Runtime.InteropServices;
using Leto.Internal;
using System.Buffers;
using System.Diagnostics;

namespace Leto.Handshake
{
    public static class HandshakeFraming
    {
        public static readonly int HeaderSize = Marshal.SizeOf<HandshakeHeader>();

        public static bool ReadHandshakeFrame(ref ReadableBuffer buffer, out ReadableBuffer handshakeMessage, out HandshakeType handshakeType)
        {
            if(buffer.Length < HeaderSize)
            {
                handshakeMessage = default;
                handshakeType = HandshakeType.none;
                return false;
            }
            var header = buffer.Slice(0, HeaderSize).ToSpan().Read<HandshakeHeader>();
            if(buffer.Length < (header.Length + HeaderSize))
            {
                handshakeMessage = default;
                handshakeType = HandshakeType.none;
                return false;
            }
            handshakeMessage = buffer.Slice(0, HeaderSize + (int)header.Length);
            buffer = buffer.Slice((int)header.Length + HeaderSize);
            handshakeType = header.MessageType;
            return true;
        }

        public static void WriteHandshakeFrame(this ConnectionStates.ConnectionState state,int contentSize, BufferExtensions.ContentWriter content, HandshakeType handshakeType)
        {
            var writer = new WriterWrapper(state.Connection.HandshakeOutput.Writer.Alloc(), state.HandshakeHash);
            writer.WriteBigEndian(handshakeType);
            writer.WriteBigEndian((UInt24)contentSize);
            content(ref writer);
            Debug.Assert((writer.BytesWritten - 4) == contentSize);
            writer.Commit();
        }
    }
}
