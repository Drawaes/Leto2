using System;
using System.Buffers;
using System.IO.Pipelines;
using System.Runtime;
using System.Runtime.CompilerServices;
using Leto.Internal;

namespace Leto
{
    public static class BufferExtensions
    {
        public delegate void ContentWriter(ref WriterWrapper writer);

        internal static unsafe T Reverse<[Primitive]T>(T value) where T : struct
        {
            // note: relying on JIT goodness here!
            if (typeof(T) == typeof(byte) || typeof(T) == typeof(sbyte))
            {
                return value;
            }
            else if (typeof(T) == typeof(ushort) || typeof(T) == typeof(short))
            {
                ushort val = 0;
                Unsafe.Write(&val, value);
                val = (ushort)((val >> 8) | (val << 8));
                return Unsafe.Read<T>(&val);
            }
            else if (typeof(T) == typeof(uint) || typeof(T) == typeof(int)
                || typeof(T) == typeof(float))
            {
                uint val = 0;
                Unsafe.Write(&val, value);
                val = (val << 24)
                    | ((val & 0xFF00) << 8)
                    | ((val & 0xFF0000) >> 8)
                    | (val >> 24);
                return Unsafe.Read<T>(&val);
            }
            else if (typeof(T) == typeof(ulong) || typeof(T) == typeof(long)
                || typeof(T) == typeof(double))
            {
                ulong val = 0;
                Unsafe.Write(&val, value);
                val = (val << 56)
                    | ((val & 0xFF00) << 40)
                    | ((val & 0xFF0000) << 24)
                    | ((val & 0xFF000000) << 8)
                    | ((val & 0xFF00000000) >> 8)
                    | ((val & 0xFF0000000000) >> 24)
                    | ((val & 0xFF000000000000) >> 40)
                    | (val >> 56);
                return Unsafe.Read<T>(&val);
            }
            else
            {
                // default implementation
                var len = Unsafe.SizeOf<T>();
                var val = stackalloc byte[len];
                Unsafe.Write(val, value);
                int to = len >> 1, dest = len - 1;
                for (var i = 0; i < to; i++)
                {
                    var tmp = val[i];
                    val[i] = val[dest];
                    val[dest--] = tmp;
                }
                return Unsafe.Read<T>(val);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Span<byte> ToSpan(this ReadableBuffer buffer)
        {
            if (buffer.IsSingleSpan)
            {
                return buffer.First.Span;
            }
            return buffer.ToArray();
        }

        //public static void WriteVector<[Primitive] T>(ref WriterWrapper buffer, ContentWriter writeContent) where T : struct
        //{
        //    var bookMark = buffer.Buffer;
        //    if (typeof(T) == typeof(ushort) || typeof(T) == typeof(short))
        //    {
        //        buffer.Ensure(2);
        //        buffer.Advance(2);
        //    }
        //    else if (typeof(T) == typeof(byte))
        //    {
        //        buffer.Ensure(1);
        //        buffer.Advance(1);
        //    }
        //    else if(typeof(T) == typeof(UInt24))
        //    {
        //        buffer.Ensure(3);
        //        buffer.Advance(3);
        //    }
        //    else
        //    {
        //        Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.internal_error, $"Unkown vector type {typeof(T).Name}");
        //    }
        //    var sizeofVector = buffer.BytesWritten;
        //    writeContent(ref buffer);
        //    sizeofVector = buffer.BytesWritten - sizeofVector;
        //    if (typeof(T) == typeof(ushort) || typeof(T) == typeof(short))
        //    {
        //        bookMark.Span.WriteBigEndian((ushort)sizeofVector);
        //    }
        //    else if(typeof(T) == typeof(UInt24))
        //    {
        //        bookMark.Span.WriteBigEndian((UInt24)sizeofVector);
        //    }
        //    else
        //    {
        //        bookMark.Span.Write((byte)sizeofVector);
        //    }
        //}

        public static int WriteBigEndian<T>(this Span<byte> span, T value)
            where T : struct
        {
            if (BitConverter.IsLittleEndian)
            {
                value = Reverse(value);
            }
            return span.Write(value);
        }

        public static T ReadBigEndian<T>(this Span<byte> span)
            where T : struct
        {
            var value = span.Read<T>();
            if(BitConverter.IsLittleEndian)
            {
                value = Reverse(value);
            }
            return value;
        }

        public unsafe static int Write<T>(this Span<byte> span, T value)
            where T : struct
        {
            var length = Unsafe.SizeOf<T>();
            if (span.Length < length)
            {
                throw new ArgumentOutOfRangeException(nameof(value));
            }

            fixed (void* sPtr = &span.DangerousGetPinnableReference())
            {
                Unsafe.Write(sPtr, value);
            }
            return length;
        }

        public static Memory<byte> SliceAndConsume(ref Memory<byte> buffer, int size)
        {
            var returnBuffer = buffer.Slice(0, size);
            buffer = buffer.Slice(size);
            return returnBuffer;
        }

        public static void CopyTo(this Memory<byte> buffer, Span<byte> span) => buffer.Span.CopyTo(span);

        public static Span<byte> Slice(this byte[] buffer, int start, int length) => new Span<byte>(buffer, start, length);

        public static Span<byte> Slice(this byte[] buffer, int start) => new Span<byte>(buffer, start, buffer.Length - start);
    }
}
