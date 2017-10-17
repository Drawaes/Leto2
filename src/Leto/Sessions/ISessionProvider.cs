using System;
using System.IO.Pipelines;
using Leto.Internal;

namespace Leto.Sessions
{
    public interface ISessionProvider : IDisposable
    {
        BigEndianAdvancingSpan ProcessSessionTicket(BigEndianAdvancingSpan sessionTicket);
        void EncryptSessionKey(ref WriterWrapper writer, Span<byte> ticketContent);
        int SizeOfEncryptedKey(int ticketContentSize);
        DateTime GetCurrentExpiry();
    }
}
