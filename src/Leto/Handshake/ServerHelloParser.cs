using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Text;
using Leto.Internal;

namespace Leto.Handshake
{
    public ref struct ServerHelloParser
    {
        private Span<byte> _originalMessage;
        private TlsVersion _tlsVersion;
        private Span<byte> _serverRandom;
        private Span<byte> _sessionId;
        private Span<byte> _supportedGroups;
        private ushort _cipherSuite;

        public ServerHelloParser(ReadableBuffer buffer, SecurePipeConnection secureConnection)
        {
            _originalMessage = buffer.ToSpan();
            var span = new BigEndianAdvancingSpan(_originalMessage);
            span.Read<HandshakeHeader>();
            _tlsVersion = span.Read<TlsVersion>();
            _serverRandom = span.TakeSlice(TlsConstants.RandomLength).ToSpan();
            _sessionId = span.ReadVector<byte>().ToSpan();
            _cipherSuite = span.Read<ushort>();

            var compression = span.Read<byte>(); //Dump compression
            if(compression != 0)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.handshake_failure, "Compression is not supported");
            }

            _supportedGroups = default;
            if (span.Length == 0) return;

            span = span.ReadVector<ushort>();
            while (span.Length > 0)
            {
                var extType = span.Read<ExtensionType>();
                var extBuffer = span.ReadVector<ushort>();

                switch (extType)
                {
                    case ExtensionType.supported_groups:
                        throw new NotImplementedException();
                    case ExtensionType.application_layer_protocol_negotiation:
                        throw new NotImplementedException();
                    case ExtensionType.server_name:
                        throw new NotImplementedException();
                    case ExtensionType.SessionTicket:
                        throw new NotImplementedException();
                    case ExtensionType.signature_algorithms:
                        throw new NotImplementedException();
                    case ExtensionType.renegotiation_info:
                        throw new NotImplementedException();
                }
            }
        }

        public TlsVersion TlsVersion => _tlsVersion;
        public ushort CipherSuite => _cipherSuite;
        public Span<byte> SupportedGroups => _supportedGroups;
        public Span<byte> OriginalMessage => _originalMessage;
        public Span<byte> ServerRandom => _serverRandom;
    }
}
