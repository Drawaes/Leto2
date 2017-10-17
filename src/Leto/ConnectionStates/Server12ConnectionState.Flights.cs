using Leto.Handshake;
using Leto.KeyExchanges;
using Leto.RecordLayer;
using System;
using System.Buffers;
using System.IO.Pipelines;
using Leto.Internal;
using System.Runtime.CompilerServices;

namespace Leto.ConnectionStates
{
    public sealed partial class Server12ConnectionState
    {
        private void SendFirstFlightAbbreviated(ClientHelloParser clientHello)
        {
            WriteServerHello(clientHello.SessionId);
            _secretSchedule.WriteSessionTicket();
            RecordHandler.WriteRecords(Connection.HandshakeOutput.Reader, RecordType.Handshake);
            _requiresTicket = false;
            WriteChangeCipherSpec();
            (_storedKey, _writeKey) = _secretSchedule.GenerateKeys();
            _secretSchedule.GenerateAndWriteServerVerify();
            _state = HandshakeState.WaitingForClientFinishedAbbreviated;
            RecordHandler.WriteRecords(Connection.HandshakeOutput.Reader, RecordType.Handshake);
        }

        private void SendFirstFlightFull()
        {
            if (KeyExchange == null)
            {
                KeyExchange = _cryptoProvider.KeyExchangeProvider.GetKeyExchange(CipherSuite.KeyExchange, default);
            }
            SendSecondFlight();
            _state = HandshakeState.WaitingForClientKeyExchange;
            RecordHandler.WriteRecords(Connection.HandshakeOutput.Reader, RecordType.Handshake);
        }

        private void SendSecondFlight()
        {
            WriteServerHello(default);
            WriteCertificates();
            WriteServerKeyExchange();
            WriteServerHelloDone();
        }

        private void WriteServerHelloDone() =>
            this.WriteHandshakeFrame(0, (ref WriterWrapper buffer) => { return; }, HandshakeType.server_hello_done);

        private void WriteServerKeyExchange()
        {
            if (KeyExchange.RequiresServerKeyExchange)
            {
                this.WriteHandshakeFrame(TotalKeySize(), SendKeyExchange, HandshakeType.server_key_exchange);
            }
        }

        private void WriteServerHello(Span<byte> sessionId) =>
            this.WriteHandshakeFrame(SizeOfServerHelloContent(), (ref WriterWrapper buffer) => WriteServerHelloContent(ref buffer), HandshakeType.server_hello);

        private void WriteServerHelloContent(ref WriterWrapper writer)//, Span<byte> sessionId)
        {
            var fixedSize = SizeOfServerHello();// sessionId.Length;
            writer.WriteBigEndian(TlsVersion.Tls12);
            writer.Write(_secretSchedule.ServerRandom);

            //We don't support session id's instead resumption is supported through tickets
            //If we are using a ticket the client will want us to respond with the same id
            writer.WriteBigEndian((byte)0);// sessionId.Length);
            //span.CopyFrom(sessionId);

            writer.WriteBigEndian(CipherSuite.Code);
            //We don't support compression at the TLS level as it is prone to attacks
            writer.WriteBigEndian<byte>(0);

            //Completed the fixed section now we write the extensions
            writer.WriteBigEndian((ushort)SizeOfServerHelloExtensions());
            WriteExtensions(ref writer);
        }

        private int SizeOfServerHello() => TlsConstants.RandomLength + sizeof(TlsVersion) + 2 * sizeof(byte) + sizeof(ushort) + 0;
        private int SizeOfServerHelloExtensions()
        {
            var size = 0;
            if (_secureRenegotiation)
            {
                size = Connection.Listener.SecureRenegotiationProvider.SizeOfExtension();
            }

            if (_negotiatedAlpn != Handshake.Extensions.ApplicationLayerProtocolType.None)
            {
                size = Connection.Listener.AlpnProvider.GetExtensionSize(_negotiatedAlpn);
            }

            if (_requiresTicket)
            {
                size += Unsafe.SizeOf<ExtensionType>() + sizeof(ushort);
            }

            return size;
        }
        public int SizeOfServerHelloContent() => SizeOfServerHello() + SizeOfServerHelloExtensions() + sizeof(ushort);

        public void WriteExtensions(ref WriterWrapper writer)
        {
            if (_secureRenegotiation)
            {
                Connection.Listener.SecureRenegotiationProvider.WriteExtension(ref writer);
            }
            if (_negotiatedAlpn != Handshake.Extensions.ApplicationLayerProtocolType.None)
            {
                Connection.Listener.AlpnProvider.WriteExtension(ref writer, _negotiatedAlpn);
            }
            if (_requiresTicket)
            {
                writer.WriteBigEndian(ExtensionType.SessionTicket);
                writer.WriteBigEndian((ushort)0);
            }
        }

        private int TotalKeySize()
        {
            var totalSize = _certificate.SignatureSize + 2 + 4 + KeyExchange.KeyExchangeSize + 2;
            return totalSize;
        }

        private unsafe void SendKeyExchange(ref WriterWrapper writer)
        {
            var messageLength = 4 + KeyExchange.KeyExchangeSize;
            writer.Enusure(messageLength);
            var span = writer.Span.Slice(0, messageLength);
            writer.WriteBigEndian(ECCurveType.named_curve);
            writer.WriteBigEndian(KeyExchange.NamedGroup);
            writer.WriteBigEndian((byte)KeyExchange.KeyExchangeSize);
            Span<byte> s = stackalloc byte[KeyExchange.KeyExchangeSize];
            KeyExchange.PublicKeySpan(s);
            writer.Write(s);
            writer.WriteBigEndian(_signatureScheme);
            writer.WriteBigEndian((ushort)_certificate.SignatureSize);

            WriteKeySignature(ref writer, span);
        }

        private void WriteKeySignature(ref WriterWrapper writer, Span<byte> message)
        {
            var tempBuffer = new byte[TlsConstants.RandomLength * 2 + message.Length];
            _secretSchedule.ClientRandom.CopyTo(tempBuffer);
            _secretSchedule.ServerRandom.CopyTo(tempBuffer.Slice(TlsConstants.RandomLength));
            message.CopyTo(tempBuffer.Slice(TlsConstants.RandomLength * 2));
            var hash = _certificate.SignHash(_cryptoProvider.HashProvider, _signatureScheme, tempBuffer);
            writer.Write(hash);
        }
    }
}
