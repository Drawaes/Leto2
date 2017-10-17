using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Runtime.CompilerServices;
using System.Text;
using Leto.BulkCiphers;
using Leto.CipherSuites;
using Leto.Handshake;
using Leto.Hashes;
using Leto.Internal;
using Leto.RecordLayer;

namespace Leto.ConnectionStates
{
    public class Client12ConnectionState : ConnectionState
    {
        private bool _initialSendDone = false;
        private SecretSchedules.SecretSchedule12 _secretSchedule;

        public override TlsVersion RecordVersion => TlsVersion.Tls12;

        public override void ChangeCipherSpec()
        {
            if(_state != HandshakeState.WaitingForChangeCipherSpec)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.handshake_failure, $"Got change cipher spec but got {_state}");
            }
            _readKey = _storedKey;
            _state = HandshakeState.WaitingForServerFinished;
        }

        public override bool ProcessHandshake()
        {
            if (!_initialSendDone)
            {
                SendFirstFlight();
                return true;
            }

            var hasWritten = false;
            var hasReader = Connection.HandshakeInput.Reader.TryRead(out var reader);
            if (!hasReader) return hasWritten;
            var buffer = reader.Buffer;
            try
            {
                while (HandshakeFraming.ReadHandshakeFrame(ref buffer, out var messageBuffer, out var messageType))
                {
                    switch (messageType)
                    {
                        case HandshakeType.server_hello when _state == HandshakeState.WaitingForServerHello:
                            HandleServerHello(messageBuffer);
                            break;
                        case HandshakeType.certificate when _state == HandshakeState.WaitingForServerCertificate:
                            HandleServerCertificate(messageBuffer);
                            break;
                        case HandshakeType.server_key_exchange:
                            HandleServerKeyExchange(messageBuffer);
                            break;
                        case HandshakeType.server_hello_done:
                            SecondFlight(messageBuffer);
                            return true;
                        case HandshakeType.finished when _state == HandshakeState.WaitingForServerFinished:
                            HandleServerFinished(messageBuffer);
                            return false;
                        default:
                            Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.unexpected_message, "Unknown message type");
                            return false;
                    }
                }
            }
            finally
            {
                Connection.HandshakeInput.Reader.Advance(buffer.Start, buffer.End);
            }
            return hasWritten;
        }

        private void SendFirstFlight()
        {
            _initialSendDone = true;
            // Write the client hello
            _secretSchedule = new SecretSchedules.SecretSchedule12(this);
            HandshakeHash = new HashBuffer(new Memory<byte>(new byte[HelloSize() + 4]));
            this.WriteHandshakeFrame(HelloSize(), WriteClientHello, HandshakeType.client_hello);
            _state = HandshakeState.WaitingForServerHello;
            RecordHandler.WriteRecords(Connection.HandshakeOutput.Reader, RecordType.Handshake);
        }

        private void HandleServerFinished(ReadableBuffer messageBuffer)
        {
            if (!_secretSchedule.GenerateAndCompareServerVerify(messageBuffer))
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.handshake_failure, "Failed to verify server finished");
            }
            _state = HandshakeState.HandshakeCompleted;
            _secretSchedule.DisposeStore();
        }

        private void HandleServerKeyExchange(ReadableBuffer messageBuffer)
        {
            HandshakeHash.HashData(messageBuffer);
            var parser = new ServerKeyExchangeParser(messageBuffer);
            _signatureScheme = parser.SignatureScheme;
            _certificate.CheckSignature(_cryptoProvider.HashProvider, _signatureScheme, parser.Signature, parser.Data);
            KeyExchange.SetPeerKey(parser.Key, _certificate, _signatureScheme);
        }

        private void HandleServerCertificate(ReadableBuffer messageBuffer)
        {
            HandshakeHash.HashData(messageBuffer);
            _certificate = Connection.Listener.CertificateList.CheckCertificate(messageBuffer);
            KeyExchange.SetCertificate(_certificate);
            if (KeyExchange.RequiresServerKeyExchange)
            {
                _state = HandshakeState.WaitingForServerKeyExchange;
            }
            else
            {
                _state = HandshakeState.WaitingForServerHelloDone;
            }
        }

        private void HandleServerHello(ReadableBuffer messageBuffer)
        {
            var helloParser = new ServerHelloParser(messageBuffer, Connection);
            var version = GetVersion(ref helloParser);
            if (version != TlsVersion.Tls12)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.protocol_version, "Invalid protocol version");
            }
            _secretSchedule.SetServerRandom(helloParser.ServerRandom);
            CipherSuite = _cryptoProvider.CipherSuites.GetCipherSuite(TlsVersion.Tls12, helloParser.CipherSuite);
            KeyExchange = _cryptoProvider.KeyExchangeProvider.GetKeyExchange(CipherSuite.KeyExchange, new BigEndianAdvancingSpan(helloParser.SupportedGroups));
            var oldHash = HandshakeHash;
            HandshakeHash = _cryptoProvider.HashProvider.GetHash(CipherSuite.HashType);
            HandshakeHash.HashData(((HashBuffer)oldHash).GetBufferedData());
            HandshakeHash.HashData(helloParser.OriginalMessage);
            _state = HandshakeState.WaitingForServerCertificate;
        }

        private void SecondFlight(ReadableBuffer messageBuffer)
        {
            HandshakeHash.HashData(messageBuffer);
            if (messageBuffer.Length < 4)
            {
                throw new NotImplementedException();
            }
            // send second flight
            var sendSize = KeyExchange.ClientSendSize;
            _secretSchedule.GenerateMasterSecret(false);
            this.WriteHandshakeFrame(sendSize, KeyExchange.ClientSendKey, HandshakeType.client_key_exchange);
            RecordHandler.WriteRecords(Connection.HandshakeOutput.Reader, RecordType.Handshake);
            WriteChangeCipherSpec();
            (_writeKey, _storedKey) = _secretSchedule.GenerateKeys();
            _state = HandshakeState.WaitingForClientFinished;
            this.WriteHandshakeFrame(_secretSchedule.ClientVerifySize, WriteClientVerify, HandshakeType.finished);
            RecordHandler.WriteRecords(Connection.HandshakeOutput.Reader, RecordType.Handshake);
            _state = HandshakeState.WaitingForChangeCipherSpec;
        }

        private void WriteClientVerify(ref WriterWrapper writer)
        {
            var cverify = _secretSchedule.GenerateClientVerify();
            writer.Write(cverify);
        }

        private void WriteChangeCipherSpec()
        {
            var writer = Connection.HandshakeOutput.Writer.Alloc();
            writer.WriteBigEndian<byte>(1);
            writer.Commit();
            RecordHandler.WriteRecords(Connection.HandshakeOutput.Reader, RecordType.ChangeCipherSpec);
        }

        private int HelloSize()
        {
            var size = _secretSchedule.ClientRandom.Length;
            size += Unsafe.SizeOf<TlsVersion>();
            size += 1; // Session id byte length and zero long
            size += _cryptoProvider.CipherSuites.CipherSuitesSize;
            size += 1; // No compression
            return size;
        }

        private void WriteClientHello(ref WriterWrapper writer)
        {
            writer.WriteBigEndian(RecordVersion);
            _secretSchedule.GenerateClientRandom();
            writer.Write(_secretSchedule.ClientRandom);
            writer.WriteBigEndian<byte>(0);
            writer.Write(_cryptoProvider.CipherSuites.GetCipherSuites());
            writer.WriteBigEndian<byte>(0);
        }
    }
}
