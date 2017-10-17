using System;
using System.Buffers;
using Leto.Hashes;
using static Leto.BufferExtensions;
using Leto.BulkCiphers;
using static Leto.TlsConstants;
using System.Runtime.InteropServices;
using System.IO.Pipelines;
using Leto.Sessions;
using Leto.Handshake;
using Leto.Internal;
using System.Runtime.CompilerServices;

namespace Leto.ConnectionStates.SecretSchedules
{
    public class SecretSchedule12 : IDisposable
    {
        private OwnedMemory<byte> _secretStore;
        private Memory<byte> _clientRandom;
        private Memory<byte> _serverRandom;
        private Memory<byte> _masterSecret;
        private Memory<byte> _clientVerify;
        private Memory<byte> _serverVerify;
        private ConnectionState _state;
        private ICryptoProvider _cryptoProvider;

        public SecretSchedule12(ConnectionState state)
        {
            _state = state;
            _secretStore = state.Connection.Listener.SecretSchedulePool.GetSecretBuffer();
            var memory = _secretStore.Memory;
            _clientRandom = SliceAndConsume(ref memory, RandomLength);
            _serverRandom = SliceAndConsume(ref memory, RandomLength);
            _masterSecret = SliceAndConsume(ref memory, Tls12.MasterSecretLength);
            _clientVerify = SliceAndConsume(ref memory, VerifyDataLength);
            _serverVerify = SliceAndConsume(ref memory, VerifyDataLength);
            _cryptoProvider = state.Connection.Listener.CryptoProvider;
        }

        internal ReadOnlySpan<byte> ClientRandom => _clientRandom.Span;
        internal ReadOnlySpan<byte> ServerRandom => _serverRandom.Span;
        private ISessionProvider Sessions => _state.Connection.Listener.SessionProvider;

        public int ClientVerifySize => _clientVerify.Length;

        public void SetClientRandom(Span<byte> random)
        {
            random.CopyTo(_clientRandom.Span);
            GenerateServerRandom();
        }

        public void GenerateClientRandom()
        {
            var span = _clientRandom.Span;
            _cryptoProvider.FillWithRandom(span);
        }

        private void GenerateServerRandom()
        {
            var span = _serverRandom.Span;
            var randomBytes = RandomLength - Tls12.EndOfRandomDowngradeProtection.Length;
            _cryptoProvider.FillWithRandom(span.Slice(0, randomBytes));
            span = span.Slice(randomBytes);
            //https://tlswg.github.io/tls13-spec/#rfc.section.4.1.3
            //Last 8 bytes of random are a special value to protect against downgrade attacks
            Tls12.EndOfRandomDowngradeProtection.CopyTo(span);
        }

        internal void SetServerRandom(Span<byte> serverRandom) => serverRandom.CopyTo(_serverRandom.Span);

        public void GenerateMasterSecret(bool dispose)
        {
            var seed = new byte[RandomLength * 2];
            _clientRandom.Span.CopyTo(seed);
            _serverRandom.Span.CopyTo(seed.Slice(RandomLength));
            _state.KeyExchange.DeriveMasterSecret(_cryptoProvider.HashProvider, _state.CipherSuite.HashType, seed, _masterSecret.Span);
            if (dispose)
            {
                _state.KeyExchange.Dispose();
                _state.KeyExchange = null;
            }
        }

        public bool ReadSessionTicket(BigEndianAdvancingSpan buffer)
        {
            var advanceBuffer = Sessions.ProcessSessionTicket(buffer);
            if (advanceBuffer.Length == 0)
            {
                return false;
            }
            var info = advanceBuffer.Read<SessionInfo>();
            if (info.Version != _state.RecordVersion)
            {
                return false;
            }
            _state.CipherSuite = _cryptoProvider.CipherSuites.GetCipherSuite(info.CipherSuite);
            advanceBuffer.ToSpan().CopyTo(_masterSecret.Span);
            return true;
        }

        public void WriteSessionTicket()
        {
            if (_state.Connection.Listener.SessionProvider == null) return;
            var size = sizeof(uint) + Sessions.SizeOfEncryptedKey(_masterSecret.Length) + Unsafe.SizeOf<SessionInfo>();
            _state.WriteHandshakeFrame(size, (ref WriterWrapper w) =>
            {
                var currentExpiry = _state.Connection.Listener.SessionProvider.GetCurrentExpiry();
                w.WriteBigEndian((uint)(DateTime.UtcNow - currentExpiry).TotalSeconds);
                var ticketBuffer = new byte[Marshal.SizeOf<SessionInfo>() + _masterSecret.Length];
                var ticketSpan = new Span<byte>(ticketBuffer);
                var info = new SessionInfo()
                {
                    CipherSuite = _state.CipherSuite.Code,
                    Timestamp = currentExpiry.Ticks,
                    Version = _state.RecordVersion
                };
                ticketSpan.WriteBigEndian(info);
                _masterSecret.CopyTo(ticketSpan.Slice(Marshal.SizeOf<SessionInfo>()));

                Sessions.EncryptSessionKey(ref w, ticketBuffer);
            }, HandshakeType.new_session_ticket);
        }

        public bool GenerateAndCompareClientVerify(Span<byte> clientVerify)
        {
            var hashResult = new byte[_state.HandshakeHash.HashSize];
            _state.HandshakeHash.InterimHash(hashResult);
            _cryptoProvider.HashProvider.Tls12Prf(_state.CipherSuite.HashType, _masterSecret.Span, Tls12.Label_ClientFinished, hashResult, _clientVerify.Span);
            _state.HandshakeHash.HashData(clientVerify);
            return Internal.CompareFunctions.ConstantTimeEquals(_clientVerify.Span, clientVerify.Slice(Marshal.SizeOf<HandshakeHeader>()));
        }

        public Span<byte> GenerateClientVerify()
        {
            var hashResult = new byte[_state.HandshakeHash.HashSize];
            _state.HandshakeHash.InterimHash(hashResult);
            _cryptoProvider.HashProvider.Tls12Prf(_state.CipherSuite.HashType, _masterSecret.Span, Tls12.Label_ClientFinished, hashResult, _clientVerify.Span);
            return _clientVerify.Span;
        }

        public void GenerateAndWriteServerVerify()
        {
            var hashResult = new byte[_state.HandshakeHash.HashSize];
            _state.HandshakeHash.InterimHash(hashResult);
            _cryptoProvider.HashProvider.Tls12Prf(_state.CipherSuite.HashType, _masterSecret.Span, Tls12.Label_ServerFinished, hashResult, _serverVerify.Span);
            _state.WriteHandshakeFrame(_serverVerify.Span.Length, WriteServerVerify, HandshakeType.finished);
        }

        public bool GenerateAndCompareServerVerify(ReadableBuffer buffer)
        {
            buffer = buffer.Slice(Unsafe.SizeOf<HandshakeHeader>());
            var hashResult = new byte[_state.HandshakeHash.HashSize];
            _state.HandshakeHash.FinishHash(hashResult);
            _cryptoProvider.HashProvider.Tls12Prf(_state.CipherSuite.HashType, _masterSecret.Span, Tls12.Label_ServerFinished, hashResult, _serverVerify.Span);
            return CompareFunctions.ConstantTimeEquals(_serverVerify.Span, buffer.ToSpan());
        }

        private void WriteServerVerify(ref WriterWrapper writer) => writer.Write(_serverVerify.Span);

        public (AeadBulkCipher clientKey, AeadBulkCipher serverKey) GenerateKeys()
        {
            var (keySize, ivSize) = _cryptoProvider.BulkCipherProvider.GetCipherSize(_state.CipherSuite.BulkCipherType);
            var materialLength = (keySize + 4) * 2;
            var material = new byte[materialLength];
            var seedLength = _clientRandom.Length * 2;
            var seed = new byte[seedLength];
            _serverRandom.CopyTo((Span<byte>)seed);
            _clientRandom.CopyTo(seed.Slice(_serverRandom.Length));
            _cryptoProvider.HashProvider.Tls12Prf(_state.CipherSuite.HashType, _masterSecret.Span, Tls12.Label_KeyExpansion, seed, material);
            var clientBuffer = _state.Connection.Listener.SecretSchedulePool.GetKeyBuffer();
            var serverBuffer = _state.Connection.Listener.SecretSchedulePool.GetKeyBuffer();

            material.Slice(0, keySize).CopyTo(clientBuffer.Span);
            material.Slice(keySize * 2, 4).CopyTo(clientBuffer.Span.Slice(keySize));
            material.Slice(keySize, keySize).CopyTo(serverBuffer.Span);
            material.Slice(keySize * 2 + 4, 4).CopyTo(serverBuffer.Span.Slice(keySize));
            var clientKey = _cryptoProvider.BulkCipherProvider.GetCipher<AeadTls12BulkCipher>(_state.CipherSuite.BulkCipherType, clientBuffer);
            var serverKey = _cryptoProvider.BulkCipherProvider.GetCipher<AeadTls12BulkCipher>(_state.CipherSuite.BulkCipherType, serverBuffer);
            return (clientKey, serverKey);
        }

        public void DisposeStore()
        {
            _secretStore?.Dispose();
            _secretStore = null;
            _state.HandshakeHash?.Dispose();
            _state.HandshakeHash = null;
        }

        public void Dispose()
        {
            try
            {
                _secretStore?.Dispose();
                _secretStore = null;
                GC.SuppressFinalize(this);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Exception disposing key {ex}");
                throw;
            }
        }

        ~SecretSchedule12()
        {
            Dispose();
        }
    }
}
