using Leto.Certificates;
using Leto.ConnectionStates.SecretSchedules;
using Leto.Handshake.Extensions;
using Leto.Sessions;
using System;
using System.Buffers;
using System.IO.Pipelines;
using System.Threading.Tasks;

namespace Leto
{
    public abstract class SecurePipeOptions : IDisposable
    {
        private ApplicationLayerProtocolProvider _alpnProvider;
        private SecureRenegotiationProvider _secureRenegotiationProvider;
        private CertificateList _certificateList = new CertificateList();
        private HostNameProvider _hostNameProvider = new HostNameProvider();
        private SecretSchedulePool _secretPool;
        private PipeOptions _pipeOptions;
        private BufferPool _bufferPool;

        protected SecurePipeOptions(ICertificate certificate, PipeOptions pipeOptions = null, SecurePipeListenerConfig config = null)
        {
            config = config ?? new SecurePipeListenerConfig();
            if (pipeOptions == null)
            {
                _bufferPool = new MemoryPool();
                _pipeOptions = new PipeOptions(_bufferPool);
            }
            else
            {
                _pipeOptions = pipeOptions;
            }
            _secretPool = new SecretSchedulePool(config.MaxInFightHandshakes, config.MaxInFlightConnections);
            _certificateList.AddCertificate(certificate);
            _alpnProvider = new ApplicationLayerProtocolProvider(true, ApplicationLayerProtocolType.Http1_1);
            _secureRenegotiationProvider = new SecureRenegotiationProvider();
        }

        public abstract ICryptoProvider CryptoProvider { get; set; }
        public abstract ISessionProvider SessionProvider { get; }
        public ApplicationLayerProtocolProvider AlpnProvider => _alpnProvider;
        public SecureRenegotiationProvider SecureRenegotiationProvider => _secureRenegotiationProvider;
        public CertificateList CertificateList => _certificateList;
        public SecretSchedulePool SecretSchedulePool => _secretPool;
        public HostNameProvider HostNameProvider => _hostNameProvider;
        internal PipeOptions PipeOptions => _pipeOptions;

        public Task<SecurePipeConnection> CreateConnection(IPipeConnection connection)
        {
            var secureConnection = new SecurePipeServerConnection(connection, this);
            return secureConnection.HandshakeAwaiter;
        }

        public Task<SecurePipeConnection> CreateClientConnection(IPipeConnection connection)
        {
            var secureConnection = new SecurePipeClientConnection(connection, this);
            return secureConnection.HandshakeAwaiter;
        }

        public void Dispose() => Dispose(false);
        
        protected virtual void Dispose(bool disposing)
        {
            _bufferPool?.Dispose();
            _secretPool?.Dispose();
            _secretPool = null;
            GC.SuppressFinalize(this);
        }

        ~SecurePipeOptions() => Dispose(true);
    }
}
