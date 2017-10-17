using Leto.OpenSsl11;
using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Xunit;
using CommonFacts;
using System.Diagnostics;
using Leto.KeyExchanges;
using System.Buffers;

namespace Leto.OpenSslFacts
{
    public class ClientSslStreamFacts
    {
        [Theory]
        [InlineData(CipherSuites.PredefinedCipherSuites.PredefinedSuite.RSA_AES_128_GCM_SHA256, null)]
        [InlineData(CipherSuites.PredefinedCipherSuites.PredefinedSuite.RSA_AES_256_GCM_SHA384, null)]
        [InlineData(CipherSuites.PredefinedCipherSuites.PredefinedSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, new NamedGroup[] { NamedGroup.secp256r1 })]
        [InlineData(CipherSuites.PredefinedCipherSuites.PredefinedSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, new NamedGroup[] { NamedGroup.secp384r1 })]
        [InlineData(CipherSuites.PredefinedCipherSuites.PredefinedSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, new NamedGroup[] { NamedGroup.x25519 })]
        [InlineData(CipherSuites.PredefinedCipherSuites.PredefinedSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, null)]
        public async Task HandshakeCompletes(CipherSuites.PredefinedCipherSuites.PredefinedSuite suite, NamedGroup[] supportedNamedGroups)
        {
            using (var bufferPool = new MemoryPool())
            using (var securePipeOptions = new OpenSslSecurePipeListener(Data.Certificates.RSACertificate, new PipeOptions(bufferPool)))
            {
                if (supportedNamedGroups != null)
                {
                    securePipeOptions.CryptoProvider.KeyExchangeProvider.SetSupportedNamedGroups(supportedNamedGroups);
                }
                securePipeOptions.CryptoProvider.CipherSuites.SetCipherSuites(new CipherSuites.CipherSuite[] { CipherSuites.PredefinedCipherSuites.GetSuiteByName(suite) });
                await FullConnectionSSlStreamFacts.SmallMessageFact(new PipeOptions(bufferPool), securePipeOptions);
            }
        }


        [Fact]
        public async Task HandshakeCompletesWithEcdsa()
        {
            using (var bufferPool = new MemoryPool())
            using (var securePipeOptions = new OpenSslSecurePipeListener(Data.Certificates.ECDSACertificate, new PipeOptions(bufferPool)))
            {
                securePipeOptions.CryptoProvider.CipherSuites.SetCipherSuites(new CipherSuites.CipherSuite[] { CipherSuites.PredefinedCipherSuites.GetSuiteByName(CipherSuites.PredefinedCipherSuites.PredefinedSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384) });
                await FullConnectionSSlStreamFacts.SmallMessageFact(new PipeOptions(bufferPool), securePipeOptions);
            }
        }

        [Fact]
        public async Task EphemeralSessionProvider()
        {
            using (var bufferPool = new MemoryPool())
            {
                var options = new PipeOptions(bufferPool);
                using (var securePipeOptions = new OpenSslSecurePipeListener(Data.Certificates.RSACertificate, options))
                {
                    securePipeOptions.UseEphemeralSessionProvider();
                    await FullConnectionSSlStreamFacts.SmallMessageFact(options, securePipeOptions);
                    await FullConnectionSSlStreamFacts.SmallMessageFact(options, securePipeOptions);
                }
            }
        }

        [Fact]
        public async Task MultiBuffer()
        {
            using (var bufferPool = new MemoryPool())
            {
                var options = new PipeOptions(bufferPool);
                using (var securePipeOptions = new OpenSslSecurePipeListener(Data.Certificates.RSACertificate, options))
                {
                    await FullConnectionSSlStreamFacts.MultiBufferFact(options, securePipeOptions);
                }
            }
        }

        //[Fact]
        //public void SocketTest()
        //{
        //    var readData = string.Empty;
        //    var wait = new System.Threading.ManualResetEvent(false);
        //    using (var securePipeOptions = new System.IO.Pipelines.Networking.Sockets.SocketListener())
        //    using (var secureListener = new OpenSslSecurePipeListener(Data.Certificates.RSACertificate))
        //    {

        //        secureListener.CryptoProvider = new TestingCryptoProvider();
        //        secureListener.CryptoProvider.CipherSuites.SetCipherSuites(new CipherSuites.CipherSuite[] { CipherSuites.PredefinedCipherSuites.GetSuiteByName(CipherSuites.PredefinedCipherSuites.PredefinedSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384) });
        //        securePipeOptions.OnConnection(async (conn) =>
        //        {
        //            var pipe = await secureListener.CreateConnection(conn);
        //            Console.WriteLine("Handshake Done");
        //            var reader = await pipe.Input.ReadAsync();
        //            readData = Encoding.UTF8.GetString(reader.Buffer.ToArray());
        //            var writer = pipe.Output.Alloc();
        //            writer.Append(reader.Buffer);
        //            await writer.FlushAsync();
        //            wait.Set();
        //        });
        //        securePipeOptions.Start(new IPEndPoint(IPAddress.Any, 443));

        //        wait.WaitOne();
        //        Assert.Equal("", readData);
        //    }
        //}

        [Fact]
        public async Task Pipe2PipeTest()
        {
            var readData = string.Empty;
            var wait = new System.Threading.ManualResetEvent(false);
            var ipAddress = new IPEndPoint(IPAddress.Loopback, 27777);
            using (var securePipeOptions = new System.IO.Pipelines.Networking.Sockets.SocketListener())
            using (var secureListener = new OpenSslSecurePipeListener(Data.Certificates.RSACertificate))
            {

                //secureListener.CryptoProvider = new TestingCryptoProvider();
                secureListener.CryptoProvider.CipherSuites.SetCipherSuites(new CipherSuites.CipherSuite[] { CipherSuites.PredefinedCipherSuites.GetSuiteByName(CipherSuites.PredefinedCipherSuites.PredefinedSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) });
                securePipeOptions.OnConnection(async (conn) =>
                {
                    var pipe = await secureListener.CreateConnection(conn);
                    Console.WriteLine("Handshake Done");
                    var reader = await pipe.Input.ReadAsync();
                    readData = Encoding.UTF8.GetString(reader.Buffer.ToArray());
                    var writer = pipe.Output.Alloc();
                    writer.Append(reader.Buffer);
                    await writer.FlushAsync();
                    wait.Set();
                });
                securePipeOptions.Start(ipAddress);

                var client = await secureListener.CreateClientConnection(await System.IO.Pipelines.Networking.Sockets.SocketConnection.ConnectAsync(ipAddress));


                //        wait.WaitOne();
                //        Assert.Equal("", readData);
            }
        }
    }
}
