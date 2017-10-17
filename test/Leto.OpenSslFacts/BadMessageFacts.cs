using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace Leto.OpenSslFacts
{
    public class BadMessageFacts
    {
        [Fact]
        public async Task ClientHelloWithExtraBytes()
        {
            using (var securePipeOptions = new OpenSsl11.OpenSslSecurePipeListener(Data.Certificates.RSACertificate))
            {
                await CommonFacts.BadHelloFacts.SendHelloWithExtraTrailingBytes(securePipeOptions);
            }
        }

        [Fact]
        public async Task WrongInitialHandshakeMessage()
        {
            using (var securePipeOptions = new OpenSsl11.OpenSslSecurePipeListener(Data.Certificates.RSACertificate))
            {
                await CommonFacts.BadHelloFacts.WrongInitialHandshakeMessage(securePipeOptions);
            }
        }

        [Fact]
        public async Task InvalidVectorSizeForExtensions()
        {
            using (var securePipeOptions = new OpenSsl11.OpenSslSecurePipeListener(Data.Certificates.RSACertificate))
            {
                await CommonFacts.BadHelloFacts.InvalidVectorSizeForExtensions(securePipeOptions);
            }
        }

        [Fact]
        public async Task StartWithApplicationRecord()
        {
            using (var securePipeOptions = new OpenSsl11.OpenSslSecurePipeListener(Data.Certificates.RSACertificate))
            {
                await CommonFacts.BadHelloFacts.StartWithApplicationRecord(securePipeOptions);
            }
        }

        [Fact]
        public async Task UnknownAlpn()
        {
            using (var securePipeOptions = new OpenSsl11.OpenSslSecurePipeListener(Data.Certificates.RSACertificate))
            {
                await CommonFacts.BadHelloFacts.UnknownALPN(securePipeOptions);
            }
        }
    }
}
