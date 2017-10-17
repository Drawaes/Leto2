using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Text;
using System.Threading.Tasks;
using Leto.ConnectionStates;
using Leto.RecordLayer;

namespace Leto
{
    public class SecurePipeClientConnection : SecurePipeConnection
    {
        internal SecurePipeClientConnection(IPipeConnection connection, SecurePipeOptions securePipeOptions)
            :base(connection, securePipeOptions, new Client12ConnectionState())
        {
            
        }
    }
}
