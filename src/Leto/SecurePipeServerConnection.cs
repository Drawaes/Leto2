using Leto.ConnectionStates;
using Leto.RecordLayer;
using System.IO.Pipelines;
using System.Threading.Tasks;

namespace Leto
{
    public class SecurePipeServerConnection : SecurePipeConnection
    {
        internal SecurePipeServerConnection(IPipeConnection connection, SecurePipeOptions securePipeOptions)
            :base(connection, securePipeOptions, new Server12ConnectionState())
        {
            
        }
    }
}
