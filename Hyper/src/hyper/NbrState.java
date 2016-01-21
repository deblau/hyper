package hyper;

import java.io.IOException;
import java.net.SocketAddress;
import java.nio.channels.SocketChannel;

/**
 * State variables associated with acting as potential new neighbor node. The {@link CubeProtocol} class includes a list
 * of these, one for each simultaneously connecting client.
 */
class NbrState
{
	// Coordinating ANN
	CubeAddress ann;

	// Socket to the connecting node
	SocketChannel chan;

	// Nonce to use when connecting
	Integer nonce;

	// Phase 3 state of the neighbor, used for protocol state validation
	CubeMessage.Type state = null;

	public NbrState(CubeAddress ann, SocketAddress addr, Integer nonce) throws IOException
	{
		this.ann = ann;
		chan = SocketChannel.open(addr);
		this.nonce = nonce;
	}
}
