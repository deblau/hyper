package hyper;

import java.net.InetSocketAddress;

/**
 * State variables associated with acting as INN. The {@link CubeProtocol} class includes a list of these, one for each
 * simultaneously connecting client.
 */
class INNState
{
	// Connecting client address
	InetSocketAddress clientAddr;
	
	public INNState(InetSocketAddress clientAddr)
	{
		this.clientAddr = clientAddr;
	}
}