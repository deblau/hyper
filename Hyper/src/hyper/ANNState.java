package hyper;

import java.net.InetSocketAddress;

/**
 * State variables associated with acting as ANN. The {@link CubeProtocol} class includes a list of these, one for each
 * simultaneously connecting client.
 */
class ANNState
{
	// Initiating INN
	CubeAddress inn;

	// Connecting client address
	InetSocketAddress clientAddr;

	// Nonce to use with this client
	double nonce;

	public ANNState(CubeAddress inn, InetSocketAddress clientAddr)
	{
		this.inn = inn;
		this.clientAddr = clientAddr;
		nonce = Math.random();
	}
}