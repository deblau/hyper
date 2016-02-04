package hyper;

import java.nio.channels.SocketChannel;

/**
 * State variables associated with connecting to a node. The {@link CubeProtocol} class includes one of these to use
 * when it connects to a Cube.
 */
class CltState extends State
{
	// SocketChannel connected to INN
	SocketChannel innChan;
	
	// SocketChannel connected to ANN
	SocketChannel annChan;
	
	// The nonce to communicate to connecting neighbors
	int nonce;
	
	@Override
	public String toString()
	{
		return "State: " + state;
	}
}
