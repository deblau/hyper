package hyper;

import java.nio.channels.SocketChannel;
import java.util.ArrayList;

/**
 * State variables associated with connecting to a node. The {@link CubeProtocol} class includes one of these to use
 * when it connects to a Cube.
 */
class CltState extends State
{
	// SocketChannel connected to INN
	SocketChannel innChan;
	
	// Nonces to use when connecting
	public ArrayList<Integer> nonces;

	@Override
	public String toString()
	{
		return "State: " + state + "\nNonces: " + nonces;
	}
}
