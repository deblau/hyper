package hyper;

import java.nio.channels.SocketChannel;
import java.util.ArrayList;

/**
 * State variables associated with connecting to a node. The {@link CubeProtocol} class includes one of these to use
 * when it connects to a Cube.
 */
class CltState extends State
{
	// Socket connected to INN
	SocketChannel innChan;

	// Socket connected to ANN
	SocketChannel annChan;

	// Sockets connected from potential neighbors
	ArrayList<SocketChannel> nbrChans = new ArrayList<>();

	// Nonces to use when connecting
	public ArrayList<Integer> nonces;

	@Override
	public String toString()
	{
		return "State: " + state + "\nNeighbors: " + nbrChans.toString() + "\nNonces: " + nonces;
	}
}
