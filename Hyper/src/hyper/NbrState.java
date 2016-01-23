package hyper;

import java.net.SocketAddress;
import java.nio.channels.SocketChannel;

/**
 * State variables associated with acting as potential new neighbor node. The {@link CubeProtocol} class includes a list
 * of these, one for each simultaneously connecting client.
 */
class NbrState extends State
{
	// Coordinating ANN
	CubeAddress ann;

	// Address of client
	SocketAddress addr;
	
	// Connection to client
	SocketChannel chan = null;

	// Nonce to use when connecting
	Integer nonce = (int) (Math.random() * Integer.MAX_VALUE);

	public NbrState(CubeAddress ann, SocketAddress addr)
	{
		this.ann = ann;
		this.addr = addr;
	}

	@Override
	public String toString()
	{
		return "State: " + state + "\nANN: " + ann + "\nClient/Nonde: " + addr + ", " + nonce;
	}
}
