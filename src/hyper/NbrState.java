package hyper;

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
	CubeAddress addr = null;

	// Connection to client
	SocketChannel chan = null;

	public NbrState(CubeAddress ann) {
		this.ann = ann;
	}

	@Override
	public String toString()
	{
		return "State: " + state + "\nANN: " + ann + "\nClient: " + addr;
	}
}
