package hyper;

import java.nio.channels.SocketChannel;
import java.util.ArrayList;

/**
 * State variables associated with acting as INN. The {@link CubeProtocol} class includes a list of these, one for each
 * simultaneously connecting client.
 */
class INNState extends State
{
	// Socket channel for connecting client
	SocketChannel chan;

	// List of able and willing nodes
	ArrayList<CubeAddress> acked = new ArrayList<>();

	// List of unable nodes
	ArrayList<CubeAddress> unable = new ArrayList<>();

	// List of unwilling nodes
	ArrayList<CubeAddress> unwilling = new ArrayList<>();

	// Phase 1 hop count of the INN
	int hops = 1;

	INNState(SocketChannel chan)
	{
		this.chan = chan;
	}

	@Override
	public String toString()
	{
		return "State: " + state + "\nAcked/Unable/Unwilling: " + acked.toString() + ", " + unable.toString() + ", "
				+ unwilling.toString();
	}
}