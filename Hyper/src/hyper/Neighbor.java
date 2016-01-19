package hyper;

import java.nio.channels.SocketChannel;

/**
 * State variables associated with my connection to each of my Cube neighbors.
 */
class Neighbor
{
	// The neighbor's CubeAddress
	CubeAddress addr;

	// The neighbor's SocketChannel
	SocketChannel chan;

	public Neighbor(CubeAddress addr, SocketChannel chan)
	{
		this.addr = addr;
		this.chan = chan;
	}
}
