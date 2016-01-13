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

	// The nonce to use when connecting
	Double nonce;

	/**
	 * @param addr
	 * @param chan
	 * @param nonce
	 */
	public Neighbor(CubeAddress addr, SocketChannel chan, Double nonce)
	{
		super();
		this.addr = addr;
		this.chan = chan;
		this.nonce = nonce;
	}
}
