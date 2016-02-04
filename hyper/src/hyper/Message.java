package hyper;

import java.io.Serializable;

/**
 * Structure for sending and receiving data in a Cube.
 *
 */
public class Message
{
	/**
	 * Address of another node in the Cube. This must be set to send a peer-to-peer message, and is automatically set
	 * when sending a broadcast message or receiving a message from another peer.
	 */
	public CubeAddress peer = CubeAddress.INVALID_ADDRESS;

	/**
	 * Payload data. This must be set to send a message, and is automatically set when receiving a message.
	 */
	public Serializable data = null;

	/**
	 * Default constructor.
	 * 
	 * @param peer
	 *            The {@link CubeAddress} of a peer to which payload data should be sent
	 * @param data
	 *            The payload data
	 */
	public Message(CubeAddress peer, Serializable data) {
		this.peer = peer;
		this.data = data;
	}

	@Override
	public String toString()
	{
		return "Peer: " + peer + ", data: " + data;
	}
}
