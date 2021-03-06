package hyper;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;

/**
 * A Cube protocol message.
 */
class CubeMessage implements Serializable
{
	/**
	 * 
	 */
	private static final long serialVersionUID = -2640817563881316595L;

	// Message types
	public enum Type {

		/**
		 * Messages exchanged during Phase 1: Determining possible attachment point
		 */

		// Message (outside the Cube) from CLT to INN, requesting a CubeAddress
		// Src: INVALID_ADDRESS
		// Dest: INVALID_ADDRESS
		// Data: CLT's TCP address
		CONN_EXT_INN_ATTACH,

		// Message from INN to other Cube nodes, asking recipients for ability and willingness to accept connection
		// Src: INN
		// Dest: BCAST_FORWARD
		// Data: CLT's TCP address
		CONN_INN_GEN_ANN,

		// Message from generic Cube node to INN, declaring nodes willing and able to accept connection
		// Src: BCAST_REVERSE
		// Dest: INN
		// Data: CLT's TCP address, bitmap of unwilling nodes
		CONN_GEN_INN_AVAIL,

		// Message from INN to selected address negotiation node (ANN), tentatively handing off negotiation
		// Src: INN
		// Dest: Node that responded CONN_GEN_INN_AVAIL
		// Data: CLT's TCP address
		CONN_INN_ANN_HANDOFF,

		/**
		 * Messages exchanged during Phase 2: Offering a CubeAddress to the client
		 */

		// Message (outside the Cube) from ANN to CLT, offering it a new CubeAddress
		// Src: INVALID_ADDRESS
		// Dest: offered CubeAddress
		// Data: the dimension of the Cube and the number of neighbors
		CONN_ANN_EXT_OFFER,

		// Message (outside the Cube) from CLT to ANN, accepting the offer
		// Src: accepted CubeAddress
		// Dest: INVALID_ADDRESS
		// Data: null
		CONN_EXT_ANN_ACCEPT,

		// Message (outside the Cube) from CLT to ANN, CLT is unwilling to connect through ANN; ANN must abort
		// Src: INVALID_ADDRESS
		// Dest: INVALID_ADDRESS
		// Data: null
		CONN_EXT_ANN_DECLINE,

		/**
		 * Messages exchanged during Phase 3: Neighbors all connect without revealing their CubeAddresses
		 */

		// Message from ANN to NBR, instructing NBR to connect to CLT
		// Src: ANN
		// Dest: NBR
		// Data: CLT's TCP address
		CONN_ANN_NBR_CONNECT,

		// Message (outside the Cube) from NBR to CLT, offering to connect
		// Src: INVALID_ADDRESS
		// Dest: INVALID_ADDRESS
		// Data: null
		CONN_NBR_EXT_OFFER,

		// Message (outside the Cube) from CLT to NBR, accepting the connection
		// Src: CLT
		// Dest: INVALID_ADDRESS
		// Data: null
		CONN_EXT_NBR_ACCEPT,

		// Message (outside the Cube) from CLT to NBR, declining the connection
		// Src: INVALID_ADDRESS
		// Dest: INVALID_ADDRESS
		// Data: null
		CONN_EXT_NBR_DECLINE,

		// Message from NBR to ANN, indicating connection established
		// Src: NBR
		// Dest: ANN
		// Data: CLT's TCP address
		CONN_NBR_ANN_CONNECTED,

		// Message from NBR to ANN, indicating failed connection
		// Src: NBR
		// Dest: ANN
		// Data: CLT's TCP address
		CONN_NBR_ANN_DISCONNECTED,

		/**
		 * Messages exchanged during Phase 4: CubeAddress advertisement
		 */

		// Message from ANN to NBR, instructing NBR to advertise its Cube address to CLT
		// Src: ANN
		// Dest: NBR
		// Data: CLT's TCP address
		CONN_ANN_NBR_IDENTIFY,

		// Message (outside the Cube) from NBR to CLT, identifying NBR's Cube address
		// Src: NBR
		// Dest: CLT
		// Data: null
		CONN_NBR_EXT_IDENTIFY,

		// Message from NBR to ANN, indicating that the client was informed and state is correct
		// Src: NBR
		// Dest: CLT
		// Data: null
		CONN_NBR_ANN_IDENTIFIED,

		// Message from ANN to CLT, declaring successful address negotiation
		// Src: ANN
		// Dest: CLT
		// Data: null
		CONN_ANN_EXT_SUCCESS,

		// Message from ANN to INN, declaring successful address negotiation
		// Src: ANN
		// Dest: INN
		// Data: CLT's TCP address
		CONN_ANN_INN_SUCCESS,

		// Message from INN to unable ANNs, declaring successful address negotiation
		// Src: INN
		// Dest: ANN
		// Data: CLT's TCP address
		CONN_INN_GEN_CLEANUP,

		/**
		 * Failure messages exchanged during multiple phases
		 */

		// Invalid message format (including source/destination address)
		// Src: varies
		// Dest: varies
		// Data: message type
		INVALID_MSG,

		// Invalid (i.e., unconnected) Cube address
		// Src: the invalid address
		// Dst: the node that sent the message to the invalid address
		// Data: the original data
		INVALID_ADDRESS,

		// Invalid protocol state
		// Src: varies
		// Dest: varies
		// Data: Type[] of current state, attempted transition state
		INVALID_STATE,

		// Invalid message data
		// Src: varies
		// Dest: varies
		// Data: varies
		INVALID_DATA,

		// Message (outside the Cube) from ingress negotiation node (INN) to client (CLT), rejecting a connection
		// Src: INVALID_ADDRESS
		// Dest: INVALID_ADDRESS
		// Data: null (could be extended to include a reason)
		CONN_INN_EXT_CONN_REFUSED,

		// Message from address negotiation node (ANN) to INN, declaring unsuccessful address negotiation
		// Src: ANN
		// Dest: INN
		// Data: CLT's TCP address
		CONN_ANN_INN_FAIL,

		// Message from ANN to new neighbor (NBR), declaring unsuccessful address negotiation
		// Src: ANN
		// Dest: NBR
		// Data: CLT's TCP address
		CONN_ANN_NBR_FAIL,

		// Message from ANN to CLT, declaring unsuccessful address negotiation
		// Src: INVALID_ADDRESS
		// Dest: INN
		// Data: CLT's TCP address
		CONN_ANN_EXT_FAIL,

		/**
		 * Messages exchanged post-connection
		 */

		// Message between Cube nodes, containing useful data
		// Data: arbitrary
		DATA_MSG,

		// Message from a Cube node, informing its neighbors that it's disconnecting
		// Data: (optional) String providing a reason
		NODE_SHUTDOWN,
	};

	// Source Cube address
	private CubeAddress src = CubeAddress.INVALID_ADDRESS;

	// Destination Cube address
	private CubeAddress dst = CubeAddress.INVALID_ADDRESS;

	// Path information used for route requests and broadcasts; see Katseff
	private BigInteger travel = new BigInteger("-1");

	// Hop count
	// private int hopcount;

	// Type of message
	private Type type = Type.INVALID_MSG;

	// Payload data
	private Serializable data = null;

	// The SocketChannel this Message came from, if any
	private SocketChannel channel = null;

	@Override
	public String toString()
	{
		return "CubeMessage (" + src + "=>" + dst + ") type " + type + ", data: " + data;
	}

	/*
	 * Non-broadcast message constructor
	 */
	CubeMessage(CubeAddress src, CubeAddress dst, Type type, Serializable data) {
		this.src = src;
		this.dst = dst;
		this.type = type;
		this.data = data;
	}

	/*
	 * Broadcast message constructor
	 */
	CubeMessage(CubeAddress src, CubeAddress dst, Type type, Serializable data, int dim) {
		this.src = src;
		this.dst = dst;
		this.type = type;
		this.data = data;
		this.travel = BigInteger.ZERO.setBit(dim).subtract(BigInteger.ONE);
	}

	/**
	 * Send this message on a {@link SocketChannel}. Should be called only by the {@link CubeProtocol}.
	 * 
	 * @param chan
	 *            The {@link SocketChannel}
	 * @return Whether the message was sent
	 */
	boolean send(SocketChannel chan)
	{
		/*
		 * This is a non-blocking send; the receive on the other end is still blocking. Note that the channel is not
		 * serializeable, so we have to save it temporarily.
		 */
		try
		{
			// First, write ourselves onto a ByteArrayOutputStream (except for our channel, which is purely local)
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			SocketChannel ch = channel;
			channel = null;
			new ObjectOutputStream(baos).writeObject(this);
			channel = ch;

			// Next, determine our size, and write ourselves into a sized ByteBuffer
			int size = baos.toByteArray().length;
			ByteBuffer buf = ByteBuffer.allocate(size + 4);
			buf.putInt(size);
			buf.put(baos.toByteArray());

			// Finally, write the ByteBuffer to the indicated channel
			buf.rewind();
			while (buf.hasRemaining())
				chan.write(buf);
			return true;
		} catch (IOException e)
		{
			return false;
		}
	}

	/**
	 * Receive a message from a {@link SocketChannel}. Should be called only by the {@link MessageListener}. This passes
	 * along any IOExceptions for processing by the <code>MessageListener</code>, which has programmatic access to the
	 * corresponding {@link CubeProtocol}.
	 * 
	 * @param chan
	 *            The {@link SocketChannel}
	 * @return a received {@link CubeMessage}, or <code>null</code> if unsuccessful
	 * @throws IOException
	 */
	static CubeMessage recv(SocketChannel chan) throws IOException
	{
		// First, determine the size of the CubeMessage object
		ByteBuffer buf = ByteBuffer.allocate(4);
		chan.read(buf);
		buf.rewind();
		int size = buf.getInt();

		// Then, allocate a ByteBuffer and read the CubeMessage
		buf = ByteBuffer.allocate(size);
		while (buf.hasRemaining())
			chan.read(buf);

		// Finally, populate the message
		try
		{
			CubeMessage msg = (CubeMessage) new ObjectInputStream(new ByteArrayInputStream(buf.array())).readObject();
			msg.channel = chan;
			return msg;
		} catch (ClassNotFoundException e)
		{
			return null;
		}
	}

	public CubeAddress getSrc()
	{
		return src;
	}

	public CubeAddress getDst()
	{
		return dst;
	}

	// Called by CubeProtocol to implement broadcast
	BigInteger getTravel()
	{
		return travel;
	}

	// Called by CubeProtocol to implement broadcast
	void setTravel(BigInteger travel)
	{
		this.travel = travel;
	}

	public Type getType()
	{
		return type;
	}

	public Serializable getData()
	{
		return data;
	}

	SocketChannel getChannel()
	{
		return channel;
	}
}