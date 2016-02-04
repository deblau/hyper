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
		// Data: EXT's TCP address
		CONN_EXT_INN_ATTACH,

		// Message from INN to other Cube nodes, asking recipients for ability and willingness to accept connection
		// Src: INN
		// Dest: BCAST_FORWARD
		// Data: null
		CONN_INN_GEN_ANN,

		// Message from generic Cube node to INN, declaring existence
		// Src: BCAST_REVERSE
		// Dest: INN
		// Data: null
		CONN_GEN_INN_AVAIL,

		// Message from INN to ANN, requesting cryptography
		// Src: INN
		// Dest: ANN
		// Data: An INN cryptographic token
		CONN_INN_ANN_ENCRYPT,

		// Message from ANN to INN, confirming cryptography
		// Src: ANN
		// Dest: INN
		// Data: The INN token and an ANN token
		CONN_ANN_INN_ENCRYPT,

		// Message from INN to ANN, tentatively handing off negotiation
		// Src: INN
		// Dest: ANN
		// Data: EXT's TCP address, encrypted using the two tokens
		CONN_INN_ANN_HANDOFF,
		
		/**
		 * Messages exchanged during Phase 2: Determining the CubeAddress
		 */

		// Message from ANN to NBR, requesting cryptography
		// Src: ANN
		// Dest: NBR
		// Data: An ANN cryptographic token
		CONN_ANN_NBR_ENCRYPT,

		// Message from NBR to ANN, confirming cryptography
		// Src: NBR
		// Dest: ANN
		// Data: The ANN token and a NBR token
		CONN_NBR_ANN_ENCRYPT,

		// Message from ANN to NBR, requesting willingness to connect
		// Src: INN
		// Dest: ANN
		// Data: EXT's TCP address, encrypted using the two tokens
		CONN_ANN_NBR_WILLING,
		
		// Message from INN to selected address negotiation node (ANN), tentatively handing off negotiation
		// Src: INN
		// Dest: ANN
		// Data: EXT's TCP address, encrypted using the two tokens and true/false
		CONN_NBR_ANN_WILLING,
		
		/**
		 * Messages exchanged during Phase 3: Establishing IP connections
		 */

		// Message (outside the Cube) from ANN to EXT, offering it a new CubeAddress
		// Src: INVALID_ADDRESS
		// Dest: offered CubeAddress
		// Data: the dimension of the Cube and a nonce
		CONN_ANN_EXT_OFFER,

		// Message (outside the Cube) from EXT to ANN, accepting or declining the offer
		// Src: EXT if accepted; INVALID_ADDRESS if declined
		// Dest: INVALID_ADDRESS
		// Data: the nonce
		CONN_EXT_ANN_REPLY,

		// Message from ANN to NBR, instructing IP connection to EXT
		// Src: ANN
		// Dest: NBR
		// Data: EXT's TCP address encrypted using the two tokens, and the nonce
		CONN_ANN_NBR_CONNECT,

		// Message (outside the Cube) from NBR to EXT, offering IP connection
		// Src: INVALID_ADDRESS
		// Dest: INVALID_ADDRESS
		// Data: null
		CONN_NBR_EXT_OFFER,

		// Message (outside the Cube) from EXT to NBR, accepting or declining the offer
		// Src: EXT if accepted; INVALID_ADDRESS if declined
		// Dest: INVALID_ADDRESS
		// Data: the nonce
		CONN_EXT_NBR_REPLY,

		// Message from NBR to ANN, notifying ANN of failed connection; ANN must bail
		// Src: NBR
		// Dest: ANN
		// Data: EXT's TCP address, encrypted using the two tokens
		CONN_NBR_ANN_DECLINED,

		/**
		 * Messages exchanged during Phase 4: CubeAddress advertisement
		 */

		// Message from NBR to ANN, notifying ANN of an accepted, validated connection
		// Src: NBR
		// Dest: ANN
		// Data: EXT's TCP address, encrypted using the two tokens
		CONN_NBR_ANN_CONNECTED,

		// Message from ANN to NBR, instructing NBR to advertise its Cube address to EXT
		// Src: ANN
		// Dest: NBR
		// Data: the nonce
		CONN_ANN_NBR_IDENTIFY,

		// Message (outside the Cube) from NBR to EXT, identifying NBR's Cube address
		// Src: NBR
		// Dest: CLT
		// Data: null
		CONN_NBR_EXT_IDENTIFY,

		// Message from ANN to INN, declaring successful address negotiation
		// Src: ANN
		// Dest: INN
		// Data: The INN cryptographic token
		CONN_ANN_INN_SUCCESS,

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

		// Message (outside the Cube) from INN to EXT, rejecting a connection
		// Src: INVALID_ADDRESS
		// Dest: INVALID_ADDRESS
		// Data: null (could be extended to include a reason)
		CONN_INN_EXT_CONN_REFUSED,

		// Message from ANN to INN, declaring unsuccessful address negotiation
		// Src: ANN
		// Dest: INN
		// Data: EXT's TCP address, encrypted using the INN/ANN tokens
		CONN_ANN_INN_FAIL,

		// Message from ANN to NBR, declaring unsuccessful address negotiation
		// Src: ANN
		// Dest: NBR
		// Data: EXT's TCP address, encrypted using the ANN/NBR tokens
		CONN_ANN_NBR_FAIL,

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