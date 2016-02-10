package hyper;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.net.InetSocketAddress;
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

	// Source Cube address
	private CubeAddress src = CubeAddress.INVALID_ADDRESS;

	// Destination Cube address
	private CubeAddress dst = CubeAddress.INVALID_ADDRESS;

	// Path information used for route requests and broadcasts; see Katseff
	private BigInteger travel = CubeAddress.INVALID_ADDRESS;

	// Type of message
	private CubeMessageType type = CubeMessageType.INVALID_FORMAT;

	// Encrypted InetSocketAddress of connecting peer -- used during the connection process
	private InetSocketAddress peer = null;

	// Payload data
	private Serializable data = null;

	// The SocketChannel this Message came from, if any
	private SocketChannel channel = null;

	@Override
	public String toString()
	{
		return "CubeMessage (" + src + "=>" + dst + ") type " + type + " for peer " + peer + ", with data: " + data;
	}

	/*
	 * Non-broadcast message constructor
	 */
	CubeMessage(CubeAddress src, CubeAddress dst, CubeMessageType type, InetSocketAddress addr, Serializable data) {
		this.src = src;
		this.dst = dst;
		this.type = type;
		this.peer = addr;
		this.data = data;
	}

	/*
	 * Broadcast message constructor, used only for intra-Cube communications
	 */
	CubeMessage(CubeAddress src, CubeAddress dst, CubeMessageType type, InetSocketAddress addr, Serializable data,
			int dim) {
		this.src = src;
		this.dst = dst;
		this.type = type;
		this.peer = addr;
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
		try {
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
		} catch (IOException e) {
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
		try {
			CubeMessage msg = (CubeMessage) new ObjectInputStream(new ByteArrayInputStream(buf.array())).readObject();
			msg.channel = chan;
			return msg;
		} catch (ClassNotFoundException e) {
			return null;
		}
	}

	/**
	 * Determine whether this (received) message is properly formatted according to its {@link CubeMessageType}. Called
	 * by {@link CubeProtocol#process(CubeMessage)}.
	 * 
	 * @return Whether the message is properly formatted.
	 */
	boolean hasProperFormat()
	{
		CubeAddress none = CubeAddress.INVALID_ADDRESS;
		CubeAddress bprc = CubeAddress.BCAST_PROCESS;
		CubeAddress brvs = CubeAddress.BCAST_REVERSE;
		switch (type) {
		case CONN_ANN_EXT_OFFER:
			// Fix data when re-implementing Phase 2
			return none.equals(src) && null != dst && dst.isUnicast() && none.equals(travel) && null == peer
					&& null != data && data instanceof Integer;
		case CONN_ANN_EXT_FAIL:
		case CONN_ANN_EXT_SUCCESS:
		case CONN_NBR_EXT_IDENTIFY:
			return null != src && src.isUnicast() && null != dst && dst.isUnicast() && none.equals(travel)
					&& null == peer && null == data;
		case CONN_ANN_INN_FAIL:
		case CONN_ANN_INN_SUCCESS:
		case CONN_ANN_NBR_CONNECT:
		case CONN_ANN_NBR_FAIL:
		case CONN_ANN_NBR_IDENTIFY:
		case CONN_INN_ANN_HANDOFF: // No INN authorization for now
		case CONN_NBR_ANN_CONNECTED:
		case CONN_NBR_ANN_DISCONNECTED:
		case CONN_NBR_ANN_IDENTIFIED:
			// Fix when peer is actually encrypted
			return null != src && src.isUnicast() && null != dst && dst.isUnicast() && none.equals(travel)
					&& null != peer && null == data;
		case CONN_EXT_ANN_ACCEPT:
		case CONN_EXT_NBR_ACCEPT:
			return null != src && src.isUnicast() && none.equals(dst) && none.equals(travel) && null == peer
					&& null == data;
		case CONN_EXT_ANN_DECLINE:
		case CONN_EXT_NBR_DECLINE:
		case CONN_INN_EXT_CONN_REFUSED:
		case CONN_NBR_EXT_OFFER:
			return none.equals(src) && none.equals(dst) && none.equals(travel) && null == peer && null == data;
		case CONN_EXT_INN_ATTACH:
			return none.equals(src) && none.equals(dst) && none.equals(travel) && null != peer && null == data;
		case CONN_GEN_INN_AVAIL:
			// No INN authorization; fix data when topological ANN selection is implemented; fix peer when encrypted
			return brvs.equals(src) && null != dst && dst.isUnicast() && none.equals(travel) && null != peer
					&& null != data && data instanceof BigInteger[];
		case CONN_INN_GEN_ANN:
		case CONN_INN_GEN_CLEANUP:
			// No INN authorization; fix peer when encrypted; remove CLEANUP entirely when broadcast implemented
			return null != src && src.isUnicast() && bprc.equals(dst) && !none.equals(travel) && null != peer
					&& null == data;
		case INVALID_ADDRESS: // FIXME
		case INVALID_DATA: // FIXME
		case INVALID_FORMAT: // FIXME
		case INVALID_STATE: // FIXME
		case NODE_SHUTDOWN:
			return true;
		case UNICAST_MSG:
			return null != src && src.isUnicast() && null != dst && dst.isUnicast() && none.equals(travel)
					&& null == peer;
		case BROADCAST_MSG:
			return null != src && src.isUnicast() && null != dst && dst.isBcast() && !none.equals(travel)
					&& null == peer;
		case REVERSE_BROADCAST_MSG:
			return null != src && src.isBcast() && null != dst && dst.isUnicast() && none.equals(travel)
					&& null == peer;
		default:
			return false;
		}
	}

	/**
	 * Obtain the {@link InetSocketAddress} of the peer to whom this connection message pertains. This is called by
	 * {@link CubeProtocol#process(CubeMessage)} after the message format has been validated.
	 * 
	 * @param state
	 *            The current {@link CubeState}
	 * @param msg
	 *            The {@link CubeMessage} to be processed
	 * @return The current {@link CxnState} with respect to this connection
	 */
	InetSocketAddress getPeer()
	{
		switch (type) {
		// Cases where I am the peer
		case CONN_ANN_EXT_FAIL:
		case CONN_ANN_EXT_OFFER:
		case CONN_ANN_EXT_SUCCESS:
		case CONN_INN_EXT_CONN_REFUSED:
		case CONN_NBR_EXT_IDENTIFY:
		case CONN_NBR_EXT_OFFER:
			return Utilities.quietLocal(channel);

		// Cases where the peer sent me this message
		case CONN_EXT_ANN_ACCEPT:
		case CONN_EXT_ANN_DECLINE:
		case CONN_EXT_NBR_ACCEPT:
		case CONN_EXT_NBR_DECLINE:
			return Utilities.quietRemote(channel);

		// All other cases pertaining to connections -- fix return value once encryption is implemented
		case CONN_ANN_INN_FAIL:
		case CONN_ANN_INN_SUCCESS:
		case CONN_ANN_NBR_CONNECT:
		case CONN_ANN_NBR_FAIL:
		case CONN_ANN_NBR_IDENTIFY:
		case CONN_EXT_INN_ATTACH: // Special case processing
		case CONN_GEN_INN_AVAIL:
		case CONN_INN_ANN_HANDOFF:
		case CONN_INN_GEN_ANN:
		case CONN_INN_GEN_CLEANUP:
		case CONN_NBR_ANN_CONNECTED:
		case CONN_NBR_ANN_DISCONNECTED:
		case CONN_NBR_ANN_IDENTIFIED:
		case INVALID_ADDRESS:
		case INVALID_DATA:
		case INVALID_FORMAT:
		case INVALID_STATE:
			return peer;

		// All other cases should have a null peer
		default:
			return null;
		}
	}

	/**
	 * Reply to this message's sender that its format is invalid.
	 */
	void replyInvalid(CubeMessageType type)
	{
		// We don't need to save any fields, since we're improperly formatted anyway
		CubeAddress tmp = src;
		src = dst;
		dst = tmp;
		this.type = type;
		send(channel);
	}

	/**
	 * Reply to this message's sender that its state machine has an improper state.
	 */
	void replyState()
	{

	}

	CubeAddress getSrc()
	{
		return src;
	}

	CubeAddress getDst()
	{
		return dst;
	}

	BigInteger getTravel()
	{
		return travel;
	}

	void setTravel(BigInteger travel)
	{
		this.travel = travel;
	}

	CubeMessageType getType()
	{
		return type;
	}

	Serializable getData()
	{
		return data;
	}

	SocketChannel getChannel()
	{
		return channel;
	}
}