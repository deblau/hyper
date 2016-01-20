package hyper;

import java.io.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
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

		// Invalid message
		INVALID_MSG,

		// Invalid state
		// Src: varies
		// Dest: varies
		// Data: [current state, attempted transition state]
		INVALID_STATE,

		// Invalid data
		// Src: varies
		// Dest: varies
		// Data: varies
		INVALID_DATA,

		// Message (outside the Cube) from external client to ingress negotiation node (INN), requesting a CubeAddress
		// Src: NO_ADDRESS
		// Dest: NO_ADDRESS
		// Data: InetSocketAddress of client's MessageListener
		CONN_EXT_INN_REQ,

		// Message from INN to other Cube nodes, asking recipients for ability and willingness to accept connection
		// Src: INN
		// Dest: Connected node
		// Data: InetSocketAddress of client's MessageListener
		CONN_INN_REQ_ANN,

		// Message from Cube node to INN, declaring ability and willingness to accept connection
		// Src: Connected node
		// Dest: INN
		// Data: InetSocketAddress of client's MessageListener
		CONN_NODE_INN_ACK,

		// Message from Cube node to INN, declaring inability to accept a connection
		// Src: Connected node
		// Dest: INN
		// Data: InetSocketAddress of client's MessageListener
		CONN_NODE_INN_UNABLE,

		// Message from Cube node to INN, declaring unwillingness to accept a connection
		// Src: Connected Node
		// Dest: INN
		// Data: InetSocketAddress of client's MessageListener
		CONN_NODE_INN_UNWILLING,

		// Message from INN to selected address negotiation node (ANN), tentatively handing off negotiation
		// Src: INN
		// Dest: Connected node
		// Data: InetSocketAddress of client's MessageListener
		CONN_INN_ANN_HANDOFF,

		// Message from ANN to INN, declaring successful address negotiation
		// Src: (New) ANN
		// Dest: INN
		// Data: InetSocketAddress of client's MessageListener
		CONN_ANN_INN_SUCC,

		// Message from ANN to INN, declaring unsuccessful address negotiation due to inability
		// Src: ANN
		// Dest: INN
		// Data: InetSocketAddress of client's MessageListener
		CONN_ANN_INN_UNABLE,

		// Message from ANN to INN, declaring unsuccessful address negotiation due to unwillingness
		// Src: ANN
		// Dest: INN
		// Data: InetSocketAddress of client's MessageListener
		CONN_ANN_INN_UNWILLING,

		// Message from INN to ANN, instructing attachment using a higher Cube dimension
		// Src: INN
		// Dest: ANN
		// Data: InetSocketAddress of client's MessageListener
		CONN_INN_ANN_EXPAND,

		// Message (outside the Cube) from INN to client, rejecting the connection
		// Src: NO_ADDRESS
		// Dest: NO_ADDRESS
		// Data: null (could be extended to include a reason)
		CONN_INN_EXT_CONN_REFUSED,

		// Message from ANN to new neighbor, asking for willingness to accept connection
		// Src: ANN
		// Dest: Connected node two hops from ANN (first hop is the tentative connection point)
		// Data: InetSocketAddress of client's MessageListener
		CONN_ANN_NEI_REQ,

		// Message from new neighbor to ANN, declaring willingness to accept connection
		// Src: Connected node two hops from ANN
		// Dest: ANN
		// Data: InetSocketAddress of client's MessageListener and a nonce generated by the neighbor
		CONN_NEI_ANN_ACK,

		// Message from new neighbor to ANN, declaring unwillingness to accept connection
		// Src: Connected node two hops from ANN
		// Dest: ANN
		// Data: InetSocketAddress of client's MessageListener
		CONN_NEI_ANN_NAK,

		// Message (outside the Cube) from ANN to external client, offering it a new CubeAddress
		// Src: NO_ADDRESS
		// Dest: offered CubeAddress
		// Data: nonces generated by the new neighbors
		CONN_ANN_EXT_OFFER,

		// Message (outside the Cube) from external client to ANN, acknowledging (and accepting) the offer
		// Src: accepted CubeAddress
		// Dest: NO_ADDRESS
		// Data: null
		CONN_EXT_ANN_ACK,

		// Message (outside the Cube) from external client to ANN, declining the offer
		// Src: NO_ADDRESS
		// Dest: NO_ADDRESS
		// Data: null
		CONN_EXT_ANN_NAK,

		// Message from ANN to new neighbor, declaring negotiation a success
		// Src: ANN
		// Dest: Connected node two hops from ANN
		// Data: InetSocketAddress of client's MessageListener
		CONN_ANN_NEI_SUCC,

		// Message from ANN to new neighbor, declaring negotiation a failure
		// Src: ANN
		// Dest: Connected node two hops from ANN
		// Data: InetSocketAddress of client's MessageListener
		CONN_ANN_NEI_FAIL,

		// Message (outside the Cube) from new neighbor to external client, offering to connect
		// Src: NO_ADDRESS
		// Dest: client's CubeAddress
		// Data: null
		CONN_NEI_EXT_OFFER,

		// Message (outside the Cube) from external client to new neighbor, accepting the connection
		// Src: client's CubeAddress
		// Dest: NO_ADDRESS
		// Data: all of the nonces
		CONN_EXT_NEI_ACK,

		// Message (outside the Cube) from external client to new neighbor, declining the connection
		// Src: client's CubeAddress
		// Dest: NO_ADDRESS
		// Data: null
		CONN_EXT_NEI_NAK,

		// Message from new neighbor to ANN, indicating successful connection
		// Src: Connected node two hops from ANN
		// Dest: ANN
		// Data: InetSocketAddress of client's MessageListener
		CONN_NEI_ANN_SUCC,

		// Message from new neighbor to ANN, indicating failed connection
		// Src: Connected node two hops from ANN
		// Dest: ANN
		// Data: InetSocketAddress of client's MessageListener
		CONN_NEI_ANN_FAIL,

		// Message from ANN to new neighbors, indicating that advertising node addresses is okay
		// Src: ANN
		// Dest: Connected node two hops from ANN
		// Data: InetSocketAddress of client's MessageListener
		CONN_ANN_NEI_ADV,

		// Message from ANN to new neighbors, indicating that advertising node addresses is NOT okay
		// Src: ANN
		// Dest: Connected node two hops from ANN
		// Data: InetSocketAddress of client's MessageListener
		CONN_ANN_NEI_NADV,

		// Message (outside the Cube) from new neighbor to external client, completing the handshake
		// Src: neighbor's CubeAddress
		// Dest: client's CubeAddress
		// Data: null
		CONN_NEI_EXT_ACK,

		// Message (outside the Cube) from ANN to client, confirming the connection and shutting down the link
		// Src: ANN
		// Dest: client's CubeAddress
		// Data: dimension of the cube
		CONN_ANN_EXT_CONN_SUCC,

		// Message (outside the Cube) from ANN to client, denying the connection and shutting down the link
		// Src: INN
		// Dest: client's CubeAddress
		// Data: dimension of the cube
		CONN_ANN_EXT_CONN_FAIL,

		// Message requesting a route to a destination
		// Data: none (destination is stored in msg.dst)
		ROUTE_REQ,

		// Message stating the that destination is reachable
		// Data: destination
		ROUTE_RESP_RCHBL,

		// Message stating that the destination is unreachable
		// Data: destination
		ROUTE_RESP_UNRCH,

		// Message between Cube nodes, containing useful data
		// Data: arbitrary
		DATA_MSG,
	};

	// Source Cube address
	private CubeAddress src = CubeAddress.INVALID_ADDRESS;

	// Destination Cube address
	private CubeAddress dst = CubeAddress.INVALID_ADDRESS;

	// Path information used for route requests and broadcasts; see Katseff
	private BigInteger travel;

	// Type of message
	private Type type = Type.INVALID_MSG;

	// Payload data
	private Object data = null;

	// The SocketChannel this Message came from, if any
	private SocketChannel channel = null;

	@Override
	public String toString()
	{
		return "CubeMessage (" + src + "=>" + dst + ") type " + type + ", data: " + data;
	}

	/*
	 * For sending regular messages when the source and destination already have Cube addresses
	 */
	public CubeMessage(CubeAddress src, CubeAddress dst, Type type, Object data) {
		this.src = src;
		this.dst = dst;
		this.type = type;
		this.data = data;
	}

	/**
	 * Send this message on a {@link SocketChannel}. Should be called only by the {@link CubeProtocol}.
	 * 
	 * @param chan
	 *            The {@link SocketChannel}
	 * @throws IOException
	 */
	void send(SocketChannel chan) throws IOException
	{
		// This is a non-blocking send; the receive on the other end is still blocking
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		new ObjectOutputStream(baos).writeObject(this);
		ByteBuffer buf = ByteBuffer.wrap(baos.toByteArray());
		chan.write(buf);
	}

	/**
	 * Receive a message from a {@link SocketChannel}. Should be called only by the {@link MessageListener}.
	 * 
	 * @param chan
	 *            The {@link SocketChannel}
	 * @return the new {@link CubeMessage}
	 * @throws IOException
	 */
	static CubeMessage recv(SocketChannel chan)
	{
		try
		{
			CubeMessage msg = (CubeMessage) new ObjectInputStream(Channels.newInputStream(chan)).readObject();
			msg.channel = chan;
			return msg;
		} catch (ClassNotFoundException e)
		{
			e.printStackTrace();
			return null;
		} catch (IOException e)
		{
			System.err.println(Thread.currentThread() + " got IOException " + chan);
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

	// Called by CubeProtocol to implement Phase 1 using custom hop count
	void setDst(CubeAddress dst)
	{
		this.dst = dst;
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

	// Called by CubeProtocol to implement broadcast
	void reduceHops()
	{
		// dst is null when a user calls broadcast(); it's not null when we're being tricky under the hood
		if (null != dst)
			dst = (CubeAddress) dst.add(BigInteger.ONE);
	}

	public Type getType()
	{
		return type;
	}

	public Object getData()
	{
		return data;
	}

	SocketChannel getChannel()
	{
		return channel;
	}
}