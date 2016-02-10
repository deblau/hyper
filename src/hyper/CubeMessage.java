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
	private BigInteger travel = new BigInteger("-1");

	// Type of message
	private CubeMessageType type = CubeMessageType.INVALID_MSG;

	// Encrypted InetSocketAddress of connecting peer -- used during the connection process
	private InetSocketAddress encryptedPeerAddr = null;

	// Payload data
	private Serializable data = null;

	// The SocketChannel this Message came from, if any
	private SocketChannel channel = null;

	@Override
	public String toString() {
		return "CubeMessage (" + src + "=>" + dst + ") type " + type + " for peer " + encryptedPeerAddr
				+ ", with data: " + data;
	}

	/*
	 * Non-broadcast message constructor
	 */
	CubeMessage(CubeAddress src, CubeAddress dst, CubeMessageType type, Serializable data) {
		this.src = src;
		this.dst = dst;
		this.type = type;
		this.data = data;
	}

	/*
	 * Broadcast message constructor
	 */
	CubeMessage(CubeAddress src, CubeAddress dst, CubeMessageType type, Serializable data, int dim) {
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
	boolean send(SocketChannel chan) {
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
	static CubeMessage recv(SocketChannel chan) throws IOException {
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

	CubeAddress getSrc() {
		return src;
	}

	CubeAddress getDst() {
		return dst;
	}

	BigInteger getTravel() {
		return travel;
	}

	void setTravel(BigInteger travel) {
		this.travel = travel;
	}

	CubeMessageType getType() {
		return type;
	}

	InetSocketAddress getEncryptedPeerAddr() {
		return encryptedPeerAddr;
	}

	void setEncryptedPeerAddr(InetSocketAddress encryptedPeerAddr) {
		this.encryptedPeerAddr = encryptedPeerAddr;
	}

	Serializable getData() {
		return data;
	}

	SocketChannel getChannel() {
		return channel;
	}
}