package hyper;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class SocksServer {
	// Version constants
	final byte SOCKS_VERSION = 0x5;

	// Connect request constants
	final byte SOCKS_AUTH_NONE = (byte) 0x0;
	final byte SOCKS_AUTH_GSSAPI = (byte) 0x1;
	final byte SOCKS_AUTH_USERPASS = (byte) 0x2;
	final byte SOCKS_AUTH_CHAP = (byte) 0x3;
	/* 0x4 is unassigned */
	final byte SOCKS_AUTH_CRAM = (byte) 0x5;
	final byte SOCKS_AUTH_SSL = (byte) 0x6;
	final byte SOCKS_AUTH_NDS = (byte) 0x7;
	final byte SOCKS_AUTH_MAF = (byte) 0x8;
	/* 0x9 through 0x7f are unassigned */
	/* 0x80 through 0xfe are private use */
	final byte SOCKS_AUTH_UNACCEPTABLE = (byte) 0xff;

	// Request constants
	final byte SOCKS_REQ_CMD_CONNECT = (byte) 0x1;
	final byte SOCKS_REQ_CMD_BIND = (byte) 0x2;
	final byte SOCKS_REQ_CMD_UDP_ASSOC = (byte) 0x3;

	final byte SOCKS_REQ_RSV = (byte) 0x0;

	final byte SOCKS_REQ_ATYP_IPV4 = (byte) 0x1;
	final byte SOCKS_REQ_ATYP_FQDN = (byte) 0x3;
	final byte SOCKS_REQ_ATYP_IPV6 = (byte) 0x4;

	// Reply constants
	final byte SOCKS_REP_SUCCEED = (byte) 0x0;
	final byte SOCKS_REP_FAIL = (byte) 0x1;
	final byte SOCKS_REP_DISALLOWED = (byte) 0x2;
	final byte SOCKS_REP_NET_UNREACH = (byte) 0x3;
	final byte SOCKS_REP_HOST_UNREACH = (byte) 0x4;
	final byte SOCKS_REP_CONN_REFUSED = (byte) 0x5;
	final byte SOCKS_REP_TTL_EXPIRED = (byte) 0x6;
	final byte SOCKS_REP_CMD_NOT_SUPP = (byte) 0x7;
	final byte SOCKS_REP_ADDR_NOT_SUPP = (byte) 0x8;

	// Private data
	private ServerSocket listener;
	private BlockingQueue<QueueItem> queue;

	// Constructors
	public SocksServer(int port, BlockingQueue<QueueItem> queue) throws IOException {
		// Fire up the socket to listen for proxy connections
		listener = new ServerSocket(port);

		// Save the queue for communication with the Cube protocol object
		this.queue = queue;
	}

	// Main method
	public static void main(String[] args) throws IOException {
		int socksport = 1080;
		int cubeport = 24680;
		LinkedBlockingQueue<QueueItem> queue = new LinkedBlockingQueue<>();

		// create the cube protocol object
		// create the cube connections object
		SocksServer server = new SocksServer(socksport, queue);
// fix this crap
	}

	/**
	 * Negotiate a SOCKS connection per RFC 1928 section 3.
	 * 
	 * @param sock
	 *            the incoming socket connection
	 * @return whether the negotiation was successful
	 * @throws IOException
	 */
	public static int negotiate() throws IOException {
		// Read the packet
		byte[] buffer = new byte[1 + 1 + 255];
		sock.getInputStream().read(buffer);

		// Ensure the version is correct
		if (buffer[0] != SOCKS_VERSION)
			return SOCKS_REP_DISALLOWED;

		// Ignore authentication

		// Return response that no authentication is required
		sock.getOutputStream().write(new byte[] { SOCKS_VERSION, SOCKS_AUTH_NONE });
		return SOCKS_REP_SUCCEED;
	}

	/**
	 * Process a SOCKS request per RFC 1928 section 4.
	 * 
	 * A CONNECT request should indicate a publicly available host/port that is
	 * advertised as an Ingress Negotiation Node (INN).
	 * 
	 * A BIND request is necessary only to set up secondary connections, for
	 * example if one is running a server.
	 * 
	 * A UDP ASSOCIATE request is used by some UDP protocols.
	 * 
	 * @param sock
	 *            the incoming socket connection
	 * @return whether the processing was successful
	 * @throws IOException
	 */
	public static void do_request(Socket sock) throws IOException {
		// Read the packet
		byte[] buffer = new byte[1 + 1 + 1 + 1 + 255 + 2];
		sock.getInputStream().read(buffer);

		// Ensure the version is correct
		if (buffer[0] != SOCKS_VERSION || buffer[2] != SOCKS_REQ_RSV)
			reply(SOCKS_REP_DISALLOWED);

		// Call the appropriate request
		switch (buffer[1]) {

		// Determine the Internet address and port
		case SOCKS_REQ_CMD_CONNECT:
			start_connect(buffer);
		}

		// Request that the Cube protocol object connect to a cube having the
		// given address as an ingress negotiator
		return -1;
	}

	private static void start_connect(byte[] buffer) throws UnknownHostException {
		byte[] addrbytes;
		InetAddress addr;
		int port;
		switch (buffer[3]) {

		case SOCKS_REQ_ATYP_IPV4:
			addrbytes = Arrays.copyOfRange(buffer, 4, 8);
			addr = InetAddress.getByAddress(addrbytes);
			port = buffer[8] << 8 + buffer[9];
			break;

		case SOCKS_REQ_ATYP_FQDN:
			int len = buffer[4];
			addrbytes = Arrays.copyOfRange(buffer, 5, 5 + len);
			addr = InetAddress.getByName(new String(addrbytes));
			port = buffer[5 + len] << 8 + buffer[6 + len];
			break;

		case SOCKS_REQ_ATYP_IPV6:
			addrbytes = Arrays.copyOfRange(buffer, 7, 23);
			addr = InetAddress.getByAddress(addrbytes);
			port = buffer[24] << 8 + buffer[25];
			break;

		default:
			finish_connect(SOCKS_REP_ADDR_NOT_SUPP);
			return;
		}

		// Place connect request in the queue

		// Success... for now
	}

	/**
	 * Called by the Cube protocol handler asynchronously when the connect
	 * request is finished processing
	 * 
	 * @param status
	 */
	static void finish_connect(byte status) {

	}

	/**
	 * Format a reply message to the SOCKS client.
	 * 
	 * @param reply
	 * @param atyp
	 * @param bndaddr
	 * @param bndport
	 */
	private static void reply(byte reply, byte atyp, byte[] bndaddr, int bndport) {

	}

}
