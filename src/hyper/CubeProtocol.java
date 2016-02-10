package hyper;

import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.channels.SocketChannel;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Vector;

import hyper.CubeMessage.Type;

/**
 * A class implementing the Cube protocol.
 * 
 * <h3>Motivation behind the protocol</h3>
 * <p>
 * The goal of this protocol is to provide an address space overlaying the IP address space that provides anonymous
 * communication between nodes using the overlay space. Obviously, at some point the overlay address must be mapped to
 * an IP address to facilitate communication, so the secrecy of this map is essential. Just as clear is the fact that,
 * for any choice of overlay address space, each node must know the IP addresses of its "neighbors", where neighborhood
 * is defined in some sense. The chief problem of such an arrangement is routing: each node must use the underlying IP
 * protocol to route messages on a hop by hop basis, but how does a node know which hop to use when the only nodes that
 * know the destination IP address are the destination node's neighbors in the overlay space? The chief accomplishment
 * of the Cube protocol is providing an algorithm for solving this problem, thereby showing that the necessary
 * "neighbor mapping" condition is actually sufficient to implement routing.
 * </p>
 * 
 * <p>
 * The key insight is to route messages along a direction that reduces the Hamming distance between the address of the
 * local node (which might be a relay node) and the destination address. This first-pass routing algorithm was developed
 * at the University of Michigan for so-called "complete" hypercubes; see J. Squire and S.M. Palais,
 * <em>Programming and Design Consideration of a Highly Parallel Copmputer</em>, Proc. AFIP Spring Joint Computer Conf.,
 * 23 (1963), pp. 395-400. Squire et al. required an address space that was an exact power of two, and each address had
 * to be serviced by a node. However, the problem at hand cannot be solved this way, since the number of nodes in the
 * system may not be so rigidly determined; that is, nodes might be "missing". The "incomplete" hypercube routing
 * problem was solved by Howard Katseff at AT&T; see Katseff, H., <em>Incomplete Hypercubes</em>, Hypercube
 * Multiprocessors, 1987: Proc. Second Conf. on Hypercube Multiprocessors, pp. 258-264.
 * </p>
 * 
 * <p>
 * If the <em>m</em> nodes in an incomplete hypercube are consecutively numbered from 0 to <em>m-1</em>, then there is
 * an <em>n</em> such that 2<sup><em>n</em></sup> < <em>m</em> < 2<sup><em>n+1</em></sup>. It was noted in Chen, G.-H.
 * et al., <em>An Algorithm Paradigm for Incomplete Hypercubes</em>, Computers Math. Applic. Vol. 22, No. 6, pp. 93-96,
 * 1991, that Katseff's algorithms require O(<em>n</em><sup>2</sup>) computation time and O(<em>n</em>) communication
 * time; the algorithms are therefore relatively scalable to large networks. The Chen paper proposed an algorithm that
 * used only O(<em>n</em>) computation time; however, in the present application, it cannot be guaranteed that the
 * present nodes will be consecutively numbered in the overlay address space. In particular, in the Cube protocol,
 * existing nodes have a right to deny connections from a new client for any reason, including the new client's IP
 * address, and such denial may foreclose the use of a particular overlay address. However, this insight justifies the
 * protocol's attempt to assign addresses for new nodes within the existing address space, before increasing the size of
 * the address space (that is, increasing the dimension of the hypercube).
 * </p>
 * 
 * <h3>Protocol overview</h3>
 * <p>
 * The Cube protocol uses Katseff's Algorithm 3 for routing, and Algorithm 6 for broadcast messaging. Algorithm 6 is
 * also "reversed" for gathering data from all connected nodes; see, for example, Fosdick et al., An Introduction to
 * High-performance Scientific Computing, p. 468 (MIT Press, 1996).
 * </p>
 * 
 * <p>
 * There is one major function provided by the protocol that requires many different types of messages to be passed:
 * connecting new clients to the Cube. The chief concern in this area of the protocol is maintaining the anonymity of
 * the link between an {@link InetAddress} and a {@link CubeAddress}. Obviously, each Cube must provide one or more
 * nodes that act as gateways for the connection process, and the <code>InetAddress</code> of each of these Ingress
 * Negotiation Nodes (INNs) must be discoverable outside the protocol. The discovery process for INNs is outside the
 * scope of this protocol; Cube communities may develop their own standards. However, the protocol nevertheless shields
 * the revelation of any <code>CubeAddress</code> to a connecting client until the last possible moment, after it has
 * been approved to join the Cube.
 * </p>
 * 
 * <p>
 * The connection process operates in four phases. In the first phase, the INN locates an attachment point for an
 * external client that wishes to join; that is, a previously-connected node that is willing and able to be a neighbor
 * in the Cube address space. This attachment node takes over the remainder of the process as an Address Negotiation
 * Node (ANN). In the second phase, the ANN offers the external client a CubeAddress using a direct connection (i.e.,
 * outside the normal Cube message passing algorithm), without revealing its own Cube address or that of any of the
 * would-be neighbors. In the third phase, the ANN instructs each neighbor to establish an IP connection to the client
 * (again, without revealing its Cube address). In the fourth phase, if all has gone perfectly, the ANN instructs each
 * neighbor to reveal its address to the client outside the normal Cube channels, completing the Cube connection while
 * preventing other nodes from learning of the confidential relationship between {@link InetAddress} and
 * {@link CubeAddress}. If any of Phases 2 through 4 fail, the ANN informs the neighbors and the INN, which resumes the
 * search for a different, working ANN. If no ANN can be found (even after considering expanding the Cube's dimension),
 * the INN informs the client that the connection was denied.
 * </p>
 * 
 * <p>
 * An ANN may only connect the client if the client's prospective neighbors (including the ANN itself) are all willing
 * and able to connect to the new client. Willingness to connect is a potentially serious issue; for example, a node may
 * wish to maintain a blacklist of IP addresses or blocks that are denied connections due to political or network
 * routing efficiency concerns. Therefore, the protocol guarantees that no Cube member shall be required to connect to
 * any client for which it signals an unwillingness to do so (and vice versa). This guarantee is implemented by the INN
 * gathering, from each node in the Cube in Phase 1, an indication of its willingness to connect to the client, then
 * performing a calculation to guarantee that the selected ANN and the other new neighbors are all willing. However,
 * ability to connect (that is, whether a node has a slot for connecting to another node) is an issue of Cube topology,
 * which is easily fixed within the protocol.
 * </p>
 * 
 * <p>
 * The details of these processes follow. Message types referenced below support the connection state machine, and are
 * found in the {@link CubeMessage.Type} inner class. Messages for protocol connections are named in four parts. The
 * first part is <code>CONN</code>, signifying their purpose. The second and third parts indicate the role of the
 * computers respectively sending and receiving the message: <code>EXT</code> for the external client, <code>INN</code>
 * for the Ingress Negotiation Node, <code>GEN</code> for a generic Cube node, <code>ANN</code> for the Address
 * Negotiation Node, and <code>NBR</code> for a potential neighbor node. The fourth part is the purpose of the message.
 * </p>
 * 
 * <h3>Protocol detail</h3>
 * 
 * <h4>Phase 1: Locating a possible attachment point</h4>
 * <p>
 * The first phase locates an attachment point for a new node, and is executed by the INN in response to receiving a
 * <code>CONN_EXT_INN_ATTACH</code> message from an external client. The INN broadcasts <code>CONN_INN_GEN_ANN</code>
 * messages to other nodes in the Cube. All other nodes, in turn, return reverse broadcast their availability in a
 * <code>CONN_GEN_INN_AVAIL</code> message as either unwilling (in which case they will be excluded from further
 * consideration) or able because they have a vacancy in their connectivity table. The INN designates a random "able"
 * node as the address negotiating node (ANN), and hands off the remainder of the process to the ANN using a
 * <code>CONN_INN_ANN_HANDOFF</code> message.
 * </p>
 * 
 * <p>
 * Because address negotiation can fail, the ANN must reply with a success-or-fail status to the INN. If the negotiation
 * of Phases 2 through 4 succeeds as indicated by a <code>CONN_ANN_INN_SUCCESS</code> message, the INN can terminate its
 * participation in the addressing protocol. However if the negotiation fails via a <code>CONN_ANN_INN_FAIL</code>
 * message, the INN continues searching using the ANN cache. If the INN is unable to locate any willing and able ANN,
 * the protocol expands the dimension of the Cube by attaching the new client to the INN itself. (Only the INN can be
 * used here, since a message to any other node instructing attachment would permit computation of the new client's
 * {@link CubeAddress}.) If the INN is unwilling, then the connection fails.
 * </p>
 * 
 * <p>
 * <b>Address security analysis</b>: During Phase 1, the new peer's {@link InetSocketAddress} is passed around, but its
 * {@link CubeAddress} has not been determined. Listening for nodes that accept responsibility as ANN does not reveal a
 * confidential address relationship, since it is not known whether the remaining Phases will be successful, and in any
 * event the accepting ANN might attach the new peer on any of a number of different <code>CubeAddress</code>es, with
 * the uncertainty growing as the Cube's dimension increases.
 * </p>
 * 
 * <h4>Phase 2: Offering a CubeAddress to the client</h4>
 * <p>
 * The ANN notifies the new client of the client's new <code>CubeAddress</code> and the list of nonces from its new
 * neighbors via <code>CONN_ANN_EXT_OFFER</code>. This is done without revealing the ANN's <code>CubeAddress</code>,
 * because the client cannot yet be trusted with that information.
 * </p>
 * 
 * <p>
 * The client may acknowledge the address using a <code>CONN_EXT_ANN_ACCEPT</code> message. If so, the ANN proceeds to
 * Phase 3. However, if the client expresses unwillingness to connect to the ANN via <code>CONN_EXT_ANN_DECLINE</code>.
 * In this case, the ANN sends a <code>CONN_ANN_INN_FAIL</code> message to the INN and terminates processing.
 * </p>
 * 
 * <p>
 * <b>Address security analysis</b>: Phase 2 communications within the Cube do not contain the proposed
 * {@link CubeAddress} of the client, and communications outside the Cube do not contain the {@link CubeAddress} of any
 * Cube node.
 * </p>
 * 
 * <h4>Phase 3: Neighbors all connect without revealing their CubeAddresses</h4>
 * <p>
 * Phase 3 begins with the ANN instructing each neighbor to connect to the client via <code>CONN_ANN_NBR_CONNECT</code>.
 * Each neighbor sends to the client, by direct connection outside the node, a <code>CONN_NBR_EXT_OFFER</code> message
 * containing no data. In response, the new client must reply with a <code>CONN_EXT_NBR_ACCEPT</code> message containing
 * its new <code>CubeAddress</code>, or a <code>CONN_EXT_NBR_DECLINE</code> message. Each neighbor verifies that the new
 * <code>CubeAddress</code> is a valid neighbor. The neighbor reports success or failure of the verification to the ANN
 * via <code>CONN_NBR_ANN_CONNECTED</code> and <code>CONN_NBR_ANN_DISCONNECTED</code> messages.
 * </p>
 * 
 * <p>
 * If the ANN gets even a single failure, it shuts down the negotiation by sending a <code>CONN_ANN_NBR_FAIL</code>
 * message, informing each of them not to advertise its <code>CubeAddress</code> to the client. The ANN then informs the
 * INN of the failure. However, if all neighbors report success, the connection is assured and the protocol proceeds to
 * the final phase.
 * </p>
 * 
 * <p>
 * <b>Address security analysis</b>: Phase 3 communications within the Cube do not contain the {@link CubeAddress} of
 * the client, and communications outside the Cube do not contain the {@link CubeAddress} of any Cube node.
 * </p>
 * 
 * <h4>Phase 4: CubeAddress advertisement</h4>
 * <p>
 * Once all neighbor connections were successful, the ANN sends each neighbor a <code>CONN_ANN_NBR_IDENTIFY</code>
 * message, instructing it to divulge its {@link CubeAddress} to the client. Then each neighbor, including the ANN,
 * sends the client a <code>CONN_NBR_EXT_IDENTIFY</code> message containing its <code>CubeAddress</code>. No response is
 * required from the client. The ANN also transmits <code>CONN_ANN_INN_SUCCESS</code> to the INN, to permit the INN to
 * clean up its own ingress state.
 * </p>
 * 
 * <p>
 * <b>Address security analysis</b>: Phase 4 communications within the Cube do not contain the {@link CubeAddress} of
 * the client. Communications outside the Cube contain the {@link CubeAddress} of each neighbor, which is necessary for
 * implementing an overlay routing protocol, but no other sensitive information.
 * </p>
 */
public class CubeProtocol
{
	// Cube state
	private CubeState cubeState = new CubeState();

	// Connection states, one per connecting peer
	private HashMap<InetSocketAddress, CxnState> cxnStates = new HashMap<>();

	// // INN states
	// private HashMap<InetSocketAddress, INNState> innStates = new HashMap<>();
	//
	// // ANN states
	// private HashMap<InetSocketAddress, ANNState> annStates = new HashMap<>();
	//
	// // NBR states
	// private HashMap<InetSocketAddress, NbrState> nbrStates = new HashMap<>();
	//
	// // CLT state
	// private CltState cltState;

	// State machine: { message received => acceptable state in which to receive it }
	@SuppressWarnings({ "serial" })
	private static HashMap<Type, Type> sm = new HashMap<Type, Type>() {
		{
			// INN transitions
			put(Type.CONN_GEN_INN_AVAIL, Type.CONN_INN_GEN_ANN);
			put(Type.CONN_ANN_INN_SUCCESS, Type.CONN_INN_ANN_HANDOFF);
			put(Type.CONN_ANN_INN_FAIL, Type.CONN_INN_ANN_HANDOFF);

			// ANN transitions
			put(Type.CONN_INN_ANN_HANDOFF, Type.CONN_GEN_INN_AVAIL);
			put(Type.CONN_EXT_ANN_ACCEPT, Type.CONN_ANN_EXT_OFFER);
			put(Type.CONN_EXT_ANN_DECLINE, Type.CONN_ANN_EXT_OFFER);
			put(Type.CONN_NBR_ANN_CONNECTED, Type.CONN_ANN_NBR_CONNECT);
			put(Type.CONN_NBR_ANN_DISCONNECTED, Type.CONN_ANN_NBR_CONNECT);
			put(Type.CONN_NBR_ANN_IDENTIFIED, Type.CONN_ANN_NBR_IDENTIFY);
			put(Type.CONN_INN_GEN_CLEANUP, Type.CONN_GEN_INN_AVAIL);

			// NBR transitions
			put(Type.CONN_EXT_NBR_ACCEPT, Type.CONN_NBR_EXT_OFFER);
			put(Type.CONN_EXT_NBR_DECLINE, Type.CONN_NBR_EXT_OFFER);
			put(Type.CONN_ANN_NBR_IDENTIFY, Type.CONN_NBR_ANN_CONNECTED);

			// EXT transitions
			put(Type.CONN_ANN_EXT_OFFER, Type.CONN_EXT_INN_ATTACH);
			put(Type.CONN_NBR_EXT_OFFER, Type.CONN_EXT_ANN_ACCEPT);
			put(Type.CONN_NBR_EXT_IDENTIFY, Type.CONN_EXT_ANN_ACCEPT);
			put(Type.CONN_ANN_EXT_SUCCESS, Type.CONN_EXT_ANN_ACCEPT);
			put(Type.CONN_ANN_EXT_FAIL, Type.CONN_EXT_ANN_ACCEPT);
		}
	};

	// Our MessageListener
	private MessageListener listener;

	// Local message queuing
	private ArrayList<CubeMessage> queued = new ArrayList<>();

	// Our monitor object, used so we don't return from connect() or recv() too soon
	boolean blocking = false;
	Thread blockingThread = null; // Only necessary for testing

	CubeProtocol(MessageListener listener)
	{
		this.listener = listener;
		listener.setProtocol(this);
	}

	// Determine if a message is meant for me. If so, return true; otherwise, forward it.
	private boolean fwdMsg(CubeMessage msg)
	{
		CubeAddress none = CubeAddress.INVALID_ADDRESS;
		CubeAddress frwd = CubeAddress.BCAST_FORWARD;
		CubeAddress rvrs = CubeAddress.BCAST_REVERSE;

		// Determine the destination
		CubeAddress dst = msg.getDst();

		// Quickly bail based on source or destination, if we can
		if (null == msg.getSrc() || msg.getSrc().equals(none) || msg.getSrc().equals(rvrs) || null == dst
				|| dst.equals(none) || msg.getSrc().equals(msg.getDst()))
			return true;

		// Non-broadcast processing
		if (dst.compareTo(BigInteger.ZERO) >= 0)
		{
			if (dst.equals(cubeState.addr))
				// It's mine
				return true;
			else
			{
				// It's not mine; forward it
				unicastSend(msg);
				return false;
			}
		}

		// Broadcast processing
		if (null == msg.getTravel() || !dst.equals(frwd) && !dst.equals(CubeAddress.BCAST_PROCESS))
		{
			// The broadcast data are invalid
			reply(msg, Type.INVALID_MSG, msg.getType());
			return false;
		}

		// If we are at the end of the broadcast chain, return immediately
		if (msg.getTravel().equals(BigInteger.ZERO))
			return true;

		// Forward the message, ignoring the return value
		bcastSend(msg);

		// Return based on whether we should (also) process the message
		return dst.equals(CubeAddress.BCAST_PROCESS);
	}

	/**
	 * Process a {@link CubeMessage} received by the {@link MessageListener} according to the Cube protocol.
	 * 
	 * Documentation about the meaning of each message type can be found in the {@link CubeMessage} class and by
	 * consulting the description of the protocol.
	 * 
	 * @param msg
	 *            the {@link CubeMessage} to process
	 */
	void process(CubeMessage msg)
	{
		// Forward messages that are not meant for me
		if (!fwdMsg(msg))
			return;

		System.err.println(Thread.currentThread() + " " + msg);

		switch (msg.getType()) {
		/*
		 * Phase 1
		 */
		case CONN_EXT_INN_ATTACH:
			conn_ext_inn_attach(msg);
			break;
		case CONN_INN_GEN_ANN:
			// Broadcast message
			conn_inn_gen_ann(msg);
			break;
		case CONN_GEN_INN_AVAIL:
			conn_gen_inn_avail(msg);
			break;
		case CONN_INN_ANN_HANDOFF:
			conn_inn_ann_handoff(msg);
			break;
		/*
		 * Phase 2
		 */
		case CONN_ANN_EXT_OFFER:
			conn_ann_ext_offer(msg);
			break;
		case CONN_EXT_ANN_ACCEPT:
			conn_ext_ann_accept(msg);
			break;
		case CONN_EXT_ANN_DECLINE:
			conn_ext_ann_decline(msg);
			break;
		/*
		 * Phase 3
		 */
		case CONN_ANN_NBR_CONNECT:
			conn_ann_nbr_connect(msg);
			break;
		case CONN_NBR_EXT_OFFER:
			conn_nbr_ext_offer(msg);
			break;
		case CONN_EXT_NBR_ACCEPT:
			conn_ext_nbr_accept(msg);
			break;
		case CONN_EXT_NBR_DECLINE:
			conn_ext_nbr_decline(msg);
			break;
		case CONN_NBR_ANN_CONNECTED:
			conn_nbr_ann_connected(msg);
			break;
		case CONN_NBR_ANN_DISCONNECTED:
			conn_nbr_ann_disconnected(msg);
			break;
		/*
		 * Phase 4
		 */
		case CONN_ANN_NBR_IDENTIFY:
			conn_ann_nbr_identify(msg);
			break;
		case CONN_NBR_EXT_IDENTIFY:
			conn_nbr_ext_identify(msg);
			break;
		case CONN_NBR_ANN_IDENTIFIED:
			conn_nbr_ann_identified(msg);
			break;
		case CONN_ANN_EXT_SUCCESS:
			conn_ann_ext_success(msg);
			break;
		case CONN_ANN_INN_SUCCESS:
			conn_ann_inn_success(msg);
			break;
		case CONN_INN_GEN_CLEANUP:
			conn_inn_gen_cleanup(msg);
			break;
		/*
		 * Failure messages
		 */
		case INVALID_MSG:
			// System.err.println(Thread.currentThread() + " received INVALID_MSG: (" + msg.getSrc() + "," +
			// msg.getDst()
			// + "," + msg.getData() + ")");
			break;
		case INVALID_ADDRESS:
			invalid_address(msg);
			break;
		case INVALID_STATE:
			// System.err.println(Thread.currentThread() + " received INVALID_STATE: (" + msg.getSrc() + "," +
			// msg.getDst()
			// + "," + msg.getData() + ")");
			break;
		case INVALID_DATA:
			// System.err.println(Thread.currentThread() + " received INVALID_DATA: (" + msg.getSrc() + "," +
			// msg.getDst()
			// + "," + msg.getData() + ")");
			break;
		case CONN_INN_EXT_CONN_REFUSED:
			conn_inn_ext_conn_refused(msg);
			break;
		case CONN_ANN_INN_FAIL:
			conn_ann_inn_fail(msg);
			break;
		case CONN_ANN_NBR_FAIL:
			conn_ann_nbr_fail(msg);
			break;
		case CONN_ANN_EXT_FAIL:
			conn_ann_ext_fail(msg);
			break;
		/*
		 * Connected node messages
		 */
		case DATA_MSG:
			data_msg(msg);
			break;
		case NODE_SHUTDOWN:
			node_shutdown(msg);
			break;
		default:
			System.err.println(Thread.currentThread() + " received unknown message type " + msg.getType() + ": ("
					+ msg.getSrc() + "," + msg.getDst() + "," + msg.getData() + ")");
			break;
		}
	}

	/*
	 * Phase 1 methods
	 */

	/**
	 * INN must respond to initial request from client to connect.
	 * 
	 * Algorithm: broadcast a request asking generic nodes to be ANN for this connection
	 * 
	 * Security: For now, any node may act as INN. This decision was made because there is no apparent way to publish a
	 * list of "authorized" INNs that is usable by existing nodes without resolving complex trust issues. In particular,
	 * any node that wishes to advertise its IP address as an INN cannot send this information within the Cube itself,
	 * as doing so would compromise the confidentiality of the CubeAddress-to-IP Address relationship for that node, and
	 * simply allowing individual nodes to claim authorization is ripe for abuse. Also, if all "authorized" INNs become
	 * disconnected for some reason, the Cube will slowly die without a mechanism for adding new INNs. The security of
	 * this method therefore relies on the Cube community restricting access to the list of participating IP addresses.
	 * 
	 * One possible solution is to allow a broadcast message advertising an IP address to which any participating node
	 * can directly connect (outside the Cube) if it wishes to advertise itself as an INN. On one hand, this mechanism
	 * could be abused to quickly harvest many IP addresses from the Cube. On the other hand, this would leave the
	 * decision whether the advertised IP address is trustworthy up to the individual nodes, rather than a central
	 * authority.
	 */
	private void conn_ext_inn_attach(CubeMessage msg)
	{
		// // Validate the message
		// InetSocketAddress addr = (InetSocketAddress) validateExt(msg, null);
		// CubeAddress none = CubeAddress.INVALID_ADDRESS;
		//
		// // Validate the source and destination
		// if (!msg.getSrc().equals(none))
		// {
		// new CubeMessage(none, none, Type.INVALID_ADDRESS, msg.getSrc()).send(msg.getChannel());
		// return;
		// } else if (!msg.getDst().equals(none))
		// {
		// new CubeMessage(none, none, Type.INVALID_ADDRESS, msg.getDst()).send(msg.getChannel());
		// return;
		// }
		//
		// // Ensure we are in the correct state
		// if (null != innStates.get(addr))
		// {
		// new CubeMessage(none, none, Type.INVALID_STATE, new Enum[] { null, msg.getType() }).send(msg.getChannel());
		// return;
		// }

		InetSocketAddress addr = (InetSocketAddress) msg.getData();

		// Edge case: I might be the only node in the Cube
		if (cubeState.getDim() == 0)
		{
			// Perform a blocking connection attempt, all the way through Phase 4
			connectNodeToINN(addr, msg.getChannel());
			return;
		}

		// Initialize state
		CxnState innState = new CxnState();
		cxnStates.put(addr, innState);
		innState.innAddr = cubeState.addr;
		innState.innChan = msg.getChannel();

		// Edge case: I have an open slot myself and I'm willing to take on this client
		if (cubeState.vacancy() && amWilling(addr))
		{
			// Declare myself the ANN and enter Phase 2
			innState.annAddr = cubeState.addr;
			innState.state = Type.CONN_INN_ANN_HANDOFF;
			conn_inn_ann_handoff(new CubeMessage(cubeState.addr, innState.annAddr, innState.state, addr));
			return;
		}

		// Regular processing: broadcast an INN_GEN_ANN message
		innState.state = Type.CONN_INN_GEN_ANN;
		bcastSend(new CubeMessage(cubeState.addr, CubeAddress.BCAST_PROCESS, innState.state, addr, cubeState.getDim()));
	}

	/**
	 * Generic node must respond to INN request to become ANN and connect client.
	 * 
	 * Algorithm: set up ANN state, and if I am a broadcast leaf, generate a reply
	 */
	private void conn_inn_gen_ann(CubeMessage msg)
	{
		// // Validate the message
		// InetSocketAddress addr = (InetSocketAddress) validateMsg(msg, null);
		// if (null == addr)
		// return;
		//
		// // Address validation based on "authorized" INNs?
		//
		// // Ensure proper format
		// if (null == msg.getTravel())
		// {
		// reply(msg, Type.INVALID_MSG, msg.getType());
		// return;
		// }
		//
		// // Ensure we are in the correct state
		// if (null != annStates.get(addr))
		// {
		// reply(msg, Type.INVALID_STATE, new Enum[] { annStates.get(addr).state, msg.getType() });
		// }

		InetSocketAddress addr = (InetSocketAddress) msg.getData();
		CxnState annState = new CxnState();
		cxnStates.put(addr, annState);
		annState.innAddr = msg.getSrc();

		// If we're just forwarding, wait for replies
		BigInteger zero = BigInteger.ZERO;
		if (!msg.getTravel().and(cubeState.links).equals(zero))
			return;

		// We're replying, so determine the payload and reply
		Serializable[] payload;
		boolean willing = amWilling(addr);
		if (!willing)
			payload = new Serializable[] { addr, zero.setBit(cubeState.addr.intValue()), zero };
		else if (cubeState.vacancy())
			payload = new Serializable[] { addr, zero, zero.setBit(cubeState.addr.intValue()) };
		else
			payload = new Serializable[] { addr, zero, zero };
		unicastSend(new CubeMessage(CubeAddress.BCAST_REVERSE, msg.getSrc(), Type.CONN_GEN_INN_AVAIL, payload));

		// Update state, if required
		if (!willing)
			return;
		else
			annState.state = Type.CONN_GEN_INN_AVAIL;
	}

	/**
	 * Node must gather willing/able responses and forward them to the INN.
	 * 
	 * Algorithm: if
	 */
	private void conn_gen_inn_avail(CubeMessage msg)
	{
		// // Validate the reply message
		// Serializable[] payload = (Serializable[]) validateMsg(msg, null);
		// if (null == payload)
		// return;
		// if (!(payload[0] instanceof InetSocketAddress) || !(payload[1] instanceof BigInteger)
		// || !(payload[2] instanceof BigInteger))
		// {
		// reply(msg, Type.INVALID_DATA, msg.getType());
		// return;
		// }
		//
		// // Ensure the proper state
		// InetSocketAddress addr = (InetSocketAddress) payload[0];
		// ANNState annState = annStates.get(addr);
		// if (null == annState)
		// {
		// reply(msg, Type.INVALID_STATE, msg.getType());
		// return;
		// }

		Serializable[] payload = (Serializable[]) msg.getData();
		InetSocketAddress addr = (InetSocketAddress) payload[0];
		CxnState innState = cxnStates.get(addr);

		// Aggregate data
		innState.unwilling = innState.unwilling.or((BigInteger) payload[1]);
		innState.able = innState.able.or((BigInteger) payload[2]);
		innState.replies++;

		// Are we done aggregating everyone else?
		if (innState.replies + innState.invalid.bitCount() < cubeState.getDim())
			return;

		// We are done; aggregate our own status
		if (!amWilling(addr))
			innState.unwilling = innState.unwilling.setBit(cubeState.addr.intValue());
		innState.state = Type.CONN_GEN_INN_AVAIL;
		if (cubeState.vacancy())
			innState.able = innState.able.setBit(cubeState.addr.intValue());

		// If we're not the INN, forward the totals upstream then clean up
		if (!cubeState.addr.equals(innState.innAddr))
		{
			unicastSend(new CubeMessage(CubeAddress.BCAST_REVERSE, innState.innAddr, Type.CONN_GEN_INN_AVAIL,
					new Serializable[] { addr, innState.unwilling, innState.able }));
			cxnStates.remove(addr);
			return;
		}

		// We're the INN, with aggregated totals in hand. Initialize state, then hand off to an ANN
		innState.able = innState.able;
		innState.unwilling = innState.unwilling;
		innState.state = Type.CONN_INN_ANN_HANDOFF;
		handoff(addr);
	}

	// Perform the INN => ANN hand off
	private void handoff(InetSocketAddress addr)
	{
		// INNState innState = innStates.get(addr);
		CxnState innState = cxnStates.get(addr);

		// Do we have ANNs to choose from?
		NEXT_ANN:
		while (!innState.able.equals(BigInteger.ZERO))
		{
			// Determine a random potential ANN
			int ann;
			int link = 1 + (int) (Math.random() * innState.able.bitCount());
			for (ann = cubeState.getDim(); ann >= 0 && link > 0; --ann)
				if (innState.able.testBit(ann))
					--link;
			innState.able = innState.able.clearBit(ann + 1);
			innState.annAddr = new CubeAddress(Integer.toString(ann + 1));

			// Check the prospective neighbors' willingness
			for (int i = cubeState.getDim() - 1; i >= 0; --i)
				for (int j = cubeState.getDim() - 1; j > i; --j)
					if (innState.unwilling.testBit(innState.annAddr.followLink(i).followLink(j).intValue()))
						continue NEXT_ANN;

			// We found a winner! Notify them
			unicastSend(new CubeMessage(cubeState.addr, innState.annAddr, innState.state, addr));
			return;
		}

		// There are no ANNs left, we need to expand the Cube by attaching to the INN
		cxnStates.remove(addr);
		connectNodeToINN(addr, innState.innChan);
	}

	/**
	 * Generic node must respond to INN instruction to become ANN. This method is the entry point to Phase 2.
	 * 
	 * Algorithm: initialize ANN state and contact prospective neighbors
	 */
	private void conn_inn_ann_handoff(CubeMessage msg)
	{
		// // Validate the message
		// InetSocketAddress addr = (InetSocketAddress) validateMsg(msg, annStates);
		// if (null == addr)
		// return;
		//
		// // Authenticate the source
		// ANNState annState = annStates.get(addr);
		// if (null == annState || !annState.inn.equals(msg.getSrc()))
		// {
		// reply(msg, Type.INVALID_MSG, msg.getType());
		// return;
		// }

		InetSocketAddress addr = (InetSocketAddress) msg.getData();
		CxnState annState = cxnStates.get(addr);

		// Determine (1) whether this join will expand the Cube, and (2) the new CubeAddress of the client
		boolean isExpanding = (cubeState.neighbors.size() == cubeState.getDim() && !cubeState.vacancy());
		int link = isExpanding ? cubeState.getDim() : cubeState.links.not().getLowestSetBit();
		annState.peerAddr = cubeState.addr.followLink(link);

		// Enter Phase 2
		try
		{
			// Connect to the client's CubeProtocol
			annState.annChan = SocketChannel.open(addr);
			listener.register(annState.annChan);
		} catch (IOException e)
		{
			unicastSend(new CubeMessage(cubeState.addr, annState.innAddr, Type.CONN_ANN_INN_FAIL, addr));
			return;
		}

		// Set up my own neighbor state and offer the client an address
		annState.annAddr = cubeState.addr;
		annState.state = Type.CONN_ANN_EXT_OFFER;
		new CubeMessage(CubeAddress.INVALID_ADDRESS, annState.peerAddr, annState.state, cubeState.getDim())
				.send(annState.annChan);
	}

	// INN processing to connect a client, bypassing several layers of protocol
	private void connectNodeToINN(InetSocketAddress addr, SocketChannel innChan)
	{
		CubeAddress none = CubeAddress.INVALID_ADDRESS;
		CubeAddress peerAddr = new CubeAddress(
				BigInteger.ZERO.setBit(cubeState.getDim()).or(cubeState.addr).toString());
		CubeMessage msg;

		// Phase 1: successful, since I have identified an attachment point (myself)
		// Phase 2: check all neighbors (i.e., myself) for willingness to connect
		if (!amWilling(addr))
		{
			new CubeMessage(none, none, Type.CONN_INN_EXT_CONN_REFUSED, null).send(innChan);
			quietClose(innChan);
			return;
		}

		// Phase 3: offer a CubeAddress to the client
		SocketChannel annChan;
		try
		{
			annChan = SocketChannel.open(addr);
		} catch (IOException e)
		{
			// If the address is unreachable, bail
			new CubeMessage(none, none, Type.CONN_INN_EXT_CONN_REFUSED, null).send(innChan);
			quietClose(innChan);
			return;
		}
		new CubeMessage(none, peerAddr, Type.CONN_ANN_EXT_OFFER, cubeState.getDim()).send(annChan);
		try
		{
			msg = CubeMessage.recv(annChan);
		} catch (IOException e1)
		{
			// If we get here, the client disconnected the annChan on us or the message data was garbage; bail
			new CubeMessage(none, none, Type.CONN_INN_EXT_CONN_REFUSED, null).send(innChan);
			quietClose(annChan);
			quietClose(innChan);
			return;
		}

		if (!Type.CONN_EXT_ANN_ACCEPT.equals(msg.getType()))
		{
			new CubeMessage(none, none, Type.CONN_INN_EXT_CONN_REFUSED, null).send(innChan);
			quietClose(annChan);
			quietClose(innChan);
			return;
		}

		// Phase 4: successful since the only neighbor (me) already has a connection to the client
		// Phase 5: reveal my CubeAddress and complete the connection
		new CubeMessage(cubeState.addr, peerAddr, Type.CONN_NBR_EXT_IDENTIFY, null).send(annChan);
		try
		{
			listener.register(annChan);
		} catch (IOException e)
		{
			// If we can't register this channel after sending a boatload of messages, well...
			new CubeMessage(none, none, Type.CONN_INN_EXT_CONN_REFUSED, null).send(innChan);
			quietClose(annChan);
			quietClose(innChan);
			return;
		}

		// Now that Phase 5 is complete, indicate success to everyone and update the routing information
		quietClose(innChan);
		bcastSend(new CubeMessage(cubeState.addr, CubeAddress.BCAST_PROCESS, Type.CONN_INN_GEN_CLEANUP, addr));
		new CubeMessage(cubeState.addr, peerAddr, Type.CONN_ANN_EXT_SUCCESS, null).send(annChan);
		cubeState.addNeighbor(cubeState.getDim(), annChan); // Side effect: updating the Cube dimension
	}

	/*
	 * Phase 2 methods
	 */

	/**
	 * Client must respond to an offer of a new CubeAddress from an ANN.
	 * 
	 * Algorithm: acknowledge the offer
	 */
	private void conn_ann_ext_offer(CubeMessage msg)
	{
		// // Validate the message
		// int dim = (int) validateInt(msg);
		// cltState.annChan = msg.getChannel();
		// if (!cltState.annChan.isOpen())
		// return;
		//
		// // Validate the source
		// if (!msg.getSrc().equals(CubeAddress.INVALID_ADDRESS))
		// {
		// // Serious problems: the ANN's protocol engine has a security breach
		// new CubeMessage(none, none, Type.INVALID_ADDRESS, msg.getType());
		// quietClose(cltState.annChan);
		// return;
		// }

		CxnState cltState = cxnStates.values().iterator().next();
		cltState.annChan = msg.getChannel();
		CubeAddress none = CubeAddress.INVALID_ADDRESS;

		// Am I willing to have the ANN as my neighbor?
		InetSocketAddress addr = quietAddr(cltState.annChan);
		if (null == addr || !amWilling(addr))
		{
			new CubeMessage(none, none, Type.CONN_EXT_ANN_DECLINE, null).send(cltState.annChan);
			quietClose(cltState.annChan);
			return;
		}

		// Accept the offer
		cubeState.addr = msg.getDst();
		cubeState.setDim((int) msg.getData());
		cltState.state = Type.CONN_EXT_ANN_ACCEPT;
		new CubeMessage(cubeState.addr, none, cltState.state, null).send(cltState.annChan);
	}

	/**
	 * ANN must respond to acknowledgment of CubeAddress from client. This method is the entry point to Phase 3.
	 * 
	 * Algorithm: instruct new neighbors to contact the client
	 */
	private void conn_ext_ann_accept(CubeMessage msg)
	{
		// // Validate the message
		// validateExt(msg, annStates);
		// SocketChannel chan = msg.getChannel();
		// if (!chan.isOpen())
		// return;
		//
		// // Validate the source and destination
		// InetSocketAddress addr = quietAddr(chan);
		// ANNState annState = annStates.get(addr);
		// CubeAddress none = CubeAddress.INVALID_ADDRESS;
		// if (!msg.getSrc().equals(annState.peerAddr))
		// {
		// new CubeMessage(none, none, Type.INVALID_ADDRESS, msg.getSrc()).send(chan);
		// quietClose(chan);
		// unicastSend(new CubeMessage(cubeState.addr, annState.inn, Type.CONN_ANN_INN_FAIL, addr));
		// return;
		// } else if (!msg.getDst().equals(none))
		// {
		// new CubeMessage(none, none, Type.INVALID_ADDRESS, msg.getDst()).send(chan);
		// quietClose(chan);
		// return;
		// }

		SocketChannel chan = msg.getChannel();
		InetSocketAddress addr = quietAddr(chan);
		CxnState annState = cxnStates.get(addr);

		// Enter Phase 4. First determine whether the new peer has at least one neighbor already connected
		if (cubeState.getDim() > 1 + annState.invalid.bitCount())
		{
			// Regular processing. Inform all the other neighbors to connect
			annState.replies = 1;
			annState.state = Type.CONN_ANN_NBR_CONNECT;
			annBcast(annState, addr);
			return;
		}

		// Edge case: I'm the only neighbor connected, skip straight to Phase 4
		new CubeMessage(cubeState.addr, annState.peerAddr, Type.CONN_NBR_EXT_IDENTIFY, null).send(chan);
		new CubeMessage(cubeState.addr, annState.peerAddr, Type.CONN_ANN_EXT_SUCCESS, null).send(chan);

		// Inform the INN and clean up state
		cxnStates.remove(addr);
		unicastSend(new CubeMessage(cubeState.addr, annState.innAddr, Type.CONN_ANN_INN_SUCCESS, addr));

		// Update the routing information
		int link = cubeState.addr.relativeLink(annState.peerAddr);
		cubeState.addNeighbor(link, chan);
	}

	/**
	 * ANN must respond to declining of CubeAddress from client.
	 * 
	 * Algorithm: bail
	 */
	private void conn_ext_ann_decline(CubeMessage msg)
	{
		// No need to check anything, since all paths lead to...
		InetSocketAddress addr = quietAddr(msg.getChannel());
		quietClose(msg.getChannel());
		annBail(addr);
	}

	/*
	 * Phase 3 methods
	 */

	/**
	 * Neighbor must respond to ANN instruction to connect.
	 * 
	 * Algorithm: attempt to connect, and report success/failure to ANN
	 */
	private void conn_ann_nbr_connect(CubeMessage msg)
	{
		// // Validate the message
		// InetSocketAddress addr = (InetSocketAddress) validateMsg(msg, null);
		// if (null == addr)
		// return;
		//
		// // Authenticate the source
		// if (2 != cubeState.addr.xor(msg.getSrc()).bitCount())
		// {
		// reply(msg, Type.INVALID_MSG, msg.getType());
		// return;
		// }
		//
		// // Ensure we are in the correct state
		// if (nbrStates.containsKey(addr))
		// {
		// reply(msg, Type.INVALID_STATE, new Type[] { null, msg.getType() });
		// return;
		// }
		// NbrState nbrState = new NbrState(msg.getSrc());

		// Attempt to connect to the client
		InetSocketAddress addr = (InetSocketAddress) msg.getData();
		CxnState nbrState = cxnStates.get(addr);
		nbrState.annAddr = msg.getSrc();
		try
		{
			nbrState.nbrChan = SocketChannel.open(addr);
		} catch (IOException e)
		{
			// The ANN was able to connect to the client but I can't, so bail
			nbrState.state = Type.CONN_NBR_ANN_DISCONNECTED;
			unicastSend(new CubeMessage(cubeState.addr, nbrState.annAddr, nbrState.state, null));
			return;
		}

		// Socket connection was successful, update state and offer Cube connection to the client
		CubeAddress none = CubeAddress.INVALID_ADDRESS;
		nbrState.state = Type.CONN_NBR_EXT_OFFER;
		new CubeMessage(none, none, nbrState.state, null).send(nbrState.nbrChan);
		try
		{
			listener.register(nbrState.nbrChan);
		} catch (IOException e)
		{
			nbrState.state = Type.CONN_NBR_ANN_DISCONNECTED;
			unicastSend(new CubeMessage(cubeState.addr, nbrState.annAddr, nbrState.state, null));
			return;
		}
	}

	/**
	 * Client must respond to neighbor's offer to connect.
	 * 
	 * Algorithm: respond whether we're willing to accept the connection
	 */
	private void conn_nbr_ext_offer(CubeMessage msg)
	{
		// // Validate the message
		// validateInt(msg);
		// if (!chan.isOpen())
		// return;
		//
		// // Validate the source and destination
		// if (!msg.getSrc().equals(none))
		// {
		// // Serious problems: the NBR's protocol engine has a security breach
		// new CubeMessage(none, none, Type.INVALID_ADDRESS, msg.getSrc()).send(msg.getChannel());
		// return;
		// } else if (!msg.getDst().equals(none))
		// {
		// // Moderate problems: the NBR's protocol engine is confused
		// new CubeMessage(none, none, Type.INVALID_ADDRESS, msg.getDst()).send(msg.getChannel());
		// return;
		// }

		// Are we willing to make this connection?
		SocketChannel chan = msg.getChannel();
		InetSocketAddress addr = quietAddr(chan);
		CubeAddress none = CubeAddress.INVALID_ADDRESS;
		if (amWilling(addr))
		{
			// ACK the neighbor without changing state
			new CubeMessage(cubeState.addr, none, Type.CONN_EXT_NBR_ACCEPT, null).send(chan);
		} else
		{
			// Close existing channels and wait for new ANN to contact me to try again
			CxnState cltState = cxnStates.values().iterator().next();
			cltState.state = Type.CONN_EXT_NBR_DECLINE;
			new CubeMessage(cubeState.addr, none, cltState.state, null).send(chan);
			for (SocketChannel c : cubeState.neighbors)
				quietClose(c);
			cubeState.neighbors = new Vector<>();
			cltState.state = Type.CONN_EXT_INN_ATTACH;
		}
	}

	/**
	 * Neighbor must respond to client acknowledging connection.
	 * 
	 * Algorithm: report success to ANN if the CLT's CubeAddress looks good; otherwise, report failure
	 */
	private void conn_ext_nbr_accept(CubeMessage msg)
	{
		// // Validate the message
		// validateExt(msg, nbrStates);
		// if (!chan.isOpen())
		// return;
		// NbrState nbrState = nbrStates.get(addr);

		SocketChannel chan = msg.getChannel();
		InetSocketAddress addr = quietAddr(chan);
		CxnState nbrState = cxnStates.get(addr);

		// Determine which link this client will be on
		CubeAddress peerAddr = msg.getSrc();
		int link = cubeState.addr.relativeLink(peerAddr);
		if (-1 == link)
		{
			// The ANN gave the client a CubeAddress that isn't our neighbor, so bail
			nbrState.state = Type.CONN_NBR_ANN_DISCONNECTED;
			unicastSend(new CubeMessage(cubeState.addr, nbrState.annAddr, nbrState.state, addr));
			return;
		}

		// Set up my neighbor information and Cube state
		nbrState.peerAddr = peerAddr;

		// Update the ANN
		nbrState.state = Type.CONN_NBR_ANN_CONNECTED;
		unicastSend(new CubeMessage(cubeState.addr, nbrState.annAddr, nbrState.state, addr));
	}

	/**
	 * Neighbor must respond to client declining connection.
	 * 
	 * Algorithm: close the connection and report failure to the ANN
	 */
	private void conn_ext_nbr_decline(CubeMessage msg)
	{
		// No need to check anything, since all paths lead to...
		SocketChannel chan = msg.getChannel();
		InetSocketAddress addr = quietAddr(chan);
		quietClose(chan);
		CxnState state = cxnStates.remove(addr);
		unicastSend(new CubeMessage(cubeState.addr, state.annAddr, Type.CONN_NBR_ANN_DISCONNECTED, addr));
	}

	/**
	 * ANN must respond to neighbor notice of successful client connection. This method is the entry point to Phase 4.
	 * 
	 * Algorithm: record this fact, and if all neighbors have reported in, instruct them to advertise their
	 * CubeAddresses
	 */
	private void conn_nbr_ann_connected(CubeMessage msg)
	{
		// // Validate the message
		// InetSocketAddress addr = (InetSocketAddress) validateMsg(msg, annStates);
		// if (null == addr)
		// return;
		//
		// // Authenticate the source
		// ANNState annState = annStates.get(addr);
		// if (2 != cubeState.addr.xor(msg.getSrc()).bitCount() || -1 == annState.peerAddr.relativeLink(msg.getSrc()))
		// {
		// reply(msg, Type.INVALID_MSG, msg.getType());
		// return;
		// }

		InetSocketAddress addr = (InetSocketAddress) msg.getData();
		CxnState annState = cxnStates.get(addr);

		// Record the success and check for Phase 4
		if (++annState.replies + annState.invalid.bitCount() < cubeState.getDim())
			return;

		// Enter Phase 4
		annState.replies = 1;
		annState.state = Type.CONN_ANN_NBR_IDENTIFY;
		annBcast(annState, addr);

		annState.peerAddr = annState.peerAddr;
		annState.state = Type.CONN_NBR_EXT_IDENTIFY;
		new CubeMessage(cubeState.addr, annState.peerAddr, annState.state, null);
	}

	/**
	 * ANN must respond to neighbor indication of failed SocketChannel to client.
	 * 
	 * Algorithm: instruct all neighbors to tear down their connections, and inform client and INN
	 */
	private void conn_nbr_ann_disconnected(CubeMessage msg)
	{
		// // Validate the message
		// InetSocketAddress addr = (InetSocketAddress) validateMsg(msg, annStates);
		// if (null == addr)
		// return;
		//
		// // Authenticate the source
		// ANNState annState = annStates.get(addr);
		// if (2 != cubeState.addr.xor(msg.getSrc()).bitCount() || -1 == annState.peerAddr.relativeLink(msg.getSrc()))
		// {
		// reply(msg, Type.INVALID_MSG, msg.getType());
		// return;
		// }

		InetSocketAddress addr = (InetSocketAddress) msg.getData();

		// Clean up our state and bail on the client
		CxnState annState = cxnStates.remove(addr);
		int link = cubeState.addr.relativeLink(annState.peerAddr);
		SocketChannel chan = cubeState.neighbors.remove(link);
		annState.state = Type.CONN_ANN_EXT_FAIL;
		new CubeMessage(CubeAddress.INVALID_ADDRESS, annState.peerAddr, annState.state, null).send(chan);
		quietClose(chan);

		// Bail on the neighbors and the INN
		annBail(addr);
	}

	/*
	 * Phase 4 methods
	 */

	/**
	 * Neighbor must respond to ANN instruction to advertise CubeAddress to client.
	 * 
	 * Algorithm: send my CubeAddress to client
	 */
	private void conn_ann_nbr_identify(CubeMessage msg)
	{
		// // Validate the message
		// InetSocketAddress addr = (InetSocketAddress) validateMsg(msg, nbrStates);
		// if (null == addr)
		// return;
		//
		// // Authenticate the source
		// NbrState nbrState = nbrStates.get(addr);
		// if (!nbrState.ann.equals(msg.getSrc()))
		// {
		// reply(msg, Type.INVALID_MSG, msg.getType());
		// return;
		// }

		InetSocketAddress addr = (InetSocketAddress) msg.getData();
		CxnState nbrState = cxnStates.remove(addr);

		// Advertise my CubeAddress
		nbrState.state = Type.CONN_NBR_EXT_IDENTIFY;
		new CubeMessage(cubeState.addr, nbrState.peerAddr, nbrState.state, null).send(nbrState.nbrChan);

		// Inform the ANN (before updating the routing information)
		nbrState.state = Type.CONN_NBR_ANN_IDENTIFIED;
		unicastSend(new CubeMessage(cubeState.addr, nbrState.annAddr, nbrState.state, addr));

		// Update state
		cubeState.addNeighbor(cubeState.addr.relativeLink(nbrState.peerAddr), nbrState.nbrChan);
	}

	/**
	 * Client must respond to neighbor's indication of its CubeAddress
	 * 
	 * Algorithm: add the new neighbor to my Cube state
	 */
	private void conn_nbr_ext_identify(CubeMessage msg)
	{
		// // Validate the message
		// validateInt(msg);
		// if (!chan.isOpen())
		// return;
		//
		// // Source authentication is unnecessary

		CubeAddress nAddr = msg.getSrc();
		SocketChannel chan = msg.getChannel();

		// Is the advertised address actually my neighbor?
		CubeAddress none = CubeAddress.INVALID_ADDRESS;
		int link = cubeState.addr.relativeLink(nAddr);
		if (-1 == link)
		{
			new CubeMessage(cubeState.addr, none, Type.INVALID_DATA, new CubeAddress[] { cubeState.addr, nAddr })
					.send(chan);
			quietClose(chan);
			return;
		}

		// Update the routing information
		cubeState.addNeighbor(link, chan);
	}

	/**
	 * ANN must respond to neighbor indication that its state is correct
	 * 
	 * Algorithm: if all neighbors have reported in, clean up my state and inform the INN of success
	 */
	private void conn_nbr_ann_identified(CubeMessage msg)
	{
		// // Validate the message
		// InetSocketAddress addr = (InetSocketAddress) validateMsg(msg, annStates);
		// if (null == addr)
		// return;
		//
		// // Authenticate the source
		// ANNState annState = annStates.get(addr);
		// if (2 != cubeState.addr.xor(msg.getSrc()).bitCount() || -1 == annState.peerAddr.relativeLink(msg.getSrc()))
		// {
		// reply(msg, Type.INVALID_MSG, msg.getType());
		// return;
		// }

		InetSocketAddress addr = (InetSocketAddress) msg.getData();
		CxnState annState = cxnStates.get(addr);

		// Are we done?
		if (++annState.replies + annState.invalid.bitCount() < cubeState.getDim())
			return;

		// Complete the connection
		new CubeMessage(cubeState.addr, annState.peerAddr, Type.CONN_NBR_EXT_IDENTIFY, null).send(annState.annChan);
		new CubeMessage(cubeState.addr, annState.peerAddr, Type.CONN_ANN_EXT_SUCCESS, null).send(annState.annChan);

		// Inform the INN and clean up state
		cxnStates.remove(addr);
		unicastSend(new CubeMessage(cubeState.addr, annState.innAddr, Type.CONN_ANN_INN_SUCCESS, addr));

		// Update the routing information
		int link = cubeState.addr.relativeLink(annState.peerAddr);
		cubeState.addNeighbor(link, annState.annChan);
	}

	/**
	 * CLT must respond to ANN indication that connection was successful
	 * 
	 * Algorithm: wake up the application blocking on connect()
	 */
	private void conn_ann_ext_success(CubeMessage msg)
	{
		// // Validate the message and authenticate the source
		// validateInt(msg);
		// if (!msg.getChannel().isOpen() || !msg.getChannel().equals(cltState.annChan))
		// return;

		// We are fully connected
		cxnStates.clear();
		if (null != blockingThread)
			synchronized (blockingThread)
			{
				blocking = false;
				blockingThread.notify();
				blockingThread = null;
			}
	}

	/**
	 * INN must respond to an indication of successful address negotiation from an ANN.
	 * 
	 * Algorithm: Close the client SocketChannel
	 */
	private void conn_ann_inn_success(CubeMessage msg)
	{
		// // Validate the message
		// InetSocketAddress addr = (InetSocketAddress) validateMsg(msg, innStates);
		// if (null == addr)
		// return;
		//
		// // Authenticate the source
		// INNState innState = innStates.get(addr);
		// if (!innState.ann.equals(msg.getSrc()))
		// {
		// reply(msg, Type.INVALID_MSG, msg.getType());
		// return;
		// }

		InetSocketAddress addr = (InetSocketAddress) msg.getData();
		CxnState innState = cxnStates.remove(addr);

		// Close the client socket
		quietClose(innState.innChan);

		// Inform the other ANNs that they can flush state
		innState.state = Type.CONN_INN_GEN_CLEANUP;
		while (!innState.able.equals(BigInteger.ZERO))
		{
			int link = innState.able.getLowestSetBit();
			innState.able = innState.able.clearBit(link);
			unicastSend(new CubeMessage(cubeState.addr, new CubeAddress(Integer.toString(link)), innState.state, addr));
		}
	}

	/**
	 * Node that indicated it was able, but was not chosen to be ANN, must respond to INN indication that a different
	 * ANN successfully attached the client.
	 * 
	 * Algorithm: clean up ANN state
	 */
	private void conn_inn_gen_cleanup(CubeMessage msg)
	{
		// // Validate the message
		// InetSocketAddress addr = (InetSocketAddress) validateMsg(msg, null);
		// if (null == addr)
		// return;
		//
		// // Authenticate the source
		// ANNState annState = annStates.get(addr);
		// if (!annState.inn.equals(msg.getSrc()))
		// {
		// reply(msg, Type.INVALID_MSG, msg.getType());
		// return;
		// }

		// Clean up
		InetSocketAddress addr = (InetSocketAddress) msg.getData();
		cxnStates.remove(addr);
	}

	/*
	 * Multi-phase methods
	 */

	/**
	 * Client must respond to denied Cube connection.
	 * 
	 * Algorithm: reset connection state
	 */
	private void conn_inn_ext_conn_refused(CubeMessage msg)
	{
		System.err.println("Connection refused, exiting...");
		System.exit(1);
	}

	/**
	 * Client must respond to ANN indication that a failure occurred.
	 * 
	 * Algorithm: clean up connection state
	 */
	private void conn_ann_ext_fail(CubeMessage msg)
	{
		if (cxnStates.isEmpty())
			return;

		// Don't close the INN connection, but do close all neighbor connections
		for (SocketChannel chan : cubeState.neighbors)
			quietClose(chan);
	}

	/**
	 * Neighbor must respond to ANN indication that a failure occurred.
	 * 
	 * Algorithm: clean up connection state
	 */
	private void conn_ann_nbr_fail(CubeMessage msg)
	{
		// // Validate the message
		// InetSocketAddress addr = (InetSocketAddress) validateMsg(msg, null);
		// if (null == addr)
		// return;
		//
		// // Authenticate the source
		// NbrState nbrState = nbrStates.get(addr);
		// if (null == nbrState || !nbrState.ann.equals(msg.getSrc()))
		// return;

		InetSocketAddress addr = (InetSocketAddress) msg.getData();
		CxnState nbrState = cxnStates.remove(addr);

		// It's valid, shut everything down
		if (nbrState.nbrChan.isOpen())
			quietClose(nbrState.nbrChan);
	}

	/**
	 * INN must respond to ANN indication that a failure occurred.
	 * 
	 * Algorithm: ask a different node at the same hop count to be ANN; if none remain, increase the hop count
	 */
	private void conn_ann_inn_fail(CubeMessage msg)
	{
		// // Validate the message
		// InetSocketAddress addr = (InetSocketAddress) validateMsg(msg, innStates);
		// if (null == addr)
		// return;
		//
		// // Authenticate the source
		// INNState innState = innStates.get(addr);
		// if (!innState.ann.equals(msg.getSrc()))
		// {
		// reply(msg, Type.INVALID_MSG, msg.getType());
		// return;
		// }

		// Find another ANN
		InetSocketAddress addr = (InetSocketAddress) msg.getData();
		handoff(addr);
	}

	/*
	 * Utility methods
	 */
	private void quietClose(SocketChannel chan)
	{
		try
		{
			chan.close();
		} catch (IOException e)
		{
			// Fail silently
		}
	}

	private InetSocketAddress quietAddr(SocketChannel chan)
	{
		try
		{
			return (InetSocketAddress) chan.getRemoteAddress();
		} catch (IOException e)
		{
			// The channel isn't connected
			return null;
		}
	}

	/**
	 * Node must respond to sending an invalid address, depending on protocol state.
	 */
	private void invalid_address(CubeMessage msg)
	{
		Serializable[] data = (Serializable[]) msg.getData();
		Type origType = (Type) data[0];

		// Process based on our type
		if (origType == Type.DATA_MSG)
		{
			// Queue an "invalid" message -- only the source address and data will be visible to applications
			queued.add(new CubeMessage(CubeAddress.INVALID_ADDRESS, msg.getDst(), Type.INVALID_MSG, msg.getSrc()));
			if (blocking)
				synchronized (blockingThread)
				{
					blocking = false;
					blockingThread.notify();
				}
			return;
		}

		// No idea how we got here...
		System.err.println("Got an invalid address...");
	}

	// Phases 2-4: Send a message to all prospective neighbors
	private void annBcast(CxnState annState, InetSocketAddress addr)
	{
		for (int i = 0; i < cubeState.getDim(); ++i)
		{
			// Determine each node's CubeAddress
			CubeAddress nbrAddr = annState.peerAddr.followLink(i);
			if (cubeState.addr.equals(nbrAddr) || annState.invalid.testBit(nbrAddr.intValue()))
				continue;

			// Send the message
			unicastSend(new CubeMessage(cubeState.addr, nbrAddr, annState.state, addr));
		}
	}

	// Phases 2-4: Notify everyone if an ANN determines that a connection cannot be made
	private void annBail(InetSocketAddress addr)
	{
		CxnState annState = cxnStates.remove(addr);

		// Inform the neighbors
		annState.state = Type.CONN_ANN_NBR_FAIL;
		annBcast(annState, addr);

		// Inform the INN
		annState.state = Type.CONN_ANN_INN_FAIL;
		unicastSend(new CubeMessage(cubeState.addr, annState.innAddr, annState.state, addr));
	}

	/*
	 * Messages exchanged post-connection
	 */

	/**
	 * Client must respond to received data message.
	 * 
	 * Algorithm: add the message to my local received message queue
	 */
	private void data_msg(CubeMessage msg)
	{
		/*
		 * Lazily update Cube dimension. Worst case scenario: a neighbor maliciously sends forged CubeMessages having
		 * ever-increasing source addresses. In this case, the neighbor will become able to support many new
		 * connections.
		 */
		int len = msg.getSrc().bitLength();
		if (len == cubeState.getDim() + 1)
			cubeState.setDim(len);

		// Add this message to my queue
		queued.add(msg);
		if (blocking)
			synchronized (blockingThread)
			{
				blocking = false;
				blockingThread.notify();
			}
	}

	private void node_shutdown(CubeMessage msg)
	{
		// TODO

	}

	/**
	 * Clean up state when a peer closes its connection to us. The primary function is to update the neighbors and
	 * links.
	 * 
	 * @param chan
	 */
	void closedCxn(SocketChannel chan)
	{
		// Locate the channel that went down
		int link = cubeState.neighbors.indexOf(chan);
		if (-1 == link)
		{
			// This should never happen
			System.err.println("closedCxn() called on non-connected channel!");
			return;
		}

		// Clean up state
		cubeState.neighbors.set(link, null);
		cubeState.links = cubeState.links.clearBit(link);
		neighborDisconnected(link);
	}

	/*
	 * Protected and public methods
	 */

	/**
	 * Determine whether I am willing to allow a connection from a given address.
	 * 
	 * @param addr
	 *            The {@link InetSocketAddress} of the peer that wishes to connect
	 * @return Whether I am willing to permit the connection
	 */
	protected boolean amWilling(InetSocketAddress addr)
	{
		return true;
	}

	/**
	 * Take an action when I receive an indication that a neighbor disconnected.
	 * 
	 * @param link
	 *            The link number of the disconnected neighbor
	 */
	protected void neighborDisconnected(int link)
	{
	}

	/**
	 * Connect to a Cube. Prior to calling this method, the client application is expected to have determined the
	 * address of an Ingress Negotiation Node (INN) that is offering to connect clients to the Cube of interest.
	 * 
	 * @param innAddr
	 *            The address of an INN
	 * @throws CubeException
	 *             if the argument is <code>null</code>, or if a connection to the INN cannot be established
	 */
	public void connect(InetSocketAddress innAddr) throws CubeException
	{
		// Sanity checks
		if (null == innAddr)
			throw new CubeException("connect() called with null INN address");

		// Initialize client connection state
		CxnState cltState = new CxnState();
		cxnStates.put(innAddr, cltState); // the key is irrelevant
		try
		{
			cltState.innChan = SocketChannel.open(innAddr);
		} catch (IOException e)
		{
			throw new CubeException("connect() unable to open a SocketChannel to " + innAddr);
		}
		cltState.state = Type.CONN_EXT_INN_ATTACH;

		// Send the ATTACH message
		new CubeMessage(CubeAddress.INVALID_ADDRESS, CubeAddress.INVALID_ADDRESS, cltState.state, listener.getAddress())
				.send(cltState.innChan);
		try
		{
			listener.register(cltState.innChan);
		} catch (IOException e)
		{
			throw new CubeException("connect() unable to register the connection to " + innAddr);
		}

		// Wait until we're done connecting to return
		blocking = true;
		blockingThread = Thread.currentThread();
		synchronized (blockingThread)
		{
			while (blocking)
				try
				{
					blockingThread.wait();
				} catch (InterruptedException e)
				{
				}
		}
		blockingThread = null;
	}

	/**
	 * Obtain the dimension of the Cube.
	 * 
	 * @return The dimension
	 */
	public int getDimension()
	{
		return cubeState.getDim();
	}

	/**
	 * Obtain my {@link CubeAddress}.
	 * 
	 * @return The <code>CubeAddress</code>
	 */
	public CubeAddress getCubeAddress()
	{
		return cubeState.addr;
	}

	/**
	 * Obtain the {@link InetSocketAddress} of each directly connected Cube node.
	 * 
	 * @return A {@link Vector} of the addresses
	 */
	public Vector<InetSocketAddress> getNeighbors()
	{
		Vector<InetSocketAddress> ret = new Vector<>();
		for (SocketChannel chan : cubeState.neighbors)
			try
			{
				ret.addElement((InetSocketAddress) chan.getRemoteAddress());
			} catch (IOException e)
			{
			}
		return ret;
	}

	/**
	 * <p>
	 * Send a {@link Message} to another node in the Cube, without blocking. Note that delivery of messages to other
	 * Cube nodes is not guaranteed by the Cube protocol itself.
	 * </p>
	 * <p>
	 * This method will return <code>true</code> when the <code>Message</code> was accepted by the Cube for delivery. If
	 * the {@link CubeAddress} of the <code>Message</code> refers to a non-connected node, the Cube will return a
	 * <code>Message</code> having its <code>peer</code> field set to {@link CubeAddress.INVALID_ADDRESS} and its
	 * <code>data</code> field set to the address of the non-connected node.
	 * </p>
	 * 
	 * @param msg
	 *            The <code>Message</code> to send
	 * @return whether the <code>Message</code> was sent asynchronously into the Cube
	 * @throws CubeException
	 *             if the <code>Message</code> does not specify a proper {@link CubeAddress}
	 */
	public boolean send(Message msg) throws CubeException
	{
		// Check for idiocy
		if (null == cubeState)
			throw new CubeException("send() called on unconnected Cube");
		if (null == msg.peer)
			throw new CubeException("send() called with null peer CubeAddress");
		if (BigInteger.ZERO.compareTo(msg.peer) > 0)
			throw new CubeException("send() called with invalid (negative) peer CubeAddress");

		// Send the message
		return unicastSend(new CubeMessage(cubeState.addr, msg.peer, Type.DATA_MSG, msg.data));
	}

	/*
	 * Send a message through the Cube using Katseff Algorithm 3 (with LSB instead of MSB ordering). Invoking this
	 * method cannot divulge confidential address information to a non-connected node; at worst, using this method as a
	 * response to a forged request will send a bogus message to another connected node, which will reply with
	 * INVALID_STATE.
	 */
	private boolean unicastSend(CubeMessage msg)
	{
		// Check for idiocy and/or forged messages
		if (msg.getDst().bitLength() > cubeState.getDim())
		{
			// Tried to send a message to a node outside the address space
			unicastSend(new CubeMessage(msg.getDst(), msg.getSrc(), Type.INVALID_ADDRESS,
					new Serializable[] { msg.getType(), msg.getData() }));
			return false;
		}

		if (cubeState.addr.equals(msg.getDst()))
		{
			// Loop back
			process(msg);
			return true;
		} else
		{
			int link = cubeState.addr.xor(msg.getDst()).and(cubeState.links).getLowestSetBit();
			if (-1 == link)
			{
				// Tried to send a message to a non-connected node
				unicastSend(new CubeMessage(msg.getDst(), msg.getSrc(), Type.INVALID_ADDRESS,
						new Serializable[] { msg.getType(), msg.getData() }));
				return false;
			}
			return msg.send(cubeState.neighbors.get(link));
		}
	}

	// Reply to a message with a new message type and data
	private void reply(CubeMessage request, Type type, Serializable data)
	{
		unicastSend(new CubeMessage(cubeState.addr, request.getSrc(), type, data));
	}

	/**
	 * Convenience method for replying to a received {@link Message}.
	 * 
	 * @param msg
	 *            The received <code>Message</code>
	 * @param data
	 *            The {@link Serializable} response
	 * @throws CubeException
	 *             if the <code>Message</code> does not specify a proper {@link CubeAddress}
	 */
	public void reply(Message msg, Serializable data) throws CubeException
	{
		// Check for idiocy
		if (null == cubeState)
			throw new CubeException("reply() called on unconnected Cube");
		if (null == msg.peer)
			throw new CubeException("reply() called with null peer CubeAddress");
		if (BigInteger.ZERO.compareTo(msg.peer) > 0)
			throw new CubeException("reply() called with invalid (negative) peer CubeAddress");

		unicastSend(new CubeMessage(cubeState.addr, msg.peer, Type.DATA_MSG, data));
	}

	/**
	 * Broadcasts {@link Serializable} data through the Cube. This function is efficient, in that each Cube node
	 * receives a copy of the data exactly once.
	 * 
	 * @param data
	 *            A {@link Serializable} object to broadcast
	 * @return Whether the broadcast message was successfully broadcast
	 * @throws CubeException
	 *             if no Cube is connected
	 */
	public boolean broadcast(Serializable data) throws CubeException
	{
		if (null == cubeState)
			throw new CubeException("broadcast() called on unconnected Cube");

		CubeMessage bcastMsg = new CubeMessage(cubeState.addr, CubeAddress.BCAST_PROCESS, Type.DATA_MSG, data,
				cubeState.getDim());
		return bcastSend(bcastMsg);
	}

	/*
	 * Forward a broadcast message through the Cube using Katseff Algorithm 6. Returns whether the message was forwarded
	 * successfully (which should always be true, since we gracefully handle neighbor SocketChannel closures).
	 */
	private boolean bcastSend(CubeMessage msg)
	{
		// Initial message validation
		BigInteger travel = msg.getTravel();
		if (null == travel)
			return false;

		// Initialize newtravel by adding all non-connected links
		BigInteger newtravel = travel.or(cubeState.links.not().abs()).clearBit(cubeState.getDim());

		// Loop over all links, from most significant to least, turning off bits in newtravel as we go
		for (int link = cubeState.getDim() - 1; link >= 0; --link)
		{
			// Turn off the bit for this link in newtravel if we are connected along it
			if (cubeState.links.testBit(link))
				newtravel = newtravel.clearBit(link);

			// Only send messages on links that we should travel and are connected
			if (!travel.testBit(link) || !cubeState.links.testBit(link))
				continue;

			// Send the message directly
			msg.setTravel(newtravel);
			if (false == msg.send(cubeState.neighbors.get(link)))
				return false;
		}

		// If we got here, we were successful
		return true;
	}

	/**
	 * Indicate whether a {@link Message} is available to be read.
	 * 
	 * @return whether a <code>Message</code> is available to be read
	 */
	public boolean available()
	{
		return !queued.isEmpty();
	}

	/**
	 * Perform a non-blocking wait for an incoming {@link Message}, then return it.
	 * 
	 * @return A waiting <code>Message</code>, if any; otherwise, null
	 * @throws CubeException
	 *             if no Cube is connected
	 */
	public Message recvNow() throws CubeException
	{
		if (null == cubeState)
			throw new CubeException("recvNow() called on unconnected Cube");

		if (queued.isEmpty())
			return null;
		CubeMessage msg = queued.remove(0);
		return new Message(msg.getSrc(), msg.getData());
	}

	/**
	 * Perform a blocking wait for an incoming {@link Message}, then return it.
	 * 
	 * @return The received <code>Message</code>
	 * @throws CubeException
	 *             if no Cube is connected
	 */
	public Message recv() throws CubeException
	{
		if (null == cubeState)
			throw new CubeException("recvNow() called on unconnected Cube");

		CubeMessage msg = null;
		if (!queued.isEmpty())
		{
			msg = queued.remove(0);
			return new Message(msg.getSrc(), msg.getData());
		}

		/*
		 * Wait until a message is received. Note that this method is called by a client application, not the
		 * MessageListener, so it won't block the protocol
		 */
		blocking = true;
		blockingThread = Thread.currentThread();
		while (blocking)
			synchronized (blockingThread)
			{
				try
				{
					blockingThread.wait();
				} catch (InterruptedException e)
				{
				}
			}
		blockingThread = null;
		msg = queued.remove(0);
		return new Message(msg.getSrc(), msg.getData());
	}

	/**
	 * Shut down a {@link CubeProtocol}. This method invalidates all Cube state, and shuts down the associated
	 * {@link MessageListener} as well.
	 */
	public void shutdown()
	{
		// Terminate neighbor connections
		listener.shutdown();
	}
}
