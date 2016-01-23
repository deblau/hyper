package hyper;

import hyper.CubeMessage.Type;

import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.channels.SocketChannel;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

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
 * The Cube protocol uses Katseff's Algorithm 3 for routing, and Algorithm 6 for broadcast messaging.
 * </p>
 * 
 * <p>
 * There is one major function provided by the protocol that requires many different types of messages to be passed:
 * connecting new clients to the Cube. The chief concern in this area of the protocol is maintaining the anonymity of
 * the link between an {@link InetAddress} and a {@link CubeAddress}. Obviously, each Cube must provide one or more
 * Ingress Negotiation Nodes (INNs) that act as gateways for the connection process, and the <code>InetAddress</code> of
 * each of these INNs must be discoverable outside the protocol. The discovery process for INNs is outside the scope of
 * this protocol; Cube communities may develop their own standards. However, the protocol nevertheless shields the
 * revelation of any <code>CubeAddress</code> to a connecting client until the last possible moment, after it has been
 * approved to join the Cube.
 * </p>
 * 
 * <p>
 * The connection process operates in five phases. In the first phase, the INN locates an attachment point for an
 * external client that wishes to join. This attachment node takes over the remainder of the process as an Address
 * Negotiation Node (ANN). In the second phase, the ANN confirms that attachment is acceptable to all of the would-be
 * new neighbors. In the third phase, the ANN offers the external client a CubeAddress using a direct connection (i.e.,
 * outside the normal Cube message passing algorithm), without revealing its own address or that of any of the would-be
 * neighbors. In the fourth phase, the ANN instructs the neighbors to connect to the client (again, without revealing
 * any of their Cube addresses) and verify that all (TCP/IP) connections are solid. In the fifth phase, the ANN
 * instructs the neighbor nodes to reveal their addresses to the client via direct connection, completing the Cube
 * connection. If any of Phases 2 through 5 fail, the ANN informs the INN, which resumes the search for a working ANN.
 * If no ANN can be found, the INN informs the client that the connection was denied.
 * </p>
 * 
 * <p>
 * The details of these processes follow. Message types referenced below are found in the {@link CubeMessage.Type} inner
 * class. Messages for protocol connections are named in four parts. The first part is <code>CONN</code>, signifying
 * their purpose. The second and third parts indicate the role of the clients respectively sending and receiving the
 * message: <code>EXT</code> for the external client, <code>INN</code> for the Ingress Negotiation Node,
 * <code>GEN</code> for a generic Cube node, <code>ANN</code> for the Address Negotiation Node, and <code>NBR</code> for
 * a potential neighbor node. The fourth part is the purpose of the message.
 * </p>
 * 
 * <h4>Phase 1: Locating possible attachment point</h4>
 * <p>
 * The first phase has the goal of locating an attachment point for a new node, and is executed by the INN in response
 * to receiving a <code>CONN_EXT_INN_ATTACH</code> message from an external client. The INN broadcasts, to other nodes
 * in the Cube, a <code>CONN_INN_GEN_ANN</code> request with the client's information, asking for any nodes that are
 * both able to accept the connection (because they have a vacancy in their connectivity table) and are willing to
 * accept the connection (based on client information, currently an {@link InetSocketAddress} of the client). This is
 * done by sending broadcast messages having successively increasing hop counts, until at least one other node accepts
 * the request. The INN designates this node as the address negotiating node (ANN), and hands off the remainder of the
 * process to the ANN using a <code>CONN_INN_ANN_HANDOFF</code> message (while cachine other possible attachment points
 * at the given hop count). Because address negotiation can fail, the ANN must reply with a success-or-fail status to
 * the INN. If the negotiation of Phases 2 through 5 succeeds as indicated by a <code>CONN_ANN_INN_SUCCESS</code>
 * message, the INN can terminate its participation in the addressing protocol. However if the negotiation fails (see
 * discussion below), the INN continues searching using the ANN cache.
 * </p>
 * 
 * <p>
 * An ANN may only connect the client if the client's prospective neighbors are all willing and able to connect to the
 * new client. Willingness to connect is a potentially serious issue; for example, a node may wish to maintain a
 * blacklist of IP addresses or blocks that are denied connections due to political or network routing efficiency
 * concerns. Therefore, the protocol guarantees that no Cube member shall be required to connect to any client for which
 * it signals an unwillingness to do so. This guarantee is implemented by having each ANN declare to the INN a failure
 * to connect the new client due to unwillingness of any of its potential neighbor nodes by sending a
 * <code>CONN_ANN_INN_UNWILLING</code> message if its {@link #amWilling(InetSocketAddress)} function returns
 * <code>false</code>.
 * </p>
 * 
 * <p>
 * However, ability to connect (that is, whether a node has a slot for connecting to another node) is an issue of Cube
 * topology, which is easily fixed within the protocol. An INN determines whether it can place a new client in the
 * Cube's address space by calling {@link #check_expand(InetSocketAddress)}. If the various heuristics used indicate
 * that expansion is warranted, this function instructs a randomly selected ANN, that indicated only an inability to
 * attach the new client via a <code>CONN_ANN_INN_UNABLE</code> message, to attach it anyway using a higher Cube
 * dimension. The protocol allows the INN to select itself as the attachment node (after passing its own willingness
 * check).
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
 * <h4>Phase 2: Confirming the attachment point</h4>
 * <p>
 * The second phase of the connection protocol is carried out by the ANN to find an acceptable {@link CubeAddress} for
 * the new node. The ANN first selects a vacant, neighbor <code>CubeAddress</code> as the possible address of the new
 * client. (Such an address exists, since either the ANN indicated ability to connect or the dimension of the Cube is
 * increasing.) The ANN then sends <code>CONN_ANN_NBR_REQ</code> messages to each neighbor of the possible address,
 * asking only for willingness to connect. (With a little multi-dimensional thought, it can be seen that each such
 * neighbor already is able to connect the new address.) During this process, each willing neighbor transmits a random
 * nonce to the ANN via <code>CONN_NBR_ANN_ACK</code>, used in Phase 4 for authentication. If any prospective neighbor
 * signals its unwillingness via <code>CONN_NBR_ANN_NAK</code>, the ANN chooses another <code>CubeAddress</code> for the
 * peer, and tries again. If all such addresses have at least one unwilling neighbor, the ANN relays that information to
 * the INN via <code>CONN_ANN_INN_FAIL</code> and Phase 2 terminates unsuccessfully for the ANN.
 * </p>
 * 
 * <p>
 * <b>Address security analysis</b>: The ANN knows the {@link InetSocketAddress} of the peer, and selects its potential
 * new {@link CubeAddress}, however this is not a security threat because the ANN will be a neighbor to the peer, and
 * therefore must know this relationship anyway. The same can be said for each prospective new neighbor.
 * </p>
 * 
 * <p>
 * The relaying node between the ANN and each prospective new neighbor can determine the relationship based on traffic
 * analysis, provided all messages between the pairs pass through it. To prevent this, <code>CONN_ANN_NBR_REQ</code>
 * messages are sent along a non-shortest-path route; <code>CONN_NBR_ANN_ACK</code> and <code>CONN_NBR_ANN_ACK</code>
 * replies follow the shortest-path route, thereby foiling this attack.
 * </p>
 * 
 * <h4>Phase 3: Offering a CubeAddress to the client</h4>
 * <p>
 * The ANN notifies the new client of the client's new <code>CubeAddress</code> and the list of nonces from its new
 * neighbors via <code>CONN_ANN_EXT_OFFER</code>. This is done without revealing the ANN's <code>CubeAddress</code>,
 * because the client cannot yet be trusted with that information. It is also done without revealing an association
 * between each nonce and a corresponding Cube node.
 * </p>
 * 
 * <p>
 * The client may express its own unwillingness to connect to the ANN via <code>CONN_EXT_ANN_NAK</code>. In this case,
 * the ANN communicates the address negotiation failure to the neighbors (via <code>CONN_ANN_NBR_FAIL</code>) and the
 * INN (via <code>CONN_ANN_INN_FAIL</code>). Otherwise, the client acknowledges the address and the nonces using a
 * <code>CONN_EXT_ANN_ACK</code> message. If so, the ANN communicates this fact to each of the new neighbors via
 * <code>CONN_ANN_NBR_SUCCESS</code>, and proceeds to Phase 4.
 * 
 * <p>
 * <b>Address security analysis</b>: Phase 3 communications within the Cube do not contain the {@link CubeAddress} of
 * the client, and communications outside the Cube do not contain the {@link CubeAddress} of any Cube node.
 * </p>
 * 
 * <h4>Phase 4: Neighbors all connect without revealing their CubeAddresses</h4>
 * <p>
 * Each neighbor sends to the client, by direct connection outside the node, a <code>CONN_NBR_EXT_OFFER</code> message
 * containing no data. In response, the new client must reply with a <code>CONN_EXT_NBR_ACK</code> message containing
 * both its new <code>CubeAddress</code> and the entire set of nonces. (It can, of course, be unwilling to connect, and
 * send a <code>CONN_EXT_NBR_NAK</code>.) Each neighbor verifies that (1) the new <code>CubeAddress</code> is a valid
 * neighbor, and (2) the list of nonces has length equal to the current dimension of the Cube and contains the nonce
 * generated by the neighbor itself. The neighbor reports success or failure of the verification to the ANN via
 * <code>CONN_NBR_ANN_SUCCESS</code> and <code>CONN_NBR_ANN_FAIL</code> messages.
 * </p>
 * 
 * <p>
 * If the ANN gets even a single failure, it shuts down the negotiation by sending a <code>CONN_ANN_NBR_NADV</code>
 * message, informing each of them not to advertise its <code>CubeAddress</code> to the client. The ANN then informs the
 * INN of the failure. However, if all neighbors report success, the connection is assured and the protocol proceeds to
 * the final phase.
 * </p>
 * 
 * <p>
 * <b>Address security analysis</b>: Phase 4 communications within the Cube do not contain the {@link CubeAddress} of
 * the client, and communications outside the Cube do not contain the {@link CubeAddress} of any Cube node.
 * </p>
 * 
 * <h4>Phase 5: CubeAddress advertisement</h4>
 * <p>
 * Once the ANN concludes that all neighbor connections were successful, each of the new neighbors provides the client
 * with its {@link CubeAddress} via <code>CONN_NBR_EXT_ACK</code>. The ANN goes first, then instructs the neighbors that
 * it is safe for them to provide their addresses as well, all via <code>CONN_ANN_NBR_ADV</code> messages. The ANN also
 * transmits <code>CONN_ANN_INN_SUCCESS</code> to the INN, to permit the INN to clean up its own ingress state.
 * </p>
 * 
 * <p>
 * <b>Address security analysis</b>: Phase 5 communications within the Cube do not contain the {@link CubeAddress} of
 * the client, and communications outside the Cube do not contain the {@link CubeAddress} of any Cube node.
 * </p>
 * 
 * <h3>Classes used in the protocol</h3>
 * <p>
 * Because the messages themselves are stateless, each node must keep track of state pertaining to each of its roles.
 * During the connection process, some nodes may have several roles simultaneously; for example, when the Cube is first
 * starting, Node 0 is an INN, ANN, and NBR for the first new client, all at the same time. State-keeping classes are
 * package-private, and named for the particular state being kept. For example, the {@link INNState} class keeps track
 * of the INN state, and so on.
 * </p>
 */
public class CubeProtocol
{
	// Cube state
	private CubeState cubeState = new CubeState();

	// INN states
	private HashMap<InetSocketAddress, INNState> innStates = new HashMap<>();
	private ArrayList<CubeMessage.Type> phase1INNstates = new ArrayList<>();

	// ANN states
	private HashMap<InetSocketAddress, ANNState> annStates = new HashMap<>();
	private ArrayList<CubeMessage.Type> phase1ANNstates = new ArrayList<>();
	private ArrayList<CubeMessage.Type> phase2ANNstates = new ArrayList<>();
	private ArrayList<CubeMessage.Type> phase3ANNstates = new ArrayList<>();
	private ArrayList<CubeMessage.Type> phase4ANNstates = new ArrayList<>();

	// NBR states
	private HashMap<InetSocketAddress, NbrState> nbrStates = new HashMap<>();
	private ArrayList<CubeMessage.Type> phase4NBRstates = new ArrayList<>();

	// CLT state
	private CltState cltState;
	private ArrayList<CubeMessage.Type> phase3CLTstates = new ArrayList<>();
	private ArrayList<CubeMessage.Type> phase4CLTstates = new ArrayList<>();

	// Our MessageListener
	private MessageListener listener;

	// Local message queuing
	private ArrayList<CubeMessage> queued = new ArrayList<>();
	Thread blockingRecv = null;
	boolean blocked = false;

	CubeState getCubeState()
	{
		return cubeState;
	}

	void setListener(MessageListener listener)
	{
		this.listener = listener;
	}

	public CubeProtocol()
	{
		// Set up some validation data
		phase1INNstates.add(CubeMessage.Type.CONN_INN_GEN_ANN);
		phase1INNstates.add(CubeMessage.Type.CONN_INN_ANN_HANDOFF);
		phase1ANNstates.add(CubeMessage.Type.CONN_GEN_INN_ACK);
		phase1ANNstates.add(CubeMessage.Type.CONN_GEN_INN_UNABLE);
		phase2ANNstates.add(CubeMessage.Type.CONN_ANN_NBR_REQ);
		phase3ANNstates.add(CubeMessage.Type.CONN_ANN_EXT_OFFER);
		phase3CLTstates.add(CubeMessage.Type.CONN_EXT_INN_ATTACH);
		phase4ANNstates.add(CubeMessage.Type.CONN_ANN_NBR_SUCCESS);
		phase4NBRstates.add(CubeMessage.Type.CONN_NBR_ANN_ACK);
		phase4CLTstates.add(CubeMessage.Type.CONN_EXT_ANN_ACK);
		phase4CLTstates.add(CubeMessage.Type.CONN_EXT_NBR_ACK);
	}

	/**
	 * Process a {@link CubeMessage} received by the {@link MessageListener} according to the Cube protocol.
	 * 
	 * Documentation about the meaning of each message type can be found in the {@link CubeMessage} class and by
	 * consulting the description of the protocol.
	 * 
	 * @param msg
	 *            the {@link CubeMessage} to process
	 * @throws IOException
	 */
	void process(CubeMessage msg) throws IOException
	{
		System.err.println(Thread.currentThread() + " " + msg);

		// Forward messages that are not meant for me
		CubeAddress dst = msg.getDst();
		if (!CubeMessage.Type.CONN_ANN_EXT_OFFER.equals(msg.getType()) && null != dst)
		{
			if (dst.compareTo(CubeAddress.ZERO_HOPS) < 0)
			{
				fwd_broadcast(msg);
				return;
			} else if (dst.compareTo(CubeAddress.ZERO_HOPS) > 0 && !dst.equals(cubeState.addr))
			{
				send(msg);
				return;
			}
		}

		switch (msg.getType())
		{
		case CONN_ANN_EXT_OFFER:
			conn_ann_ext_offer(msg);
			break;
		case CONN_ANN_EXT_SUCCESS:
			conn_ann_ext_success(msg);
			break;
		case CONN_ANN_INN_SUCCESS:
			conn_ann_inn_success(msg);
			break;
		case CONN_ANN_INN_FAIL:
			conn_ann_inn_fail(msg);
			break;
		case CONN_ANN_NBR_ADV:
			conn_ann_nbr_adv(msg);
			break;
		case CONN_ANN_NBR_FAIL:
			conn_ann_nbr_fail(msg);
			break;
		case CONN_ANN_NBR_NADV:
			conn_ann_nbr_nadv(msg);
			break;
		case CONN_ANN_NBR_REQ:
			conn_ann_nbr_req(msg);
			break;
		case CONN_ANN_NBR_SUCCESS:
			conn_ann_nbr_success(msg);
			break;
		case CONN_EXT_ANN_ACK:
			conn_ext_ann_ack(msg);
			break;
		case CONN_EXT_ANN_NAK:
			conn_ext_ann_nak(msg);
			break;
		case CONN_EXT_INN_ATTACH:
			conn_ext_inn_attach(msg);
			break;
		case CONN_EXT_NBR_ACK:
			conn_ext_nbr_ack(msg);
			break;
		case CONN_EXT_NBR_NAK:
			conn_ext_nbr_nak(msg);
			break;
		case CONN_INN_ANN_HANDOFF:
			conn_inn_ann_handoff(msg);
			break;
		case CONN_INN_EXT_CONN_REFUSED:
			conn_inn_ext_conn_refused(msg);
			break;
		case CONN_INN_GEN_ANN:
			// Broadcast message
			conn_inn_gen_ann(msg);
			break;
		case CONN_NBR_ANN_ACK:
			conn_nbr_ann_ack(msg);
			break;
		case CONN_NBR_ANN_FAIL:
			conn_nbr_ann_fail(msg);
			break;
		case CONN_NBR_ANN_NAK:
			conn_nbr_ann_nak(msg);
			break;
		case CONN_NBR_ANN_SUCCESS:
			conn_nbr_ann_success(msg);
			break;
		case CONN_NBR_EXT_ACK:
			conn_nbr_ext_ack(msg);
			break;
		case CONN_NBR_EXT_OFFER:
			conn_nbr_ext_offer(msg);
			break;
		case CONN_GEN_INN_ACK:
			conn_gen_inn_ack(msg);
			break;
		case CONN_GEN_INN_UNABLE:
			conn_gen_inn_unable(msg);
			break;
		case CONN_GEN_INN_UNWILLING:
			conn_gen_inn_unwilling(msg);
			break;
		case DATA_MSG:
			data_msg(msg);
			break;
		case INVALID_ADDRESS:
			invalid_address(msg);
			break;
		case INVALID_MSG:
			System.err.println(Thread.currentThread() + " received INVALID_MSG: (" + msg.getSrc() + "," + msg.getDst() + ","
					+ msg.getData() + ")");
			break;
		default:
			System.err.println(Thread.currentThread() + " received unknown message type " + msg.getType() + ": (" + msg.getSrc()
					+ "," + msg.getDst() + "," + msg.getData() + ")");
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
	 */
	private void conn_ext_inn_attach(CubeMessage msg) throws IOException
	{
		// TODO authorize this node acting as INN

		// Ensure the message is properly formatted
		SocketChannel chan = msg.getChannel();
		CubeAddress none = CubeAddress.INVALID_ADDRESS;
		if (!checkMsg(msg, none, InetSocketAddress.class))
		{
			new CubeMessage(none, none, CubeMessage.Type.INVALID_MSG, msg.getType()).send(chan);
			chan.close();
			return;
		}
		InetSocketAddress addr = (InetSocketAddress) msg.getData();

		// Ensure my state is correct
		if (innStates.containsKey(addr))
		{
			new CubeMessage(none, none, CubeMessage.Type.INVALID_STATE, new Enum[] { innStates.get(addr).state, msg.getType() })
					.send(chan);
			chan.close();
			return;
		}

		// Edge case: I might be the only node in the Cube
		if (cubeState.dim == 0)
		{
			// Perform a blocking connection attempt, all the way through Phase 5
			node1connect(msg);
			return;
		}

		// Initialize state
		INNState innState = new INNState(chan);
		innStates.put(addr, innState);

		// Edge case: I might have an open slot myself
		if (cubeState.dim > cubeState.neighbors.size() && amWilling(addr))
		{
			// Fake a successful address negotiation
			ANNState annState = new ANNState(cubeState.addr);
			annState.state = CubeMessage.Type.CONN_GEN_INN_ACK;
			annStates.put(addr, annState);

			// Send myself a loop back message designating me as ANN, and enter Phase 2
			innState.state = CubeMessage.Type.CONN_INN_ANN_HANDOFF;
			msg = new CubeMessage(cubeState.addr, cubeState.addr, innState.state, addr);
			process(msg);
			return;
		}

		// Regular processing: initialize state and send the initial broadcast messages
		innState.state = CubeMessage.Type.CONN_INN_GEN_ANN;
		msg = new CubeMessage(cubeState.addr, CubeAddress.ZERO_HOPS, innState.state, addr, cubeState.dim);
		for (Neighbor n : cubeState.neighbors)
			msg.send(n.chan);
	}

	/**
	 * Generic node must respond to INN request to become ANN and connect client.
	 * 
	 * Algorithm: determine whether I am able to connect, then whether I am willing to connect. Because the second
	 * determination is more important, do it first. Reply to the INN with the result.
	 */
	private void conn_inn_gen_ann(CubeMessage msg) throws IOException
	{
		// TODO validate that this message came from a node authorized to be an INN
		// Ensure the message is properly formatted; do not check source (unknown INN, for now)
		if (!checkMsg(msg, null, InetSocketAddress.class))
		{
			reply(msg, CubeMessage.Type.INVALID_MSG, msg.getType());
			return;
		}
		InetSocketAddress addr = (InetSocketAddress) msg.getData();

		// Ensure we are in the correct state
		if (annStates.containsKey(addr))
		{
			reply(msg, CubeMessage.Type.INVALID_STATE, new Enum[] { annStates.get(addr).state, msg.getType() });
			return;
		}

		// Am I willing to connect?
		if (!amWilling(addr))
		{
			reply(msg, CubeMessage.Type.CONN_GEN_INN_UNWILLING, addr);
			return;
		}

		// Create state and reply with ability to connect
		ANNState state = new ANNState(msg.getSrc());
		annStates.put(addr, state);
		if (BigInteger.ZERO.setBit(cubeState.dim).subtract(BigInteger.ONE).equals((BigInteger) cubeState.links))
			state.state = CubeMessage.Type.CONN_GEN_INN_UNABLE;
		else
			state.state = CubeMessage.Type.CONN_GEN_INN_ACK;

		reply(msg, state.state, addr);
	}

	/**
	 * INN must respond to generic node indicating willingness and ability to be ANN.
	 * 
	 * Algorithm: hand off negotiation to generic node to begin Phase 2 (unless already in Phase 2)
	 */
	private void conn_gen_inn_ack(CubeMessage msg) throws IOException
	{
		// Validate the reply message
		InetSocketAddress addr = validateMsg(msg, innStates, phase1INNstates);
		if (null == addr)
			return;
		INNState state = innStates.get(addr);

		// Hand off ANN duties, provided we aren't already using someone else as ANN
		if (state.state == CubeMessage.Type.CONN_INN_GEN_ANN)
		{
			// We're still in Phase 1; enter Phase 2
			state.state = CubeMessage.Type.CONN_INN_ANN_HANDOFF;
			reply(msg, state.state, addr);
		} else
			// We're in Phase 2 somewhere, but add this node to the ANN "possibles" cache
			state.acked.add(msg.getSrc());
	}

	/**
	 * INN must respond to generic node indicating its inability to act as ANN.
	 * 
	 * Algorithm: record this fact, and determine whether to expand the Cube
	 */
	private void conn_gen_inn_unable(CubeMessage msg) throws IOException
	{
		// Validate the reply message
		InetSocketAddress addr = validateMsg(msg, innStates, phase1INNstates);
		if (null == addr)
			return;

		// Add this response to the list of unable nodes
		innStates.get(addr).unable.add(msg.getSrc());

		// If everyone is unable or unwilling, we might have to expand the Cube
		check_expand(addr);
	}

	/**
	 * INN must respond to generic node indicating its unwillingness to act as ANN.
	 * 
	 * Algorithm: record this fact, and determine whether to expand the Cube
	 */
	private void conn_gen_inn_unwilling(CubeMessage msg) throws IOException
	{
		// Validate the reply message
		InetSocketAddress addr = validateMsg(msg, innStates, phase1INNstates);
		if (null == addr)
			return;

		// Add this response to the list of unwilling nodes
		innStates.get(addr).unwilling.add(msg.getSrc());

		// If everyone is unable or unwilling, we might have to expand the Cube
		check_expand(addr);
	}

	/**
	 * ANN must respond to INN instruction to become ANN. This method is the entry point to Phase 2.
	 * 
	 * Algorithm: initialize ANN state and contact prospective neighbors
	 */
	private void conn_inn_ann_handoff(CubeMessage msg) throws IOException
	{
		// Validate the reply message
		InetSocketAddress addr = validateMsg(msg, annStates, phase1ANNstates);
		if (null == addr)
			return;

		// Confirm source address
		ANNState annState = annStates.get(addr);
		if (!annState.inn.equals(msg.getSrc()))
		{
			reply(msg, CubeMessage.Type.INVALID_MSG, msg.getType());
			return;
		}

		// Determine (1) whether this join will expand the Cube, and (2) the new CubeAddress of the client
		boolean isExpanding = cubeState.neighbors.size() == cubeState.dim;
		int link = isExpanding ? cubeState.dim : cubeState.links.not().getLowestSetBit();
		annState.peerAddr = cubeState.addr.followLink(link);

		// Determine whether all of the new peer's neighbors are willing to accept the connection
		annState.state = CubeMessage.Type.CONN_ANN_NBR_REQ;
		annBcast(annState, addr);
	}

	// Check whether we need to expand the dimension of the cube
	private void check_expand(InetSocketAddress clientAddr) throws IOException
	{
		INNState innState = innStates.get(clientAddr);
		int unable = innState.unable.size();
		int unwill = innState.unwilling.size();

		// Have we contacted everyone yet?
		if (innState.hops < cubeState.dim)
		{
			// Nope. Don't increase the hop count unless we've contacted enough cubes
			if (unable + unwill <= 1 << (innState.hops - 1))
				return;

			// Increase the hop count
			++innState.hops;
			CubeAddress hopAddr = new CubeAddress(Integer.toString(-innState.hops));
			CubeMessage msg = new CubeMessage(cubeState.addr, hopAddr, CubeMessage.Type.CONN_INN_GEN_ANN, clientAddr,
					cubeState.dim);
			for (Neighbor n : cubeState.neighbors)
				msg.send(n.chan);
		}

		// Find someone who's willing to take the new guy (including possibly me)
		if (amWilling(clientAddr))
			innState.unable.add(cubeState.addr);
		while (innState.unable.size() > 0)
		{
			int index = (int) (Math.random() * innState.unable.size());
			CubeAddress addr = innState.unable.remove(index);

			// Ensure the index is not adjacent to someone who is unwilling
			for (int i = 0; i < cubeState.dim; ++i)
				if (innState.unwilling.contains(addr.followLink(i)))
					break;

			// I've picked a good node. If it's me, initialize ANN state
			if (addr.equals(cubeState.addr))
			{
				// I chose myself as the ANN; initialize state
				ANNState annState = new ANNState(cubeState.addr);
				annState.state = CubeMessage.Type.CONN_GEN_INN_ACK;
				annStates.put(clientAddr, annState);
			}

			// Enter Phase 2
			send(new CubeMessage(cubeState.addr, addr, CubeMessage.Type.CONN_INN_ANN_HANDOFF, clientAddr));
			return;
		}

		// If we get here, it's impossible to attach to the cube; deny the connection
		CubeAddress none = CubeAddress.INVALID_ADDRESS;
		new CubeMessage(none, none, CubeMessage.Type.CONN_INN_EXT_CONN_REFUSED, null).send(innState.chan);
		innStates.remove(clientAddr).chan.close();
	}

	/*
	 * Phase 2 methods
	 */

	/**
	 * Neighbor must respond to ANN request for willingness to connect.
	 * 
	 * Algorithm: return whether neighbor is willing
	 */
	private void conn_ann_nbr_req(CubeMessage msg) throws IOException
	{
		// Ensure the message is properly formatted
		if (!checkMsg(msg, null, InetSocketAddress.class))
		{
			reply(msg, CubeMessage.Type.INVALID_MSG, msg.getType());
			return;
		}
		InetSocketAddress addr = (InetSocketAddress) msg.getData();

		// Ensure we are in the correct state
		NbrState nbrState = nbrStates.get(addr);
		if (null != nbrState)
		{
			reply(msg, CubeMessage.Type.INVALID_STATE, new Enum[] { nbrState.state, msg.getType() });
			return;
		}

		// Return our willingness
		if (amWilling(addr))
		{
			nbrState = new NbrState(msg.getSrc(), addr);
			nbrState.state = Type.CONN_NBR_ANN_ACK;
			nbrStates.put(addr, nbrState);
			reply(msg, nbrState.state, addr);
		} else
			reply(msg, CubeMessage.Type.CONN_NBR_ANN_NAK, addr);
	}

	/**
	 * ANN must respond to neighbor indication of willingness to connect to client.
	 * 
	 * Algorithm: record this fact, and if all neighbors have reported in, move to Phase 3
	 */
	private void conn_nbr_ann_ack(CubeMessage msg) throws IOException
	{
		// Validate the message
		InetSocketAddress addr = validateMsg(msg, annStates, phase2ANNstates);
		if (null == addr)
			return;

		// Confirm source address
		ANNState annState = annStates.get(addr);
		if (-1 == annState.peerAddr.relativeLink(msg.getSrc()))
		{
			// The sender of this message isn't a neighbor of the peer!
			reply(msg, CubeMessage.Type.INVALID_MSG, msg.getType());
			return;
		}

		// Record willingness of a neighbor to connect, and enter Phase 3 if all neighbors have reported in
		willingPhase2(addr);
	}

	/**
	 * ANN must respond to neighbor indication of unwillingness to connect to client.
	 * 
	 * Algorithm: clean up state and inform INN
	 */
	private void conn_nbr_ann_nak(CubeMessage msg) throws IOException
	{
		// Validate the message
		InetSocketAddress addr = validateMsg(msg, annStates, phase2ANNstates);
		if (null == addr)
			return;

		// Confirm source address
		ANNState annState = annStates.get(addr);
		if (-1 == annState.peerAddr.relativeLink(msg.getSrc()))
		{
			// The sender of this message isn't a neighbor of the peer!
			reply(msg, CubeMessage.Type.INVALID_MSG, msg.getType());
			return;
		}

		// Nothing to do but bail out
		annBail(addr);
	}

	// Record willingness of a neighbor to connect, and enter Phase 3 if all neighbors have reported in
	private void willingPhase2(InetSocketAddress addr) throws IOException
	{
		ANNState annState = annStates.get(addr);

		// Update the count of willing nodes and check it for Phase 3 entry
		if (++annState.willing + annState.invalid.size() != cubeState.dim)
			return;

		// Enter Phase 3
		SocketChannel chan;
		try
		{
			// Connect to the client's CubeProtocol
			chan = SocketChannel.open(addr);

			// Give it a CubeAddress
			annState.nonces.add((int) (Math.random() * Integer.MAX_VALUE));
			annState.state = CubeMessage.Type.CONN_ANN_EXT_OFFER;
			new CubeMessage(CubeAddress.INVALID_ADDRESS, annState.peerAddr, annState.state, annState.nonces).send(chan);
			listener.register(chan);
		}
		catch (IOException e)
		{
			annBail(addr);
			return;
		}
	}

	/*
	 * Phase 3 methods
	 */

	/**
	 * Client must respond to an offer of a new CubeAddress from an ANN.
	 * 
	 * Algorithm: acknowledge the offer
	 */
	@SuppressWarnings("unchecked")
	private void conn_ann_ext_offer(CubeMessage msg) throws IOException
	{
		// Validate the message
		cltState.nonces = (ArrayList<Integer>) validateExt(msg, phase3CLTstates);
		if (null == cltState.nonces)
			return;

		// Accept the offer
		cubeState.addr = msg.getDst();
		cltState.state = CubeMessage.Type.CONN_EXT_ANN_ACK;
		new CubeMessage(cubeState.addr, CubeAddress.INVALID_ADDRESS, cltState.state, cltState.nonces).send(msg.getChannel());
	}

	/**
	 * ANN must respond to acknowledgment of CubeAddress from client. This method is the entry point to Phase 4.
	 * 
	 * Algorithm: instruct new neighbors to contact the client to verify nonces
	 */
	private void conn_ext_ann_ack(CubeMessage msg) throws IOException
	{
		// Validate the message
		@SuppressWarnings("unchecked")
		ArrayList<Integer> nonces = (ArrayList<Integer>) validateInt(msg, annStates, phase3ANNstates);
		SocketChannel chan = msg.getChannel();
		InetSocketAddress addr = (InetSocketAddress) chan.getRemoteAddress();
		if (null == nonces)
		{
			annBail(addr);
			return;
		}

		// Enter Phase 4
		ANNState annState = annStates.get(addr);
		if (1 + annState.invalid.size() < cubeState.dim)
		{
			// Regular processing
			annState.state = CubeMessage.Type.CONN_ANN_NBR_SUCCESS;
			annBcast(annState, addr);
			return;
		}

		// Edge case: I'm the only neighbor connected. Jump straight to Phase 5
		int link = cubeState.addr.relativeLink(annState.peerAddr);
		if (link + 1 > cubeState.dim)
			cubeState.dim = link + 1;
		cubeState.links = cubeState.links.followLink(link);
		cubeState.neighbors.add(link, new Neighbor(annState.peerAddr, chan));

		// Advertise my CubeAddress to the client
		annState.state = CubeMessage.Type.CONN_NBR_EXT_ACK;
		new CubeMessage(cubeState.addr, annState.peerAddr, annState.state, null).send(chan);
		annState.state = CubeMessage.Type.CONN_ANN_EXT_SUCCESS;
		new CubeMessage(cubeState.addr, annState.peerAddr, annState.state, cubeState.dim).send(chan);

		// Update the INN, and clean up
		annState.state = CubeMessage.Type.CONN_ANN_INN_SUCCESS;
		send(new CubeMessage(cubeState.addr, annState.inn, annState.state, addr));
		annStates.remove(addr);
	}

	/**
	 * ANN must respond to declining of CubeAddress from client.
	 * 
	 * Algorithm: bail
	 */
	private void conn_ext_ann_nak(CubeMessage msg) throws IOException
	{
		// No need to check anything, since all paths lead to...
		InetSocketAddress addr = (InetSocketAddress) msg.getChannel().getRemoteAddress();
		msg.getChannel().close();
		annBail(addr);
	}

	/*
	 * Phase 4 methods
	 */

	/**
	 * Neighbor must respond to ANN instruction to connect.
	 * 
	 * Algorithm: attempt to connect, and report success/failure to ANN
	 */
	private void conn_ann_nbr_success(CubeMessage msg) throws IOException
	{
		// Validate the message
		InetSocketAddress addr = validateMsg(msg, nbrStates, phase4NBRstates);
		if (null == addr)
			return;

		// Sanity check
		NbrState nbrState = nbrStates.get(addr);
		if (!nbrState.ann.equals(msg.getSrc()))
		{
			reply(msg, CubeMessage.Type.INVALID_MSG, msg.getType());
			return;
		}

		// Attempt to connect to the client
		try
		{
			nbrState.chan = SocketChannel.open(addr);
			CubeAddress none = CubeAddress.INVALID_ADDRESS;
			nbrState.state = CubeMessage.Type.CONN_NBR_EXT_OFFER;
			new CubeMessage(none, none, nbrState.state, null).send(nbrState.chan);
		}
		catch (IOException e)
		{
			nbrState.state = CubeMessage.Type.CONN_NBR_ANN_FAIL;
			send(new CubeMessage(cubeState.addr, nbrState.ann, nbrState.state, null));
			nbrStates.remove(addr);
		}
	}

	/**
	 * Client must respond to neighbor's offer to connect.
	 * 
	 * Algorithm: respond with the correct message (including the nonces), if we're willing to accept the connection
	 */
	private void conn_nbr_ext_offer(CubeMessage msg) throws IOException
	{
		// Validate the message
		validateExt(msg, phase4CLTstates);
		if (!msg.getChannel().isOpen())
			return;

		// Update state
		SocketChannel chan = msg.getChannel();
		cltState.nbrChans.add(chan);

		// Are we willing to make this connection?
		CubeAddress none = CubeAddress.INVALID_ADDRESS;
		if (amWilling((InetSocketAddress) chan.getRemoteAddress()))
		{
			cltState.state = CubeMessage.Type.CONN_EXT_NBR_ACK;
			new CubeMessage(cubeState.addr, none, cltState.state, cltState.nonces).send(chan);
		} else
		{
			// Close existing channels and wait for new ANN to contact me to try again
			cltState.state = CubeMessage.Type.CONN_EXT_NBR_NAK;
			new CubeMessage(cubeState.addr, none, cltState.state, null).send(chan);
			for (SocketChannel c : cltState.nbrChans)
				c.close();
			cltState.nbrChans = new ArrayList<>();
			cltState.state = CubeMessage.Type.CONN_EXT_INN_ATTACH;
		}
	}

	/**
	 * Neighbor must respond to client acknowledging connection.
	 * 
	 * Algorithm: if my nonce is listed, report negotiation success to ANN; otherwise, report negotiation failure
	 */
	private void conn_ext_nbr_ack(CubeMessage msg) throws IOException
	{
		// Ensure we are in the correct state
		CubeAddress client = msg.getSrc();
		SocketChannel chan = msg.getChannel();
		NbrState state = nbrStates.get(client);
		if (null == state || state.state != CubeMessage.Type.CONN_NBR_EXT_OFFER)
		{
			new CubeMessage(CubeAddress.INVALID_ADDRESS, client, CubeMessage.Type.INVALID_STATE, new Enum[] {
					annStates.get(client).state, CubeMessage.Type.CONN_INN_GEN_ANN });
			if (null != state)
				new CubeMessage(cubeState.addr, state.ann, CubeMessage.Type.CONN_NBR_ANN_FAIL, chan.getRemoteAddress());
			return;
		}

		// Ensure the message is properly formatted
		if (!checkMsg(msg, client, ArrayList.class))
		{
			new CubeMessage(CubeAddress.INVALID_ADDRESS, client, CubeMessage.Type.INVALID_MSG, null);
			new CubeMessage(cubeState.addr, state.ann, CubeMessage.Type.CONN_NBR_ANN_FAIL, chan.getRemoteAddress());
			return;
		}
		@SuppressWarnings("unchecked")
		ArrayList<Integer> replyNonces = (ArrayList<Integer>) msg.getData();

		// Determine whether the reply includes my nonce
		int link = client.relativeLink(cubeState.addr);
		if (replyNonces.size() != 1 || replyNonces.contains(state.nonce))
		{
			new CubeMessage(CubeAddress.INVALID_ADDRESS, client, CubeMessage.Type.INVALID_DATA, null);
			new CubeMessage(cubeState.addr, state.ann, CubeMessage.Type.CONN_NBR_ANN_FAIL, chan.getRemoteAddress());
			return;
		}

		// Set up my neighbor information and Cube state
		Neighbor n = new Neighbor(client, chan);
		cubeState.neighbors.add(link, n);
		cubeState.links = new CubeAddress(cubeState.links.setBit(link).toString());
		listener.register(chan);

		// Update the ANN
		state.state = CubeMessage.Type.CONN_NBR_ANN_SUCCESS;
		send(new CubeMessage(cubeState.addr, state.ann, state.state, client));
	}

	/**
	 * Neighbor must respond to client declining connection.
	 * 
	 * Algorithm: close the connection and report failure to the ANN
	 */
	private void conn_ext_nbr_nak(CubeMessage msg) throws IOException
	{
		// No need to check anything, since all paths lead to...
		InetSocketAddress addr = (InetSocketAddress) msg.getChannel().getRemoteAddress();
		msg.getChannel().close();
		NbrState state = nbrStates.remove(addr);
		send(new CubeMessage(cubeState.addr, state.ann, CubeMessage.Type.CONN_NBR_ANN_FAIL, addr));
	}

	/**
	 * ANN must respond to neighbor indication of successful SocketChannel to client.
	 * 
	 * Algorithm: record this fact, and if all neighbors have reported in, instruct them to advertise their
	 * CubeAddresses
	 */
	private void conn_nbr_ann_success(CubeMessage msg)
	{
		// TODO

	}

	/**
	 * ANN must respond to neighbor indication of failed SocketChannel to client.
	 * 
	 * Algorithm: instruct all neighbors to tear down their connections, and inform client and INN
	 */
	private void conn_nbr_ann_fail(CubeMessage msg)
	{
		// TODO

	}

	/*
	 * Phase 5 methods
	 */

	/**
	 * Neighbor must respond to ANN instruction to advertise CubeAddress to client.
	 * 
	 * Algorithm: send CubeAddress to client
	 */
	private void conn_ann_nbr_adv(CubeMessage msg)
	{
		// TODO

	}

	/**
	 * Neighbor must respond to ANN instruction /not/ to advertise CubeAddress to client.
	 * 
	 * Algorithm: clean up connection state, including disconnecting client if already connected
	 */
	private void conn_ann_nbr_nadv(CubeMessage msg)
	{
		// TODO

	}

	/**
	 * INN must respond to an indication of successful address negotiation from an ANN.
	 * 
	 * Algorithm: Close the client SocketChannel
	 */
	private void conn_ann_inn_success(CubeMessage msg)
	{
		// TODO

	}

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
	 * Client must respond to neighbor's indication of its CubeAddress and the Cube dimension
	 * 
	 * Algorithm: store this information
	 */
	private void conn_nbr_ext_ack(CubeMessage msg) throws IOException
	{
		// Ensure the message is properly formatted
		CubeAddress nAddr = msg.getSrc();
		SocketChannel chan = msg.getChannel();
		CubeAddress none = CubeAddress.INVALID_ADDRESS;
		if (!checkMsg(msg, nAddr, null))
		{
			new CubeMessage(cubeState.addr, none, CubeMessage.Type.INVALID_MSG, msg).send(chan);
			chan.close();
			if (!chan.equals(cltState.annChan))
				cltState.annChan.close();
			return;
		}

		// Ensure we are in the correct state
		if (cltState.state != CubeMessage.Type.CONN_EXT_ANN_ACK && cltState.state != CubeMessage.Type.CONN_EXT_NBR_ACK)
		{
			new CubeMessage(cubeState.addr, none, CubeMessage.Type.INVALID_STATE, new Enum[] { cltState.state,
					CubeMessage.Type.CONN_NBR_EXT_ACK }).send(chan);
			chan.close();
			if (!chan.equals(cltState.annChan))
				cltState.annChan.close();
			return;
		}
		cltState.state = CubeMessage.Type.CONN_EXT_NBR_ACK;

		// Is the advertised address actually my neighbor?
		int link = cubeState.addr.relativeLink(nAddr);
		if (-1 == link)
		{
			new CubeMessage(cubeState.addr, none, CubeMessage.Type.INVALID_DATA, new CubeAddress[] { cubeState.addr, nAddr })
					.send(chan);
			chan.close();
			if (!chan.equals(cltState.annChan))
				cltState.annChan.close();
			return;
		}

		// Update the Cube state
		Neighbor n = new Neighbor(nAddr, chan);
		cubeState.neighbors.setSize(link);
		cubeState.neighbors.add(link, n);
		cubeState.links = new CubeAddress(cubeState.links.setBit(link).toString());
	}

	/**
	 * Client must respond to INN indicating successful connection.
	 * 
	 * Algorithm: clean up client connection state
	 */
	private void conn_ann_ext_success(CubeMessage msg) throws IOException
	{
		// Ensure the message is properly formatted
		CubeAddress none = CubeAddress.INVALID_ADDRESS;
		if (!checkMsg(msg, none, Integer.class))
		{
			new CubeMessage(cubeState.addr, none, CubeMessage.Type.INVALID_MSG, msg.getType()).send(msg.getChannel());
			msg.getChannel().close();
			return;
		}
		cubeState.dim = (Integer) msg.getData();

		// Ensure we are in the correct state
		if (null == cltState)
		{
			new CubeMessage(cubeState.addr, none, CubeMessage.Type.INVALID_STATE, new Enum[] { null, msg.getType() }).send(msg
					.getChannel());
			msg.getChannel().close();
			return;
		} else if (cltState.state != CubeMessage.Type.CONN_EXT_NBR_ACK)
		{
			new CubeMessage(cubeState.addr, none, CubeMessage.Type.INVALID_STATE, new Enum[] { cltState.state, msg.getType() })
					.send(msg.getChannel());
			msg.getChannel().close();
			return;

		}

		// Clean up client state. Don't close the annChan, since the ANN is our neighbor
		cltState.innChan.close();
		cltState = null;
	}

	/*
	 * Multi-phase methods
	 */

	// Ensure that a CubeMessage has the proper source and state
	private boolean checkMsg(CubeMessage msg, CubeAddress src, Class<?> clz)
	{
		return (src == null || msg.getSrc().equals(src))
				&& (null == clz || null != msg.getData() && msg.getData().getClass().isAssignableFrom(clz));
	}

	/**
	 * Message / state validation helper for intra-Cube messages
	 * 
	 * @param msg
	 *            The message to validate
	 * @param stateMap
	 *            innStates, annStates, or nbrStates
	 * @param states
	 *            individual states to check against
	 * @return
	 * @throws IOException
	 */
	private InetSocketAddress validateMsg(CubeMessage msg, HashMap<InetSocketAddress, ? extends State> stateMap,
			List<CubeMessage.Type> states) throws IOException
	{
		// Ensure the message is properly formatted
		if (!checkMsg(msg, null, InetSocketAddress.class))
		{
			reply(msg, CubeMessage.Type.INVALID_MSG, msg.getType());
			return null;
		}
		InetSocketAddress addr = (InetSocketAddress) msg.getData();

		// Ensure we are in the correct state
		State state = stateMap.get(addr);
		if (null == state)
		{
			reply(msg, CubeMessage.Type.INVALID_STATE, new Enum[] { null, msg.getType() });
			return null;
		} else if (!states.contains(state.state))
		{
			if (!stateMap.equals(innStates))
				reply(msg, CubeMessage.Type.INVALID_STATE, new Enum[] { state.state, msg.getType() });
			return null;
		}

		// Message format and current state are both valid
		return addr;
	}

	/**
	 * Message / state validation helper for messages from a Cube node to a connecting client
	 * 
	 * @param msg
	 *            The message to validate
	 * @param states
	 *            individual states to check against
	 * @return
	 */
	private Object validateExt(CubeMessage msg, List<CubeMessage.Type> states) throws IOException
	{
		// Ensure the message is properly formatted
		CubeAddress none = CubeAddress.INVALID_ADDRESS;
		SocketChannel chan = msg.getChannel();
		if (!checkMsg(msg, null, null))
		{
			new CubeMessage(cubeState.addr, none, CubeMessage.Type.INVALID_MSG, msg.getType()).send(chan);
			chan.close();
			return null;
		}

		// Ensure we are in the correct state
		State state = cltState;
		if (null == state)
		{
			new CubeMessage(cubeState.addr, none, CubeMessage.Type.INVALID_STATE, new Enum[] { null, msg.getType() }).send(chan);
			chan.close();
			return null;
		} else if (!states.contains(state.state))
		{
			new CubeMessage(cubeState.addr, none, CubeMessage.Type.INVALID_STATE, new Enum[] { state.state, msg.getType() })
					.send(chan);
			chan.close();
			return null;
		}

		// Message format and current state are both valid
		return msg.getData();
	}

	/**
	 * Message / state validation helper for messages from a connecting client to a Cube node
	 * 
	 * @param msg
	 *            The message to validate
	 * @param stateMap
	 *            annStates or nbrStates
	 * @param states
	 *            individual states to check against
	 * @return
	 */
	private Object validateInt(CubeMessage msg, HashMap<InetSocketAddress, ? extends State> stateMap,
			List<CubeMessage.Type> states) throws IOException
	{
		// Ensure the message is properly formatted
		CubeAddress none = CubeAddress.INVALID_ADDRESS;
		if (!checkMsg(msg, null, null))
		{
			new CubeMessage(none, msg.getSrc(), CubeMessage.Type.INVALID_MSG, msg.getType()).send(msg.getChannel());
			return null;
		}

		// Ensure we are in the correct state
		InetSocketAddress addr = (InetSocketAddress) msg.getChannel().getRemoteAddress();
		State state = stateMap.get(addr);
		if (null == state)
		{
			new CubeMessage(none, msg.getSrc(), CubeMessage.Type.INVALID_STATE, new Enum[] { null, msg.getType() }).send(msg
					.getChannel());
			return null;
		} else if (!states.contains(state.state))
		{
			new CubeMessage(none, msg.getSrc(), CubeMessage.Type.INVALID_STATE, new Enum[] { state.state, msg.getType() })
					.send(msg.getChannel());
			return null;
		}

		// Message format and current state are both valid
		return msg.getData();
	}

	// Node 0 processing to connect Node 1, bypassing several layers of protocol
	@SuppressWarnings("unchecked")
	private void node1connect(CubeMessage msg) throws IOException
	{
		InetSocketAddress addr = (InetSocketAddress) msg.getData();
		SocketChannel innChan = msg.getChannel();
		CubeAddress none = CubeAddress.INVALID_ADDRESS;
		CubeAddress one = new CubeAddress("1");

		// Phase 1: successful, since I have identified an attachment point (myself)
		// Phase 2: check all neighbors (i.e., myself) for willingness to connect
		if (!amWilling(addr))
		{
			new CubeMessage(none, none, CubeMessage.Type.CONN_INN_EXT_CONN_REFUSED, null).send(innChan);
			innChan.close();
			return;
		}

		// Phase 3: offer a CubeAddress to the client
		SocketChannel annChan;
		try
		{
			annChan = SocketChannel.open(addr);
		}
		catch (IOException e)
		{
			// If the address is unreachable, bail
			new CubeMessage(none, none, CubeMessage.Type.CONN_INN_EXT_CONN_REFUSED, null).send(innChan);
			innChan.close();
			return;
		}
		Integer nonce = (int) (Math.random() * Integer.MAX_VALUE);
		ArrayList<Integer> nonces = new ArrayList<>();
		nonces.add(nonce);
		new CubeMessage(none, one, CubeMessage.Type.CONN_ANN_EXT_OFFER, nonces).send(annChan);
		msg = CubeMessage.recv(annChan);
		if (!CubeMessage.Type.CONN_EXT_ANN_ACK.equals(msg.getType()))
		{
			annChan.close();
			new CubeMessage(none, none, CubeMessage.Type.CONN_INN_EXT_CONN_REFUSED, null).send(innChan);
			innChan.close();
			return;
		}

		// Phase 4: offer to connect to the client and verify nonce
		new CubeMessage(none, one, CubeMessage.Type.CONN_NBR_EXT_OFFER, null).send(annChan);
		msg = CubeMessage.recv(annChan);
		if (!CubeMessage.Type.CONN_EXT_NBR_ACK.equals(msg.getType()) || null == msg.getData()
				|| !nonce.equals(((ArrayList<Integer>) msg.getData()).get(0)))
		{
			annChan.close();
			new CubeMessage(none, none, CubeMessage.Type.CONN_INN_EXT_CONN_REFUSED, null).send(innChan);
			innChan.close();
			return;
		}

		// Phase 5: reveal my CubeAddress and complete the connection
		cubeState.dim = 1;
		new CubeMessage(cubeState.addr, one, CubeMessage.Type.CONN_NBR_EXT_ACK, null).send(annChan);
		new CubeMessage(cubeState.addr, one, CubeMessage.Type.CONN_ANN_EXT_SUCCESS, cubeState.dim).send(annChan);
		cubeState.neighbors.add(new Neighbor(one, annChan));
		cubeState.links = one;
		listener.register(annChan);

		new CubeMessage(none, one, CubeMessage.Type.CONN_ANN_INN_SUCCESS, null).send(innChan);
		innChan.close();
	}

	/**
	 * Node must respond to sending an invalid address, depending on protocol state.
	 */
	private void invalid_address(CubeMessage msg) throws IOException
	{
		Object data = msg.getData();

		// Process based on our state
		if (data instanceof InetSocketAddress)
		{
			InetSocketAddress addr = (InetSocketAddress) data;
			ANNState annState = annStates.get(addr);
			if (null != annState && CubeMessage.Type.CONN_ANN_NBR_REQ.equals(annState.state))
			{
				/*
				 * INVALID_ADDRESS generated in response to Phase 2 request for neighbor willingness. Update the state
				 * to show that this node is absent, and assume it would be willing to connect.
				 */
				annState.invalid.add(msg.getSrc());
				willingPhase2(addr);
				return;
			}
		}

		// No idea what happens here...
		System.err.println("Got an invalid address");
	}

	// Phases 2-4: Send a message to all prospective neighbors
	private void annBcast(ANNState annState, InetSocketAddress addr) throws IOException
	{
		for (int i = 0; i < cubeState.dim; ++i)
		{
			// Determine each node's CubeAddress
			CubeAddress nbrAddr = annState.peerAddr.followLink(i);
			if (annState.invalid.contains(nbrAddr))
				continue;

			// Tell them to bail
			send(new CubeMessage(cubeState.addr, nbrAddr, annState.state, addr));
		}
	}

	// Phases 2-4: Notify everyone if an ANN determines that a connection cannot be made
	private void annBail(InetSocketAddress addr) throws IOException
	{
		ANNState annState = annStates.remove(addr);

		// Inform the neighbors
		annState.state = CubeMessage.Type.CONN_ANN_NBR_FAIL;
		annBcast(annState, addr);

		// Inform the INN
		annState.state = CubeMessage.Type.CONN_ANN_INN_FAIL;
		send(new CubeMessage(cubeState.addr, annState.inn, annState.state, addr));
	}

	/**
	 * Neighbor must respond to ANN indication that a failure occurred.
	 * 
	 * Algorithm: clean up connection state
	 */
	private void conn_ann_nbr_fail(CubeMessage msg)
	{
		// TODO

	}

	/**
	 * INN must respond to ANN indication that a failure occurred.
	 * 
	 * Algorithm: ask a different node at the same hop count to be ANN; if none remain, increase the hop count
	 */
	private void conn_ann_inn_fail(CubeMessage msg)
	{
		// TODO

	}

	/*
	 * Messages exchanged post-connection
	 */

	/**
	 * Client must respond to received data message.
	 * 
	 * Algorithm: add the message to my local received message queue
	 */
	private void data_msg(CubeMessage msg) throws IOException
	{
		/*
		 * Lazily update Cube dimension. Worst case scenario: a neighbor maliciously sends forged CubeMessages having
		 * ever-increasing source addresses. In this case, the neighbor will become able to support many new
		 * connections.
		 */
		int len = msg.getSrc().bitLength();
		if (len == cubeState.dim + 1)
			cubeState.dim = len;

		// Add this message to my queue
		queued.add(msg);
	}

	/*
	 * Utility methods
	 */

	/**
	 * Determine whether I am willing to allow a connection from a given address.
	 */
	protected boolean amWilling(InetSocketAddress addr)
	{
		return true;
	}

	/**
	 * Connect to an INN at the given address, advertising my own Cube comms port
	 */
	public void connect(InetSocketAddress cubeAddr, InetSocketAddress myAddr) throws IOException
	{
		cltState = new CltState();
		cltState.innChan = SocketChannel.open(cubeAddr);
		cltState.state = CubeMessage.Type.CONN_EXT_INN_ATTACH;
		new CubeMessage(CubeAddress.INVALID_ADDRESS, CubeAddress.INVALID_ADDRESS, cltState.state, myAddr).send(cltState.innChan);
		listener.register(cltState.innChan);
	}

	/**
	 * Obtain my {@link CubeAddress}.
	 * 
	 * @return The <code>CubeAddress</code>
	 */
	public final CubeAddress getAddress()
	{
		return cubeState.addr;
	}

	/**
	 * Send data to another node in the Cube.
	 * 
	 * @param dest
	 *            The destination address for the data
	 * @param data
	 *            The data itself
	 */
	public void send(Message msg) throws IOException
	{
		send(new CubeMessage(cubeState.addr, msg.peer, CubeMessage.Type.DATA_MSG, msg.data));
	}

	/**
	 * Send a message through the Cube using Katseff Algorithm 3 (with LSB instead of MSB ordering). Invoking this
	 * method cannot divulge confidential address information to a non-connected node; at worst, using this method as a
	 * response to a forged request will send a message to another connected node, which will reply with INVALID_STATE.
	 * 
	 * FIXME to handle transient link failures
	 */
	void send(CubeMessage msg) throws IOException
	{
		// Check for idiocy and/or forged messages
		if (msg.getDst().bitCount() > cubeState.dim + 1)
			return;

		if (cubeState.addr.equals(msg.getDst()))
		{
			// Loop back
			process(msg);
			return;
		} else
		{
			int link = cubeState.addr.xor(msg.getDst()).and(cubeState.links).getLowestSetBit();
			if (-1 == link)
			{
				// Remote node tried to send a message to a non-connected address
				send(new CubeMessage(msg.getDst(), msg.getSrc(), CubeMessage.Type.INVALID_ADDRESS, msg.getData()));
				return;
			}
			msg.send(cubeState.neighbors.get(link).chan);
		}
	}

	/**
	 * Reply to a message with a new message type and data.
	 */
	void reply(CubeMessage request, CubeMessage.Type type, Serializable data) throws IOException
	{
		send(new CubeMessage(cubeState.addr, request.getSrc(), type, data));
	}

	/**
	 * Broadcast a message through the Cube.
	 */
	public void broadcast(Message msg) throws IOException
	{
		CubeMessage bcastMsg = new CubeMessage(cubeState.addr, null, CubeMessage.Type.DATA_MSG, msg.data);
		bcastMsg.setTravel(BigInteger.ZERO.setBit(cubeState.dim).subtract(BigInteger.ONE));
		fwd_broadcast(bcastMsg);
	}

	// Utility method that forwards a broadcast message through the Cube using Katseff Algorithm 6.
	// FIXME in case msg.send() throws an IOException due to a link going down
	private void fwd_broadcast(CubeMessage msg) throws IOException
	{
		// Initialize newtravel by adding all non-connected links
		BigInteger travel = msg.getTravel();
		BigInteger newtravel = travel.or(cubeState.links.not().abs());

		// Loop over all links, from most significant to least, turning off bits in newtravel as we go
		for (int link = cubeState.dim; link >= 0; --link)
		{
			// Turn off the bit for this link in newtravel if we are connected along it
			if (cubeState.links.testBit(link))
				newtravel = newtravel.clearBit(link);

			// Only send messages on links that we should travel and are connected
			if (!travel.testBit(link) || !cubeState.links.testBit(link))
				continue;

			// Send the message directly
			msg.reduceHops();
			msg.setTravel(newtravel);
			msg.send(cubeState.neighbors.get(link).chan);
		}
	}

	/**
	 * Perform a non-blocking wait for an incoming message, then return it.
	 * 
	 * @return A waiting message, if any; otherwise, null
	 */
	public Message recvNow()
	{
		if (queued.isEmpty())
			return null;
		CubeMessage msg = queued.remove(0);
		return new Message(msg.getSrc(), msg.getData());
	}

	/**
	 * Perform a blocking wait for an incoming message, then return it.
	 * 
	 * @return The received message
	 */
	public Message recv()
	{
		while (queued.isEmpty())
			;
		CubeMessage msg = queued.remove(0);
		return new Message(msg.getSrc(), msg.getData());
	}
}
