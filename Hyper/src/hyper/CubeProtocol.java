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
	private ArrayList<CubeMessage.Type> phase5NBRstates = new ArrayList<>();

	// CLT state
	private CltState cltState;
	private ArrayList<CubeMessage.Type> phase3CLTstates = new ArrayList<>();
	private ArrayList<CubeMessage.Type> phase4CLTstates = new ArrayList<>();
	private ArrayList<CubeMessage.Type> phase5CLTstates = new ArrayList<>();

	// Our MessageListener
	private MessageListener listener;

	// Local message queuing
	private ArrayList<CubeMessage> queued = new ArrayList<>();
	Thread blockingThread = null;

	CubeState getCubeState()
	{
		return cubeState;
	}

	public CubeProtocol(MessageListener listener) {
		this.listener = listener;
		listener.setProtocol(this);

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
		phase4NBRstates.add(CubeMessage.Type.CONN_NBR_EXT_OFFER);
		phase4CLTstates.add(CubeMessage.Type.CONN_EXT_ANN_ACK);
		phase4CLTstates.add(CubeMessage.Type.CONN_EXT_NBR_ACK);

		phase5CLTstates.add(CubeMessage.Type.CONN_EXT_NBR_ACK);
		phase5NBRstates.add(CubeMessage.Type.CONN_NBR_EXT_ACK);
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
	void process(CubeMessage msg)
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

		switch (msg.getType()) {
		case CONN_ANN_EXT_FAIL:
			conn_ann_ext_fail(msg);
			break;
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
			System.err.println(Thread.currentThread() + " received INVALID_MSG: (" + msg.getSrc() + "," + msg.getDst()
					+ "," + msg.getData() + ")");
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
	 */
	private void conn_ext_inn_attach(CubeMessage msg)
	{
		// Validate the message
		InetSocketAddress addr = (InetSocketAddress) validateExt(msg, innStates, null);
		if (null == addr)
			return;

		// Edge case: I might be the only node in the Cube
		if (cubeState.dim == 0)
		{
			// Perform a blocking connection attempt, all the way through Phase 5
			node1connect(msg);
			return;
		}

		// Initialize state
		INNState innState = new INNState(msg.getChannel());
		innStates.put(addr, innState);

		// Edge case: I have an open slot myself and I'm willing to take on this client
		if (cubeState.vacancy() && amWilling(addr))
		{
			// Fake a successful address negotiation
			ANNState annState = new ANNState(cubeState.addr);
			annState.state = CubeMessage.Type.CONN_GEN_INN_ACK;
			annStates.put(addr, annState);

			// Send myself a loop back message designating me as ANN, and enter Phase 2
			innState.ann = cubeState.addr;
			innState.state = CubeMessage.Type.CONN_INN_ANN_HANDOFF;
			msg = new CubeMessage(cubeState.addr, innState.ann, innState.state, addr);
			process(msg);
			return;
		}

		// Regular processing: all of my links are already connected or I'm unwilling to connect
		innState.state = CubeMessage.Type.CONN_INN_GEN_ANN;
		msg = new CubeMessage(cubeState.addr, CubeAddress.ZERO_HOPS, innState.state, addr, cubeState.dim);
		for (SocketChannel sc : cubeState.neighbors)
			msg.send(sc);
	}

	/**
	 * Generic node must respond to INN request to become ANN and connect client.
	 * 
	 * Algorithm: determine whether I am able to connect, then whether I am willing to connect. Because the second
	 * determination is more important, do it first. Reply to the INN with the result.
	 */
	private void conn_inn_gen_ann(CubeMessage msg)
	{
		// Validate the message
		InetSocketAddress addr = validateMsg(msg, annStates, null);
		if (null == addr)
			return;

		// Am I willing to connect?
		if (!amWilling(addr))
		{
			reply(msg, CubeMessage.Type.CONN_GEN_INN_UNWILLING, addr);
			return;
		}

		// Create state and reply with ability to connect
		ANNState annState = new ANNState(msg.getSrc());
		annStates.put(addr, annState);
		if (cubeState.vacancy())
			annState.state = CubeMessage.Type.CONN_GEN_INN_ACK;
		else
			annState.state = CubeMessage.Type.CONN_GEN_INN_UNABLE;

		reply(msg, annState.state, addr);
	}

	/**
	 * INN must respond to generic node indicating willingness and ability to be ANN.
	 * 
	 * Algorithm: hand off negotiation to generic node to begin Phase 2 (unless already in Phase 2)
	 */
	private void conn_gen_inn_ack(CubeMessage msg)
	{
		// Validate the reply message
		InetSocketAddress addr = validateMsg(msg, innStates, phase1INNstates);
		if (null == addr)
			return;
		INNState innState = innStates.get(addr);

		// Hand off ANN duties, provided we aren't already using someone else as ANN
		if (innState.state == CubeMessage.Type.CONN_INN_GEN_ANN)
		{
			// We're still in Phase 1; enter Phase 2
			innState.ann = msg.getSrc();
			innState.state = CubeMessage.Type.CONN_INN_ANN_HANDOFF;
			reply(msg, innState.state, addr);
		} else
			// We're in Phase 2 somewhere, but add this node to the ANN "possibles" cache
			innState.acked.add(msg.getSrc());
	}

	/**
	 * INN must respond to generic node indicating its inability to act as ANN.
	 * 
	 * Algorithm: record this fact, and determine whether to expand the Cube
	 */
	private void conn_gen_inn_unable(CubeMessage msg)
	{
		// Validate the reply message
		InetSocketAddress addr = validateMsg(msg, innStates, phase1INNstates);
		if (null == addr)
			return;

		// Add this response to the list of unable nodes
		innStates.get(addr).unable.add(msg.getSrc());

		// If everyone is unable or unwilling, we have to expand the Cube
		check_expand(addr);
	}

	/**
	 * INN must respond to generic node indicating its unwillingness to act as ANN.
	 * 
	 * Algorithm: record this fact, and determine whether to expand the Cube
	 */
	private void conn_gen_inn_unwilling(CubeMessage msg)
	{
		// Validate the reply message
		InetSocketAddress addr = validateMsg(msg, innStates, phase1INNstates);
		if (null == addr)
			return;

		// Add this response to the list of unwilling nodes
		innStates.get(addr).unwilling.add(msg.getSrc());

		// If everyone is unable or unwilling, we have to expand the Cube
		check_expand(addr);
	}

	/**
	 * Generic node must respond to INN instruction to become ANN. This method is the entry point to Phase 2.
	 * 
	 * Algorithm: initialize ANN state and contact prospective neighbors
	 */
	private void conn_inn_ann_handoff(CubeMessage msg)
	{
		// Validate the reply message
		InetSocketAddress addr = validateMsg(msg, annStates, phase1ANNstates);
		if (null == addr)
			return;

		// Authenticate the source address
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
	private void check_expand(InetSocketAddress addr)
	{
		INNState innState = innStates.get(addr);
		int unable = innState.unable.size();
		int unwill = innState.unwilling.size();

		// Have we contacted everyone yet?
		if (innState.hops < cubeState.dim)
		{
			// Nope. Don't increase the hop count unless we've contacted enough nodes
			if (unable + unwill <= 1 << (innState.hops - 1))
				return;

			// Increase the hop count
			++innState.hops;
			CubeAddress hopAddr = new CubeAddress(Integer.toString(-innState.hops));

			// Send a broadcast message to each neighbor. CubeProtocol.send() doesn't work on broadcast messages
			CubeMessage msg = new CubeMessage(cubeState.addr, hopAddr, innState.state, addr, cubeState.dim);
			for (SocketChannel sc : cubeState.neighbors)
				msg.send(sc);
		}

		// Find someone who's willing to take the new guy (including possibly me)
		if (amWilling(addr))
			innState.unable.add(cubeState.addr);
		while (innState.unable.size() > 0)
		{
			int index = (int) (Math.random() * innState.unable.size());
			CubeAddress unableAddr = innState.unable.remove(index);

			// Ensure the index is not adjacent to someone who is unwilling
			for (int i = 0; i < cubeState.dim; ++i)
				if (innState.unwilling.contains(unableAddr.followLink(i)))
					break;

			// I've picked a good node. If it's me, initialize ANN state
			if (unableAddr.equals(cubeState.addr))
			{
				// I chose myself as the ANN; initialize state
				ANNState annState = new ANNState(cubeState.addr);
				annState.state = CubeMessage.Type.CONN_GEN_INN_ACK;
				annStates.put(addr, annState);
			}

			// Enter Phase 2
			innState.ann = unableAddr;
			innState.state = CubeMessage.Type.CONN_INN_ANN_HANDOFF;
			send(new CubeMessage(cubeState.addr, innState.ann, innState.state, addr));
			return;
		}

		// If we get here, it's impossible to attach to the cube; deny the Cube connection and cut contact
		CubeAddress none = CubeAddress.INVALID_ADDRESS;
		new CubeMessage(none, none, CubeMessage.Type.CONN_INN_EXT_CONN_REFUSED, null).send(innState.chan);
		quietClose(innStates.remove(addr).chan);
	}

	/*
	 * Phase 2 methods
	 */

	/**
	 * Neighbor must respond to ANN request for willingness to connect.
	 * 
	 * Algorithm: return whether neighbor is willing
	 */
	private void conn_ann_nbr_req(CubeMessage msg)
	{
		// Validate the message
		InetSocketAddress addr = validateMsg(msg, nbrStates, null);
		if (null == addr)
			return;

		// Return our willingness
		if (amWilling(addr))
		{
			NbrState nbrState = new NbrState(msg.getSrc());
			nbrState.state = Type.CONN_NBR_ANN_ACK;
			nbrStates.put(addr, nbrState);
			reply(msg, nbrState.state, new Serializable[] { addr, nbrState.nonce });
		} else
			reply(msg, CubeMessage.Type.CONN_NBR_ANN_NAK, addr);
	}

	/**
	 * ANN must respond to neighbor indication of willingness to connect to client.
	 * 
	 * Algorithm: record this fact, and if all neighbors have reported in, move to Phase 3
	 */
	private void conn_nbr_ann_ack(CubeMessage msg)
	{
		// Validate the message
		InetSocketAddress addr = validateMsg(msg, annStates, phase2ANNstates);
		if (null == addr)
			return;
		Integer nonce = (Integer) ((Serializable[]) msg.getData())[1];

		// Confirm source address
		ANNState annState = annStates.get(addr);
		if (-1 == annState.peerAddr.relativeLink(msg.getSrc()))
		{
			// The sender of this message isn't a neighbor of the peer!
			reply(msg, CubeMessage.Type.INVALID_MSG, msg.getType());
			return;
		}

		// Save the neighbor's nonce
		annState.nonces.add(nonce);

		// Record willingness of a neighbor to connect, and enter Phase 3 if all neighbors have reported in
		willingPhase2(addr);
	}

	/**
	 * ANN must respond to neighbor indication of unwillingness to connect to client.
	 * 
	 * Algorithm: clean up state and inform INN
	 */
	private void conn_nbr_ann_nak(CubeMessage msg)
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
	private void willingPhase2(InetSocketAddress addr)
	{
		ANNState annState = annStates.get(addr);

		// Update the count of willing nodes and check it for Phase 3 entry
		if (++annState.success != cubeState.dim)
			return;

		// Enter Phase 3
		SocketChannel chan;
		try
		{
			// Connect to the client's CubeProtocol
			chan = SocketChannel.open(addr);
			listener.register(chan);
		} catch (IOException e)
		{
			annBail(addr);
			return;
		}

		// Set up my own neighbor state
		NbrState nbrState = new NbrState(cubeState.addr);
		nbrStates.put(addr, nbrState);
		annState.nonces.add(nbrState.nonce);
		annState.state = CubeMessage.Type.CONN_ANN_EXT_OFFER;
		new CubeMessage(CubeAddress.INVALID_ADDRESS, annState.peerAddr, annState.state, annState.nonces).send(chan);

		// Reset success count to use in phase 4
		annState.success = 0;
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
	private void conn_ann_ext_offer(CubeMessage msg)
	{
		// Validate the message
		cltState.nonces = (ArrayList<Integer>) validateInt(msg, phase3CLTstates);
		if (null == cltState.nonces)
			return;

		// Am I willing to have the ANN as my neighbor?
		SocketChannel chan = msg.getChannel();
		InetSocketAddress addr = quietAddr(chan);
		CubeAddress none = CubeAddress.INVALID_ADDRESS;
		if (null == addr || !amWilling(addr))
		{
			new CubeMessage(none, none, CubeMessage.Type.CONN_EXT_ANN_NAK, null).send(chan);
			quietClose(chan);
			return;
		}

		// Accept the offer
		cubeState.addr = msg.getDst();
		cltState.nbrChans.add(chan);
		cltState.state = CubeMessage.Type.CONN_EXT_ANN_ACK;
		new CubeMessage(cubeState.addr, none, cltState.state, cltState.nonces).send(chan);
	}

	/**
	 * ANN must respond to acknowledgment of CubeAddress from client. This method is the entry point to Phase 4.
	 * 
	 * Algorithm: instruct new neighbors to contact the client to verify nonces
	 */
	private void conn_ext_ann_ack(CubeMessage msg)
	{
		// Validate the message
		@SuppressWarnings("unchecked")
		ArrayList<Integer> nonces = (ArrayList<Integer>) validateExt(msg, annStates, phase3ANNstates);
		SocketChannel chan = msg.getChannel();
		InetSocketAddress addr = quietAddr(chan);
		if (null == nonces)
		{
			annBail(addr);
			return;
		}

		// Enter Phase 4. First determine whether the new peer has at least one neighbor already connected
		ANNState annState = annStates.get(addr);
		annState.state = CubeMessage.Type.CONN_ANN_NBR_SUCCESS;
		if (cubeState.dim > 1 + annState.invalid.size())
		{
			// Regular processing
			annBcast(annState, addr);
			return;
		}

		// Edge case: I'm the only neighbor connected, jump straight to Phase 5
		annState.state = CubeMessage.Type.CONN_ANN_NBR_ADV;
		int link = cubeState.addr.relativeLink(annState.peerAddr);
		cubeState.addNeighbor(link, chan);

		// Advertise my CubeAddress to the client and wait for ACK
		NbrState nbrState = nbrStates.get(addr);
		nbrState.state = CubeMessage.Type.CONN_NBR_EXT_OFFER;
		new CubeMessage(CubeAddress.INVALID_ADDRESS, annState.peerAddr, nbrState.state, null).send(chan);
	}

	/**
	 * ANN must respond to declining of CubeAddress from client.
	 * 
	 * Algorithm: bail
	 */
	private void conn_ext_ann_nak(CubeMessage msg)
	{
		// No need to check anything, since all paths lead to...
		InetSocketAddress addr = quietAddr(msg.getChannel());
		quietClose(msg.getChannel());
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
	private void conn_ann_nbr_success(CubeMessage msg)
	{
		// Validate the message
		InetSocketAddress addr = validateMsg(msg, nbrStates, phase4NBRstates);
		if (null == addr)
			return;

		// Authenticate the source address
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
		} catch (IOException e)
		{
			// The ANN was able to connect to the client but I can't, so bail
			nbrState.state = CubeMessage.Type.CONN_NBR_ANN_FAIL;
			send(new CubeMessage(cubeState.addr, nbrState.ann, nbrState.state, null));
			return;
		}

		// Socket connection was successful, update state and offer Cube connection to the client
		CubeAddress none = CubeAddress.INVALID_ADDRESS;
		nbrState.state = CubeMessage.Type.CONN_NBR_EXT_OFFER;
		new CubeMessage(none, none, nbrState.state, null).send(nbrState.chan);
	}

	/**
	 * Client must respond to neighbor's offer to connect.
	 * 
	 * Algorithm: respond with the correct message (including the nonces), if we're willing to accept the connection
	 */
	private void conn_nbr_ext_offer(CubeMessage msg)
	{
		// Validate the message
		validateInt(msg, phase4CLTstates);
		if (!msg.getChannel().isOpen())
			return;

		// Update state
		SocketChannel chan = msg.getChannel();
		cltState.nbrChans.add(chan);
		InetSocketAddress addr = quietAddr(chan);

		// Are we willing to make this connection?
		CubeAddress none = CubeAddress.INVALID_ADDRESS;
		if (amWilling(addr))
		{
			// ACK the neighbor
			cltState.state = CubeMessage.Type.CONN_EXT_NBR_ACK;
			new CubeMessage(cubeState.addr, none, cltState.state, cltState.nonces).send(chan);
		} else
		{
			// Close existing channels and wait for new ANN to contact me to try again
			cltState.state = CubeMessage.Type.CONN_EXT_NBR_NAK;
			new CubeMessage(cubeState.addr, none, cltState.state, null).send(chan);
			for (SocketChannel c : cltState.nbrChans)
				quietClose(c);
			cltState.nbrChans = new ArrayList<>();
			cltState.state = CubeMessage.Type.CONN_EXT_INN_ATTACH;
		}
	}

	/**
	 * Neighbor must respond to client acknowledging connection.
	 * 
	 * Algorithm: if my nonce is listed, report negotiation success to ANN; otherwise, report negotiation failure
	 */
	private void conn_ext_nbr_ack(CubeMessage msg)
	{
		// Validate the message
		@SuppressWarnings("unchecked")
		ArrayList<Integer> nonces = (ArrayList<Integer>) validateExt(msg, nbrStates, phase4NBRstates);
		if (null == nonces)
			return;
		CubeAddress nAddr = msg.getSrc();
		SocketChannel chan = msg.getChannel();
		InetSocketAddress addr = quietAddr(chan);
		NbrState nbrState = nbrStates.get(addr);

		// Authenticate the client by nonce
		if (!nonces.contains(nbrState.nonce))
		{
			// Bail on the client
			new CubeMessage(CubeAddress.INVALID_ADDRESS, nAddr, CubeMessage.Type.INVALID_DATA, null).send(chan);
			quietClose(chan);

			// Bail on the ANN
			nbrState.state = CubeMessage.Type.CONN_NBR_ANN_FAIL;
			new CubeMessage(cubeState.addr, nbrState.ann, nbrState.state, addr);
			return;
		}

		// Determine which link this client will be on
		int link = cubeState.addr.relativeLink(nAddr);
		if (-1 == link)
		{
			// The ANN gave the client a CubeAddress that isn't our neighbor, so bail
			nbrState.state = CubeMessage.Type.CONN_NBR_ANN_FAIL;
			send(new CubeMessage(cubeState.addr, nbrState.ann, nbrState.state, nAddr));
			return;
		}

		// Set up my neighbor information and Cube state
		try
		{
			// The ANN connection is already registered; re-registering here will throw a CanceledKeyException
			if (!cubeState.addr.equals(nbrState.ann))
				listener.register(chan);
		} catch (IOException e)
		{
			// Bail
			nbrState.state = CubeMessage.Type.CONN_NBR_ANN_FAIL;
			send(new CubeMessage(cubeState.addr, nbrState.ann, nbrState.state, nAddr));
			return;
		}

		// Success!
		nbrState.addr = nAddr;
		cubeState.addNeighbor(link, chan);

		// Update the ANN
		nbrState.state = CubeMessage.Type.CONN_NBR_ANN_SUCCESS;
		send(new CubeMessage(cubeState.addr, nbrState.ann, nbrState.state, nAddr));
	}

	/**
	 * Neighbor must respond to client declining connection.
	 * 
	 * Algorithm: close the connection and report failure to the ANN
	 */
	private void conn_ext_nbr_nak(CubeMessage msg)
	{
		// No need to check anything, since all paths lead to...
		SocketChannel chan = msg.getChannel();
		InetSocketAddress addr = quietAddr(chan);
		quietClose(chan);
		NbrState state = nbrStates.remove(addr);
		send(new CubeMessage(cubeState.addr, state.ann, CubeMessage.Type.CONN_NBR_ANN_FAIL, addr));
	}

	/**
	 * ANN must respond to neighbor notice of successful client connection. This method is the entry point to Phase 5.
	 * 
	 * Algorithm: record this fact, and if all neighbors have reported in, instruct them to advertise their
	 * CubeAddresses
	 */
	private void conn_nbr_ann_success(CubeMessage msg)
	{
		// Validate the message
		InetSocketAddress addr = validateMsg(msg, annStates, phase4ANNstates);
		if (null == addr)
			return;
		ANNState annState = annStates.get(addr);

		// Record the success and check for Phase 5
		if (++annState.success + annState.invalid.size() < cubeState.dim)
			return;

		// Enter Phase 5: send success message to client and set up Neighbor state
		annState.state = CubeMessage.Type.CONN_ANN_EXT_SUCCESS;
		send(new CubeMessage(cubeState.addr, annState.peerAddr, annState.state, cubeState.dim));
		int link = cubeState.addr.relativeLink(annState.peerAddr);
		cubeState.addNeighbor(link, msg.getChannel());

		// Tell all neighbors to advertise their CubeAddresses
		annState.state = CubeMessage.Type.CONN_ANN_NBR_ADV;
		annBcast(annState, addr);

		// Inform the INN of our success
		annState.state = CubeMessage.Type.CONN_ANN_INN_SUCCESS;
		send(new CubeMessage(cubeState.addr, annState.inn, annState.state, addr));
	}

	/**
	 * ANN must respond to neighbor indication of failed SocketChannel to client.
	 * 
	 * Algorithm: instruct all neighbors to tear down their connections, and inform client and INN
	 */
	private void conn_nbr_ann_fail(CubeMessage msg)
	{
		// Validate the message
		InetSocketAddress addr = validateMsg(msg, annStates, phase4ANNstates);
		if (null == addr)
			return;

		// Clean up our state and bail on the client
		ANNState annState = annStates.remove(addr);
		int link = cubeState.addr.relativeLink(annState.peerAddr);
		SocketChannel chan = cubeState.neighbors.remove(link);
		annState.state = CubeMessage.Type.CONN_ANN_EXT_FAIL;
		new CubeMessage(CubeAddress.INVALID_ADDRESS, annState.peerAddr, annState.state, null).send(chan);
		quietClose(chan);

		// Bail on the neighbors and the INN
		annBail(addr);
	}

	/*
	 * Phase 5 methods
	 */

	/**
	 * Client must respond to ANN indicating successful connection.
	 * 
	 * Algorithm: set the Cube dimension and clean up client connection state
	 */
	private void conn_ann_ext_success(CubeMessage msg)
	{
		// Validate the message
		Integer dim = (Integer) validateInt(msg, phase5CLTstates);
		if (null == dim)
			return;
		cubeState.dim = (Integer) msg.getData();

		// Clean up client state. Don't close the annChan, since the ANN is our neighbor
		quietClose(cltState.innChan);
		cltState = null;
	}

	/**
	 * Neighbor must respond to ANN instruction to advertise CubeAddress to client.
	 * 
	 * Algorithm: send CubeAddress to client
	 */
	private void conn_ann_nbr_adv(CubeMessage msg)
	{
		// Validate the message
		InetSocketAddress addr = validateMsg(msg, nbrStates, phase5NBRstates);
		if (null == addr)
			return;

		// Authenticate the source address
		NbrState nbrState = nbrStates.get(addr);
		if (!nbrState.ann.equals(msg.getSrc()))
		{
			reply(msg, CubeMessage.Type.INVALID_MSG, msg.getType());
			return;
		}

		// Advertise my CubeAddress
		nbrState.state = CubeMessage.Type.CONN_NBR_EXT_OFFER;
		new CubeMessage(cubeState.addr, nbrState.addr, nbrState.state, null).send(nbrState.chan);
	}

	/**
	 * INN must respond to an indication of successful address negotiation from an ANN.
	 * 
	 * Algorithm: Close the client SocketChannel
	 */
	private void conn_ann_inn_success(CubeMessage msg)
	{
		// Validate the message
		InetSocketAddress addr = validateMsg(msg, innStates, phase1INNstates);
		if (null == addr)
			return;

		// Authenticate the source
		INNState innState = innStates.get(addr);
		if (!innState.ann.equals(msg.getSrc()))
		{
			reply(msg, CubeMessage.Type.INVALID_MSG, msg.getType());
			return;
		}

		// Close the client socket
		quietClose(innState.chan);

		// Inform the other willing ANNs that they can flush state
		innState.state = CubeMessage.Type.CONN_INN_ANN_SUCCESS;
		for (CubeAddress ackAddr : innState.acked)
			send(new CubeMessage(cubeState.addr, ackAddr, innState.state, addr));

		// Clean up my own state
		innStates.remove(addr);
	}

	/**
	 * Client must respond to neighbor's indication of its CubeAddress
	 * 
	 * Algorithm: add the new neighbor to my Cube state
	 */
	private void conn_nbr_ext_ack(CubeMessage msg)
	{
		// Validate the message
		validateInt(msg, phase5CLTstates);
		CubeAddress nAddr = msg.getSrc();
		SocketChannel chan = msg.getChannel();
		if (!chan.isOpen())
			return;

		// Is the advertised address actually my neighbor?
		int link = cubeState.addr.relativeLink(nAddr);
		if (-1 == link)
		{
			new CubeMessage(cubeState.addr, CubeAddress.INVALID_ADDRESS, CubeMessage.Type.INVALID_DATA,
					new CubeAddress[] { cubeState.addr, nAddr }).send(chan);
			quietClose(chan);
			return;
		}

		// Update the Cube state
		cubeState.addNeighbor(link, chan);
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
		if (null == cltState)
			return;

		// Don't close the INN connection, but do close all neighbor connections
		for (SocketChannel chan : cltState.nbrChans)
			quietClose(chan);
	}

	/**
	 * Neighbor must respond to ANN indication that a failure occurred.
	 * 
	 * Algorithm: clean up connection state
	 */
	private void conn_ann_nbr_fail(CubeMessage msg)
	{
		// Validate the message
		InetSocketAddress addr = validateMsg(msg, nbrStates, null);
		if (null == addr)
			return;

		// It's valid, shut everything down
		NbrState nbrState = nbrStates.get(addr);
		SocketChannel chan = nbrState.chan;
		if (chan.isOpen())
			quietClose(chan);
		nbrStates.remove(chan);
	}

	/**
	 * INN must respond to ANN indication that a failure occurred.
	 * 
	 * Algorithm: ask a different node at the same hop count to be ANN; if none remain, increase the hop count
	 */
	private void conn_ann_inn_fail(CubeMessage msg)
	{
		// Validate the message
		InetSocketAddress addr = validateMsg(msg, innStates, phase1INNstates);
		if (null == addr)
			return;

		// Validate the source
		INNState innState = innStates.get(addr);
		if (!innState.ann.equals(msg.getSrc()))
		{
			reply(msg, CubeMessage.Type.INVALID_MSG, msg.getType());
			return;
		}

		// Find another ANN
		innState.unwilling.add(innState.ann);
		innState.ann = innState.acked.remove(0);
		if (null != innState.ann)
			send(new CubeMessage(cubeState.addr, innState.ann, innState.state, addr));
		
		// If we get here, we need to increase the hop count and rebroadcast
		check_expand(addr);
	}

	// Ensure that a CubeMessage data has the proper type
	private boolean checkMsg(CubeMessage msg, Class<?> clz)
	{
		return null == clz || null != msg.getData() && msg.getData().getClass().isAssignableFrom(clz);
	}

	/**
	 * Message / state validation helper for intra-Cube messages
	 * 
	 * @param msg
	 *            The message to validate
	 * @param stateMap
	 *            innStates, annStates, or nbrStates
	 * @param states
	 *            individual states to check against, or null if we should initialize state
	 * @return
	 */
	private InetSocketAddress validateMsg(CubeMessage msg, HashMap<InetSocketAddress, ? extends State> stateMap,
			List<CubeMessage.Type> states)
	{
		// Ensure the message is properly formatted
		if (!checkMsg(msg, InetSocketAddress.class))
		{
			reply(msg, CubeMessage.Type.INVALID_MSG, msg.getType());
			return null;
		}
		InetSocketAddress addr;
		if (msg.getData() instanceof InetSocketAddress)
			addr = (InetSocketAddress) msg.getData();
		else
			// See CONN_NBR_ANN_ACK
			addr = (InetSocketAddress) ((Serializable[]) msg.getData())[0];

		// Ensure we are in the correct state
		State state = stateMap.get(addr);
		if (null == state)
		{
			if (null == states)
				return addr;
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
	 * Message / state validation helper for messages from an (internal) Cube node to a connecting client
	 * 
	 * @param msg
	 *            The message to validate
	 * @param states
	 *            individual states to check against
	 * @return
	 */
	private Object validateInt(CubeMessage msg, List<CubeMessage.Type> states)
	{
		// Ensure the message is properly formatted
		CubeAddress none = CubeAddress.INVALID_ADDRESS;
		SocketChannel chan = msg.getChannel();
		if (!checkMsg(msg, null))
		{
			new CubeMessage(cubeState.addr, none, CubeMessage.Type.INVALID_MSG, msg.getType()).send(chan);
			quietClose(chan);
			return null;
		}

		// Ensure we are in the correct state
		State state = cltState;
		if (null == state)
		{
			new CubeMessage(cubeState.addr, none, CubeMessage.Type.INVALID_STATE, new Enum[] { null, msg.getType() })
					.send(chan);
			quietClose(chan);
			return null;
		} else if (!states.contains(state.state))
		{
			new CubeMessage(cubeState.addr, none, CubeMessage.Type.INVALID_STATE,
					new Enum[] { state.state, msg.getType() }).send(chan);
			quietClose(chan);
			return null;
		}

		// Message format and current state are both valid
		return msg.getData();
	}

	/**
	 * Message / state validation helper for messages from an (external) connecting client to a Cube node
	 * 
	 * @param msg
	 *            The message to validate
	 * @param stateMap
	 *            annStates or nbrStates
	 * @param states
	 *            individual states to check against
	 * @return
	 */
	private Object validateExt(CubeMessage msg, HashMap<InetSocketAddress, ? extends State> stateMap,
			List<CubeMessage.Type> states)
	{
		// Ensure the message is properly formatted
		CubeAddress none = CubeAddress.INVALID_ADDRESS;
		SocketChannel chan = msg.getChannel();
		if (!checkMsg(msg, null))
		{
			new CubeMessage(none, msg.getSrc(), CubeMessage.Type.INVALID_MSG, msg.getType()).send(chan);
			quietClose(chan);
			return null;
		}

		// Ensure we are in the correct state
		InetSocketAddress addr = quietAddr(chan);
		State state = stateMap.get(addr);
		if (null == state)
		{
			if (null == states)
				return msg.getData();
			new CubeMessage(none, msg.getSrc(), CubeMessage.Type.INVALID_STATE, new Enum[] { null, msg.getType() })
					.send(chan);
			quietClose(chan);
			return null;
		} else if (!states.contains(state.state))
		{
			new CubeMessage(none, msg.getSrc(), CubeMessage.Type.INVALID_STATE,
					new Enum[] { state.state, msg.getType() }).send(chan);
			quietClose(chan);
			return null;
		}

		// Message format and current state are both valid
		return msg.getData();
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

	// Node 0 processing to connect Node 1, bypassing several layers of protocol
	@SuppressWarnings("unchecked")
	private void node1connect(CubeMessage msg)
	{
		InetSocketAddress addr = (InetSocketAddress) msg.getData();
		SocketChannel peerChan = msg.getChannel();
		CubeAddress none = CubeAddress.INVALID_ADDRESS;
		CubeAddress one = new CubeAddress("1");

		// Phase 1: successful, since I have identified an attachment point (myself)
		// Phase 2: check all neighbors (i.e., myself) for willingness to connect
		if (!amWilling(addr))
		{
			new CubeMessage(none, none, CubeMessage.Type.CONN_INN_EXT_CONN_REFUSED, null).send(peerChan);
			quietClose(peerChan);
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
			new CubeMessage(none, none, CubeMessage.Type.CONN_INN_EXT_CONN_REFUSED, null).send(peerChan);
			quietClose(peerChan);
			return;
		}
		Integer nonce = (int) (Math.random() * Integer.MAX_VALUE);
		ArrayList<Integer> nonces = new ArrayList<>();
		nonces.add(nonce);
		new CubeMessage(none, one, CubeMessage.Type.CONN_ANN_EXT_OFFER, nonces).send(annChan);
		msg = CubeMessage.recv(annChan);
		if (!CubeMessage.Type.CONN_EXT_ANN_ACK.equals(msg.getType()))
		{
			quietClose(annChan);
			new CubeMessage(none, none, CubeMessage.Type.CONN_INN_EXT_CONN_REFUSED, null).send(peerChan);
			quietClose(peerChan);
			return;
		}

		// Phase 4: offer to connect to the client and verify nonce
		new CubeMessage(none, one, CubeMessage.Type.CONN_NBR_EXT_OFFER, null).send(annChan);
		msg = CubeMessage.recv(annChan);
		if (!CubeMessage.Type.CONN_EXT_NBR_ACK.equals(msg.getType()) || null == msg.getData()
				|| !nonce.equals(((ArrayList<Integer>) msg.getData()).get(0)))
		{
			quietClose(annChan);
			new CubeMessage(none, none, CubeMessage.Type.CONN_INN_EXT_CONN_REFUSED, null).send(peerChan);
			quietClose(peerChan);
			return;
		}

		// Phase 5: reveal my CubeAddress and complete the connection
		cubeState.addNeighbor(0, annChan); // Side effect: updating the Cube dimension
		new CubeMessage(cubeState.addr, one, CubeMessage.Type.CONN_NBR_EXT_ACK, null).send(annChan);
		new CubeMessage(cubeState.addr, one, CubeMessage.Type.CONN_ANN_EXT_SUCCESS, cubeState.dim).send(annChan);
		try
		{
			listener.register(annChan);
		} catch (IOException e)
		{
			// If we can't register this channel after sending a boatload of messages, well...
			quietClose(annChan);
			return;
		}
	}

	/**
	 * Node must respond to sending an invalid address, depending on protocol state.
	 */
	private void invalid_address(CubeMessage msg)
	{
		Serializable[] data = (Serializable[]) msg.getData();
		CubeMessage.Type origType = (CubeMessage.Type) data[0];
		Serializable origData = data[1];

		// Process based on our type
		if (origType == CubeMessage.Type.DATA_MSG)
		{
			// Queue an "invalid" message
			queued.add(new CubeMessage(msg.getSrc(), msg.getDst(), CubeMessage.Type.INVALID_MSG, data));
			if (null != blockingThread)
				blockingThread.notify();
		}

		// Otherwise, we choked during the connection protocol
		if (origData instanceof InetSocketAddress)
		{
			InetSocketAddress addr = (InetSocketAddress) origData;
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

		// No idea how we got here...
		System.err.println("Got an invalid address...");
	}

	// Phases 2-4: Send a message to all prospective neighbors
	private void annBcast(ANNState annState, InetSocketAddress addr)
	{
		for (int i = 0; i < cubeState.dim; ++i)
		{
			// Determine each node's CubeAddress
			CubeAddress nbrAddr = annState.peerAddr.followLink(i);
			if (annState.invalid.contains(nbrAddr))
				continue;

			// Send the message
			send(new CubeMessage(cubeState.addr, nbrAddr, annState.state, addr));
		}
	}

	// Phases 2-4: Notify everyone if an ANN determines that a connection cannot be made
	private void annBail(InetSocketAddress addr)
	{
		ANNState annState = annStates.remove(addr);

		// Inform the neighbors
		annState.state = CubeMessage.Type.CONN_ANN_NBR_FAIL;
		annBcast(annState, addr);

		// Inform the INN
		annState.state = CubeMessage.Type.CONN_ANN_INN_FAIL;
		send(new CubeMessage(cubeState.addr, annState.inn, annState.state, addr));
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
		if (len == cubeState.dim + 1)
			cubeState.dim = len;

		// Add this message to my queue
		queued.add(msg);
		if (null != blockingThread)
			blockingThread.notify();
	}

	private void node_shutdown(CubeMessage msg)
	{
		// TODO

	}

	/*
	 * Protected and public methods
	 */

	/**
	 * Determine whether I am willing to allow a connection from a given address.
	 */
	protected boolean amWilling(InetSocketAddress addr)
	{
		return true;
	}

	/**
	 * Connect to a Cube. Prior to calling this method, the client application is expected to have determined the
	 * address of an Ingress Negotiation Node (INN) that is offering to connect clients to the Cube of interest.
	 * 
	 * @param innAddr
	 *            The address of an INN
	 * @throws CubeException
	 *             if either argument is <code>null</code>, or if a connection to the INN cannot be established
	 */
	public void connect(InetSocketAddress innAddr) throws CubeException
	{
		// Sanity checks
		if (null == innAddr)
			throw new CubeException("connect() called with null INN address");

		// Initialize client connection state
		cltState = new CltState();
		try
		{
			cltState.innChan = SocketChannel.open(innAddr);
		} catch (IOException e)
		{
			throw new CubeException("connect() unable to open a SocketChannel to " + innAddr);
		}
		cltState.state = CubeMessage.Type.CONN_EXT_INN_ATTACH;

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
	 * Send a {@link Message} to another node in the Cube. This method will return <code>true</code> when the
	 * <code>Message</code> was accepted by the Cube for delivery, not when it was actually accepted by the other node.
	 * If the {@link CubeAddress} of the <code>Message</code> refers to a non-connected node, the Cube will return a
	 * <code>Message</code>
	 * 
	 * @param msg
	 *            The <code>Message</code> to send
	 * @return whether the <code>Message</code> was sent into the node
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
		if (CubeAddress.ZERO.compareTo(msg.peer) > 0)
			throw new CubeException("send() called with invalid (negative) peer CubeAddress");

		// Send the message
		return send(new CubeMessage(cubeState.addr, msg.peer, CubeMessage.Type.DATA_MSG, msg.data));
	}

	/*
	 * Send a message through the Cube using Katseff Algorithm 3 (with LSB instead of MSB ordering). Invoking this
	 * method cannot divulge confidential address information to a non-connected node; at worst, using this method as a
	 * response to a forged request will send a message to another connected node, which will reply with INVALID_STATE.
	 */
	boolean send(CubeMessage msg)
	{
		// Check for idiocy and/or forged messages
		if (msg.getDst().bitLength() > cubeState.dim)
		{
			// Tried to send a message to a node outside the address space
			send(new CubeMessage(msg.getDst(), msg.getSrc(), CubeMessage.Type.INVALID_ADDRESS,
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
				send(new CubeMessage(msg.getDst(), msg.getSrc(), CubeMessage.Type.INVALID_ADDRESS,
						new Serializable[] { msg.getType(), msg.getData() }));
				return false;
			}
			return msg.send(cubeState.neighbors.get(link));
		}
	}

	// Reply to a message with a new message type and data
	void reply(CubeMessage request, CubeMessage.Type type, Serializable data)
	{
		send(new CubeMessage(cubeState.addr, request.getSrc(), type, data));
	}

	/**
	 * Broadcast a {@link Message} through the Cube.
	 * 
	 * @param msg
	 *            The <code>Message</code> to broadcast
	 * @return Whether the broadcast message was successfully sent
	 * @throws CubeException
	 *             if no Cube is connected
	 */
	public boolean broadcast(Message msg) throws CubeException
	{
		if (null == cubeState)
			throw new CubeException("broadcast() called on unconnected Cube");

		CubeMessage bcastMsg = new CubeMessage(cubeState.addr, null, CubeMessage.Type.DATA_MSG, msg.data);
		bcastMsg.setTravel(BigInteger.ZERO.setBit(cubeState.dim).subtract(BigInteger.ONE));
		return fwd_broadcast(bcastMsg);
	}

	// Utility method that forwards a broadcast message through the Cube using Katseff Algorithm 6.
	private boolean fwd_broadcast(CubeMessage msg)
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

		/*
		 * Spin until a message is received. Note that this method is called by a client application, not the
		 * MessageListener, so it won't block the protocol
		 */
		CubeMessage msg = null;
		while (true)
			try
			{
				blockingThread = Thread.currentThread();
				blockingThread.wait();
			} catch (InterruptedException e)
			{
				if (available())
				{
					msg = queued.remove(0);
					blockingThread = null;
					break;
				}
			}
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
