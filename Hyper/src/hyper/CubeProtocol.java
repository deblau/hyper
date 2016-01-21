package hyper;

import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.channels.SocketChannel;
import java.util.ArrayList;
import java.util.HashMap;

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
 * ingress negotiation nodes (INNs) that act as gateways for the new CubeAddress discovery process, and the
 * <code>InetAddress</code> of each of these INNs must be discoverable outside the protocol. The discovery process for
 * INNs is outside the scope of this protocol; Cube communities may develop their own standards. However, the protocol
 * nevertheless shields the revelation of any <code>CubeAddress</code> to a connecting client until the last possible
 * moment, after it has been approved to join the Cube.
 * </p>
 * 
 * <p>
 * The connection process operates in four phases.
 * </p>
 * 
 * <h4>Phase 1</h4>
 * <p>
 * The first phase has the goal of locating an attachment point for a new node, and is executed by the INN in response
 * to receiving a request from an external client to join the Cube. The INN relays, to other nodes in the Cube, the
 * request with the client's information, asking for any nodes that are both able to accept the connection (because they
 * have a vacancy in their connectivity table) and are willing to accept the connection (based on client information,
 * currently an {@link InetSocketAddress} of the client). This is done by sending broadcast {@link CubeMessage}s having
 * successively increasing hop counts, until at least one other node accepts the request. The INN designates this node
 * as the address negotiating node (ANN), and hands off the remainder of the process to the ANN. Because address
 * negotiation can fail, the ANN is required to reply with a success-or-fail status to the INN. If the negotiation
 * succeeds, the INN can terminate its participation in the addressing protocol, while if the negotiation fails, the INN
 * continues searching.
 * </p>
 * 
 * <p>
 * The INN itself will fail if there are no {@link CubeAddress}es whose neighbors are all willing and able to connect to
 * the new client. Willingness to connect is a potentially serious issue; for example, a node may wish to maintain a
 * blacklist of IP address blocks that are denied connections due to political or network routing efficiency concerns.
 * Therefore, the protocol guarantees that no Cube member shall be required to connect to any client for which it
 * signals an unwillingness to do so. This guarantee is implemented by having each ANN declare to the INN a failure to
 * connect the new client due to unwillingness of any of its potential neighbor nodes.
 * </p>
 * 
 * <p>
 * However, ability to connect (that is, whether there are any open links given the dimension of the Cube) is an issue
 * of address space size, which is easily fixed within the protocol. Therefore, an INN that cannot place the new client
 * in the Cube's existing address space will increase the dimension of the Cube. This is done by instructing a (randomly
 * selected) ANN, that indicated only an inability to attach the new client, to attach it anyway using a higher Cube
 * dimension.
 * </p>
 * 
 * <p>
 * <b>Security analysis</b>: During Phase 1, the new peer's {@link InetSocketAddress} is passed around, but its
 * {@link CubeAddress} has not been determined. Listening for nodes that accept responsibility as ANN does not reveal a
 * relationship, since it is not known whether the remaining Phases will be successful, and in any event the accepting
 * ANN might attach the new peer on any of a number of different <code>CubeAddress</code>es.
 * </p>
 * 
 * <h4>Phase 2</h4>
 * <p>
 * The second phase of the connection protocol is carried out by the ANN to find an acceptable {@link CubeAddress} for
 * the new node. The ANN first selects a vacant, neighbor <code>CubeAddress</code> as the possible address of the new
 * client. (Such an address exists, since either the ANN indicated ability to connect or the dimension of the Cube is
 * increasing.) The ANN then sends client connection requests to each neighbor of the possible address, asking only for
 * willingness to connect. (With a little thought, it can be seen that each such neighbor already is able to connect the
 * new address.) During this process, each willing neighbor transmits a random nonce to the ANN, used in the third phase
 * for authentication. If any prospective neighbor signals its unwillingness, the ANN chooses another potential
 * <code>CubeAddress</code> for the peer, and tries again. If all such addresses have at least one unwilling neighbor,
 * the ANN relays that information to the INN and the second phase terminates unsuccessfully for the ANN. (Thus, a
 * node's attitude toward connecting a given {@link InetSocketAddress} can go from merely unable, to unwilling,
 * depending on its two-hop neighbors.) In response to such an event, the INN resumes Phase 1 processing until it finds
 * a new ANN.
 * </p>
 * 
 * <p>
 * <b>Security analysis</b>: The ANN knows the {@link InetSocketAddress} of the peer, and selects its potential new
 * {@link CubeAddress}, however this is not a security threat because the ANN will be a neighbor to the peer, and
 * therefore must know this relationship anyway. The same can be said for each prospective new neighbor.
 * </p>
 * 
 * <p>
 * The relaying node between the ANN and each prospective new neighbor can determine the relationship based on traffic
 * analysis, provided all messages between the pairs pass through it. The number of such relay nodes that might pose a
 * security leak is <em>n</em>(<em>n</em>-1)/2=O(<em>n</em><sup>2</sup>), where <em>n</em> is the dimension of the Cube.
 * However, the number of nodes in the Cube grows as O(2<sup><em>n</em></sup>), which is exponentially faster.
 * Therefore, relative security <b>increases</b> as the Cube grows larger. [N.B. The protocol should probably be fixed
 * to require nodes to publish an encryption mechanism to encrypt traffic during this phase.]
 * </p>
 * 
 * <h4>Phase 3</h4>
 * <p>
 * The third phase of the connection protocol asks each potential new neighbor to actually establish a connection to the
 * new peer, prior to revealing its {@link CubeAddress}. This phase begins once an ANN finds a collection of nodes that
 * are willing (and able) to connect to the client. The ANN notifyies the new client of the client's new
 * <code>CubeAddress</code> and the list of nonces from its new neighbors. This is done without revealing the ANN's
 * <code>CubeAddress</code>, because the client cannot yet be trusted with that information. It is also done without
 * revealing an association between each nonce and a corresponding Cube node. Once the client acknowledges the address
 * and the nonces, the ANN communicates this fact to each of the new neighbors, who contact the client with empty
 * messages. In response, the new client must reply with both its new <code>CubeAddress</code> and the set of nonces.
 * Each neighbor verifies that (1) the new <code>CubeAddress</code> is a valid neighbor, and (2) that the list of nonces
 * contains the nonce generated by the neighbor and has length equal to the current dimension of the Cube. The neighbor
 * reports success or failure of the verification to the ANN.
 * </p>
 * 
 * <p>
 * <b>Security analysis</b>: Phase 3 communications within the Cube do not contain the {@link CubeAddress} of the
 * client, and communications outside the Cube do not contain the {@link CubeAddress} of any Cube node.
 * </p>
 * 
 * <h4>Phase 4</h4>
 * <p>
 * Once the ANN concludes that all verifications were successful, the final phase begins, in which each of the new
 * neighbors provides the client with its {@link CubeAddress}. The ANN goes first, then instructs the neighbors that it
 * is safe for them to provide their addresses as well.
 * </p>
 * 
 * <p>
 * <b>Security analysis</b>: All Phase 4 communications are done outside of the Cube; therefore, no other Cube nodes
 * have access to the relationship between {@link CubeAddress} and {@link InetSocketAddress}.
 * </p>
 */
public class CubeProtocol
{
	private CubeState cubeState = new CubeState();
	private HashMap<InetSocketAddress, INNState> innStates = new HashMap<>();
	private HashMap<InetSocketAddress, ANNState> annStates = new HashMap<>();
	private HashMap<InetSocketAddress, NbrState> nbrStates = new HashMap<>();
	private CltState cltState;
	private MessageListener listener;
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
		if (null != dst)
		{
			if (dst.compareTo(CubeAddress.ZERO_HOPS) <= 0)
				fwd_broadcast(msg);
			else if (!dst.equals(cubeState.addr))
				send(msg);
		}

		switch (msg.getType()) {
		case CONN_ANN_EXT_CONN_SUCC:
			conn_ann_ext_conn_succ(msg);
			break;
		case CONN_ANN_EXT_OFFER:
			conn_ann_ext_offer(msg);
			break;
		case CONN_ANN_INN_SUCC:
			conn_ann_inn_succ(msg);
			break;
		case CONN_ANN_INN_UNABLE:
			conn_ann_inn_unable(msg);
			break;
		case CONN_ANN_INN_UNWILLING:
			conn_ann_inn_unwilling(msg);
			break;
		case CONN_ANN_NEI_ADV:
			conn_ann_nei_adv(msg);
			break;
		case CONN_ANN_NEI_FAIL:
			conn_ann_nei_fail(msg);
			break;
		case CONN_ANN_NEI_NADV:
			conn_ann_nei_nadv(msg);
			break;
		case CONN_ANN_NEI_REQ:
			conn_ann_nei_req(msg);
			break;
		case CONN_ANN_NEI_SUCC:
			conn_ann_nei_succ(msg);
			break;
		case CONN_EXT_ANN_ACK:
			conn_ext_ann_ack(msg);
			break;
		case CONN_EXT_ANN_NAK:
			conn_ext_ann_nak(msg);
			break;
		case CONN_EXT_INN_REQ:
			conn_ext_inn_req(msg);
			break;
		case CONN_EXT_NEI_ACK:
			conn_ext_nei_ack(msg);
			break;
		case CONN_INN_ANN_HANDOFF:
			conn_inn_ann_handoff(msg);
			break;
		case CONN_INN_EXT_CONN_REFUSED:
			conn_inn_ext_conn_refused(msg);
			break;
		case CONN_INN_REQ_ANN:
			// Broadcast message
			conn_inn_req_ann(msg);
			break;
		case CONN_NEI_ANN_ACK:
			conn_nei_ann_ack(msg);
			break;
		case CONN_NEI_ANN_FAIL:
			conn_nei_ann_fail(msg);
			break;
		case CONN_NEI_ANN_NAK:
			conn_nei_ann_nak(msg);
			break;
		case CONN_NEI_ANN_SUCC:
			conn_nei_ann_succ(msg);
			break;
		case CONN_NEI_EXT_ACK:
			conn_nei_ext_ack(msg);
			break;
		case CONN_NEI_EXT_OFFER:
			conn_nei_ext_offer(msg);
			break;
		case CONN_NODE_INN_ACK:
			conn_node_inn_ack(msg);
			break;
		case CONN_NODE_INN_UNABLE:
			conn_node_inn_unable(msg);
			break;
		case CONN_NODE_INN_UNWILLING:
			conn_node_inn_unwilling(msg);
			break;
		case DATA_MSG:
			data_msg(msg);
			break;
		case INVALID_MSG:
			System.err.println(Thread.currentThread() + " received INVALID_MSG with data: (" + msg.getSrc() + ","
					+ msg.getData() + "," + msg.getData());
			break;
		default:
			System.err.println(Thread.currentThread() + " received unknown message type " + msg.getType());
			break;
		}
	}

	/*
	 * Phase 1 methods
	 */

	/**
	 * INN must respond to initial request from client to connect.
	 * 
	 * Algorithm: send a message to each of my neighbors, asking them to be ANN for this connection.
	 */
	private void conn_ext_inn_req(CubeMessage msg) throws IOException
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
			new CubeMessage(none, none, CubeMessage.Type.INVALID_STATE,
					new Enum[] { innStates.get(addr).state, msg.getType() }).send(chan);
			chan.close();
			return;
		}
		INNState innState = new INNState(chan);
		innStates.put(addr, innState);

		// Edge cases: I might be the only node in the Cube, or I might have an open slot
		if (cubeState.dim == 0 || cubeState.dim > cubeState.neighbors.size())
		{
			// Of course, I might not be willing...
			if (amWilling(addr))
			{
				// Fake a successful address negotiation
				ANNState annState = new ANNState(cubeState.addr);
				annState.state = CubeMessage.Type.CONN_NODE_INN_ACK;
				annStates.put(addr, annState);

				// Send myself a loop back message designating me as ANN, and enter Phase 2
				innState.state = CubeMessage.Type.CONN_INN_ANN_HANDOFF;
				msg = new CubeMessage(cubeState.addr, cubeState.addr, innState.state, addr);
				process(msg);
				return;
			}
		}

		// Regular processing: initialize state and send the initial broadcast messages
		innState.state = CubeMessage.Type.CONN_INN_REQ_ANN;
		msg = new CubeMessage(cubeState.addr, CubeAddress.ZERO_HOPS, innState.state, addr, cubeState.dim);
		for (Neighbor n : cubeState.neighbors)
			msg.send(n.chan);
	}

	/**
	 * Cube node must respond to INN broadcast request to become ANN and connect client.
	 * 
	 * Algorithm: determine whether I am able to connect, then whether I am willing to connect. Because the second
	 * determination could potentially take some time, do it last. Reply to the INN with the result.
	 * 
	 * @throws IOException
	 */
	private void conn_inn_req_ann(CubeMessage msg) throws IOException
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
		ANNState state = new ANNState(msg.getSrc());
		annStates.put(addr, state);

		// Am I able and willing to connect?
		if (cubeState.neighbors.size() == cubeState.dim)
		{
			state.state = CubeMessage.Type.CONN_NODE_INN_UNABLE;
			reply(msg, state.state, addr);
		} else if (amWilling(addr))
		{
			state.state = CubeMessage.Type.CONN_NODE_INN_ACK;
			reply(msg, state.state, addr);
		} else
		{
			reply(msg, CubeMessage.Type.CONN_NODE_INN_UNWILLING, addr);
			annStates.remove(addr);
		}
	}

	/**
	 * INN must respond to Cube node indicating willingness and ability to be ANN.
	 * 
	 * Algorithm: hand off negotiation to Cube node to begin Phase 2
	 */
	private void conn_node_inn_ack(CubeMessage msg) throws IOException
	{
		// Ensure the message is properly formatted; don't check source (reply to broadcast)
		if (!checkMsg(msg, null, InetSocketAddress.class))
		{
			reply(msg, CubeMessage.Type.INVALID_MSG, msg.getType());
			return;
		}
		InetSocketAddress addr = (InetSocketAddress) msg.getData();

		// Ensure we are in the correct state
		INNState state = innStates.get(addr);
		if (null == state)
		{
			reply(msg, CubeMessage.Type.INVALID_STATE, new Enum[] { null, msg.getType() });
			return;
		} else if (state.state != CubeMessage.Type.CONN_INN_REQ_ANN
				&& state.state != CubeMessage.Type.CONN_INN_ANN_HANDOFF)
		{
			// This is a reply to a broadcast message that could be late, so silently ignore it
			return;
		}

		// Hand off to this node, provided we aren't already using someone else as ANN
		if (state.state == CubeMessage.Type.CONN_INN_REQ_ANN)
		{
			state.state = CubeMessage.Type.CONN_INN_ANN_HANDOFF;
			reply(msg, state.state, addr);
		} else
			// Add this response to the list of willing nodes to use in case the current one doesn't pan out
			state.acked.add(msg.getSrc());
	}

	/**
	 * INN must respond to Cube node indicating its inability to act as ANN.
	 * 
	 * Algorithm: record this fact, and determine whether to expand the Cube
	 */
	private void conn_node_inn_unable(CubeMessage msg) throws IOException
	{
		// Ensure the message is properly formatted; don't check source (reply to broadcast)
		if (!checkMsg(msg, null, InetSocketAddress.class))
		{
			reply(msg, CubeMessage.Type.INVALID_MSG, msg.getType());
			return;
		}
		InetSocketAddress addr = (InetSocketAddress) msg.getData();

		// Ensure we are in the correct state
		INNState state = innStates.get(addr);
		if (null == state)
		{
			reply(msg, CubeMessage.Type.INVALID_STATE, new Enum[] { null, msg.getType() });
			return;
		} else if (state.state != CubeMessage.Type.CONN_INN_REQ_ANN
				&& state.state != CubeMessage.Type.CONN_INN_ANN_HANDOFF)
		{
			// This is a reply to a broadcast message that could be late, so silently ignore it
			return;
		}

		// Add this response to the list of unable nodes
		state.unable.add(msg.getSrc());

		// If everyone is unable or unwilling, we might have to expand the Cube
		check_expand(addr);
	}

	/**
	 * INN must respond to Cube node indicating its unwillingness to act as ANN.
	 * 
	 * Algorithm: record this fact, and determine whether to expand the Cube
	 */
	private void conn_node_inn_unwilling(CubeMessage msg) throws IOException
	{
		// Ensure the message is properly formatted; don't check source (reply to broadcast)
		if (!checkMsg(msg, null, InetSocketAddress.class))
		{
			reply(msg, CubeMessage.Type.INVALID_MSG, msg.getType());
			return;
		}
		InetSocketAddress addr = (InetSocketAddress) msg.getData();

		// Ensure we are in the correct state
		INNState state = innStates.get(addr);
		if (null == state)
		{
			reply(msg, CubeMessage.Type.INVALID_STATE, new Enum[] { null, msg.getType() });
			return;
		} else if (state.state != CubeMessage.Type.CONN_INN_REQ_ANN
				&& state.state != CubeMessage.Type.CONN_INN_ANN_HANDOFF)
		{
			// This is a reply to a broadcast message that could be late, so silently ignore it
			return;
		}

		// Add this response to the list of unwilling nodes
		state.unwilling.add(msg.getSrc());

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
		// Ensure the message is properly formatted
		if (!checkMsg(msg, null, InetSocketAddress.class))
		{
			reply(msg, CubeMessage.Type.INVALID_MSG, null);
			return;
		}
		InetSocketAddress addr = (InetSocketAddress) msg.getData();
		ANNState annState = annStates.get(addr);

		// Ensure we are in the correct state
		if (null == annState)
		{
			reply(msg, CubeMessage.Type.INVALID_STATE, new Enum[] { null, msg.getType() });
			return;
		} else if (annState.state != CubeMessage.Type.CONN_NODE_INN_ACK
				&& annState.state != CubeMessage.Type.CONN_NODE_INN_UNABLE)
		{
			reply(msg, CubeMessage.Type.INVALID_STATE, new Enum[] { annState.state, msg.getType() });
			return;
		}
		annState.state = CubeMessage.Type.CONN_ANN_NEI_REQ;

		// Determine (1) whether this join will expand the Cube, and (2) the new CubeAddress of the client
		boolean isExpanding = cubeState.neighbors.size() == cubeState.dim;
		int link = isExpanding ? cubeState.dim : cubeState.links.not().getLowestSetBit();
		annState.peerAddr = cubeState.addr.followLink(link);

		// Edge case: I'm the only node in the Cube (I'm already willing to connect)
		if (0 == cubeState.dim)
		{
			// Skip ahead in the protocol
			// NbrState nbrState = new NbrState(cubeState.addr, addr, (int) (Math.random() * Integer.MAX_VALUE));
			// nbrState.state = CubeMessage.Type.CONN_NEI_ANN_ACK;
			// nbrStates.put(addr, nbrState);
			//
			// annState.state = CubeMessage.Type.CONN_ANN_NEI_SUCC;
			// send(new CubeMessage(cubeState.addr, cubeState.addr, annState.state, addr));
			// return;
		}

		// Determine whether all of the new peer's neighbors are willing to accept the connection
		for (int i = 0; i < cubeState.dim; ++i)
		{
			// Determine the new neighbor's CubeAddress
			CubeAddress nbrAddr = annState.peerAddr.followLink(i);

			// Ask them if the are willing to connect
			send(new CubeMessage(cubeState.addr, nbrAddr, annState.state, addr));
		}
	}

	// if (amWilling(addr))
	// {
	// SocketChannel annChan = SocketChannel.open(addr);
	//
	// ArrayList<Integer> nonces = new ArrayList<>();
	// int nonce = (int) (Math.random() * Integer.MAX_VALUE);
	// nonces.add(nonce);
	// CubeAddress none = CubeAddress.INVALID_ADDRESS;
	// state.state = CubeMessage.Type.CONN_ANN_EXT_OFFER;
	// new CubeMessage(none, state.peerAddr, state.state, nonces).send(annChan);
	// }

	// Check whether we need to expand the dimension of the cube
	private void check_expand(InetSocketAddress clientAddr) throws IOException
	{
		INNState state = innStates.get(clientAddr);
		int unable = state.unable.size();
		int unwill = state.unwilling.size();

		// Have we contacted everyone yet?
		if (state.hops < cubeState.dim)
		{
			// Nope. Don't increase the hop count unless we've contacted enough cubes
			if (unable + unwill <= 1 << (state.hops - 1))
				return;

			// Increase the hop count
			++state.hops;
			CubeAddress hopAddr = new CubeAddress(Integer.toString(-state.hops));
			CubeMessage msg = new CubeMessage(cubeState.addr, hopAddr, CubeMessage.Type.CONN_INN_REQ_ANN, clientAddr,
					cubeState.dim);
			for (Neighbor n : cubeState.neighbors)
				msg.send(n.chan);
		}

		// Find someone who's willing to take the new guy (including possibly me)
		if (amWilling(clientAddr))
			state.unable.add(cubeState.addr);
		while (state.unable.size() > 0)
		{
			int index = (int) (Math.random() * state.unable.size());
			CubeAddress addr = state.unable.remove(index);

			// Ensure the index is not adjacent to someone who is unwilling
			for (int i = 0; i < cubeState.dim; ++i)
				if (state.unwilling.contains(addr.followLink(i)))
					break;

			// If we get here, we've got our node
			send(new CubeMessage(cubeState.addr, addr, CubeMessage.Type.CONN_INN_ANN_EXPAND, clientAddr));
			return;
		}

		// If we get here, it's impossible to attach to the cube; deny the connection
		CubeAddress none = CubeAddress.INVALID_ADDRESS;
		new CubeMessage(none, none, CubeMessage.Type.CONN_INN_EXT_CONN_REFUSED, null).send(state.chan);
		innStates.remove(clientAddr).chan.close();
	}

	/*
	 * Phase 2 methods
	 */

	/**
	 * Client must respond to ANN indication that connection has finished.
	 * 
	 * Algorithm: store the Cube's dimension and close the connection to the INN and ANN
	 */
	private void conn_ann_ext_conn_succ(CubeMessage msg) throws IOException
	{
		// Ensure the message is properly formatted
		cltState.annChan = msg.getChannel();
		CubeAddress none = CubeAddress.INVALID_ADDRESS;
		if (!checkMsg(msg, null, cubeState.addr, Integer.class))
		{
			new CubeMessage(none, none, CubeMessage.Type.INVALID_MSG, msg).send(cltState.annChan);
			cltState.annChan.close();
			return;
		}

		// Ensure we are in the correct state
		if (cltState.state != CubeMessage.Type.CONN_EXT_ANN_ACK)
		{
			new CubeMessage(none, none, CubeMessage.Type.INVALID_STATE,
					new Enum[] { cltState.state, CubeMessage.Type.CONN_ANN_EXT_OFFER }).send(cltState.annChan);
			cltState.annChan.close();
			return;
		}

		// Set the dimension and clean up
		cubeState.dim = (int) msg.getData();
		cltState.annChan.close();
		cltState.innChan.close();
		cltState = null;
	}

	/**
	 * Client must respond to an offer of a new CubeAddress from an ANN.
	 * 
	 * Algorithm: acknowledge the offer
	 */
	@SuppressWarnings("unchecked")
	private void conn_ann_ext_offer(CubeMessage msg) throws IOException
	{
		// Ensure the message is properly formatted
		cltState.annChan = msg.getChannel();
		CubeAddress none = CubeAddress.INVALID_ADDRESS;
		if (!checkMsg(msg, none, null, ArrayList.class))
		{
			new CubeMessage(none, none, CubeMessage.Type.INVALID_MSG, msg).send(cltState.annChan);
			cltState.annChan.close();
			return;
		}

		// Ensure we are in the correct state
		if (cltState.state != CubeMessage.Type.CONN_EXT_INN_REQ)
		{
			new CubeMessage(none, none, CubeMessage.Type.INVALID_STATE,
					new Enum[] { cltState.state, CubeMessage.Type.CONN_ANN_EXT_OFFER }).send(cltState.annChan);
			cltState.annChan.close();
			return;
		}

		// Accept the offer
		cubeState.addr = msg.getDst();
		cltState.nonces = (ArrayList<Integer>) msg.getData();
		cltState.state = CubeMessage.Type.CONN_EXT_ANN_ACK;
		new CubeMessage(cubeState.addr, none, cltState.state, null).send(cltState.annChan);
	}

	/**
	 * INN must respond to an indication of successful address negotiation from an ANN.
	 * 
	 * Algorithm: Close the client SocketChannel
	 */
	private void conn_ann_inn_succ(CubeMessage msg)
	{
		// Ensure we are in the correct state

	}

	/**
	 * INN must respond to node unable to be ANN.
	 * 
	 * Algorithm: ask a different node at the same hop count to be ANN; if none remain, increase the hop count
	 */
	private void conn_ann_inn_unable(CubeMessage msg)
	{
		// Ensure we are in the correct state

	}

	/**
	 * INN must respond to node unwilling to be ANN.
	 * 
	 * Algorithm: ask a different node at the same hop count to be ANN; if none remain, increase the hop count
	 */
	private void conn_ann_inn_unwilling(CubeMessage msg)
	{
		// Ensure we are in the correct state

	}

	/**
	 * Neighbor must respond to ANN instruction to advertise CubeAddress to client.
	 * 
	 * Algorithm: send CubeAddress to client
	 */
	private void conn_ann_nei_adv(CubeMessage msg)
	{
		// Ensure we are in the correct state

	}

	/**
	 * Neighbor must respond to ANN indication that a different neighbor did not connect to the client.
	 * 
	 * Algorithm: clean up connection state
	 */
	private void conn_ann_nei_fail(CubeMessage msg)
	{
		// Ensure we are in the correct state

	}

	/**
	 * Neighbor must respond to ANN instruction /not/ to advertise CubeAddress to client.
	 * 
	 * Algorithm: clean up connection state, including disconnecting client if already connected
	 */
	private void conn_ann_nei_nadv(CubeMessage msg)
	{
		// Ensure we are in the correct state

	}

	/**
	 * Neighbor must respond to ANN request for willingness to connect.
	 * 
	 * Algorithm: return whether neighbor is willing
	 */
	private void conn_ann_nei_req(CubeMessage msg)
	{
		// Ensure we are in the correct state

	}

	/**
	 * Neighbor must respond to ANN indication that all neighbors have successfully connected.
	 * 
	 * Algorithm: clean up connection state
	 */
	private void conn_ann_nei_succ(CubeMessage msg)
	{
		// Ensure we are in the correct state

	}

	/**
	 * ANN must respond to acknowledgment of CubeAddress from client.
	 * 
	 * Algorithm: instruct new neighbors to contact the client to verify nonces
	 */
	private void conn_ext_ann_ack(CubeMessage msg) throws IOException
	{
		// Ensure the message is properly formatted
		SocketChannel chan = msg.getChannel();
		CubeAddress none = CubeAddress.INVALID_ADDRESS;
		if (!checkMsg(msg, none, none, InetSocketAddress.class))
		{
			new CubeMessage(none, none, CubeMessage.Type.INVALID_MSG, null).send(chan);
			chan.close();
			return;
		}

		// Ensure my state is correct
		if (innStates.containsKey(addr))
		{
			new CubeMessage(none, none, CubeMessage.Type.INVALID_STATE,
					new Enum[] { innStates.get(addr).state, CubeMessage.Type.CONN_EXT_INN_REQ }).send(chan);
			chan.close();
			return;
		}

		// Edge case: if I am Node Zero, I have no neighbors!
		if (0 == cubeState.dim)
		{
			// Reply (skip verifying the nonce)
			++cubeState.dim;
			reply(msg, CubeMessage.Type.CONN_NEI_EXT_ACK, cubeState.dim);

			return;
		}

		// Send success message to the new neighbors
		for (Neighbor n : cubeState.neighbors)
			send(new CubeMessage(cubeState.addr, n.addr, CubeMessage.Type.CONN_ANN_NEI_SUCC,
					msg.getChannel().getRemoteAddress()));
	}

	/**
	 * ANN must respond to declining of CubeAddress from client.
	 * 
	 * Algorithm: indicate this fact to INN
	 */
	private void conn_ext_ann_nak(CubeMessage msg) throws IOException
	{

	}

	/**
	 * Neighbor must respond to client acknowledging connection
	 * 
	 * Algorithm: if my nonce is listed, report negotiation success to ANN; otherwise, report negotiation failure
	 * 
	 * @throws IOException
	 */
	private void conn_ext_nei_ack(CubeMessage msg) throws IOException
	{
		// Ensure we are in the correct state
		CubeAddress client = msg.getSrc();
		SocketChannel chan = msg.getChannel();
		NbrState state = nbrStates.get(client);
		if (null == state || state.state != CubeMessage.Type.CONN_NEI_EXT_OFFER)
		{
			new CubeMessage(CubeAddress.INVALID_ADDRESS, client, CubeMessage.Type.INVALID_STATE,
					new Enum[] { annStates.get(client).state, CubeMessage.Type.CONN_INN_REQ_ANN });
			if (null != state)
				new CubeMessage(cubeState.addr, state.ann, CubeMessage.Type.CONN_NEI_ANN_FAIL, chan.getLocalAddress());
			return;
		}

		// Ensure the message is properly formatted
		if (!checkMsg(msg, client, CubeAddress.INVALID_ADDRESS, ArrayList.class))
		{
			new CubeMessage(CubeAddress.INVALID_ADDRESS, client, CubeMessage.Type.INVALID_MSG, null);
			new CubeMessage(cubeState.addr, state.ann, CubeMessage.Type.CONN_NEI_ANN_FAIL, chan.getLocalAddress());
			return;
		}
		@SuppressWarnings("unchecked")
		ArrayList<Integer> replyNonces = (ArrayList<Integer>) msg.getData();

		// Determine whether the reply includes my nonce
		int link = client.relativeLink(cubeState.addr);
		if (replyNonces.size() != 1 || replyNonces.contains(state.nonce))
		{
			new CubeMessage(CubeAddress.INVALID_ADDRESS, client, CubeMessage.Type.INVALID_DATA, null);
			new CubeMessage(cubeState.addr, state.ann, CubeMessage.Type.CONN_NEI_ANN_FAIL, chan.getLocalAddress());
			return;
		}

		// Set up my neighbor information and Cube state
		Neighbor n = new Neighbor(client, chan);
		cubeState.neighbors.add(link, n);
		cubeState.links = new CubeAddress(cubeState.links.setBit(link).toString());
		listener.register(chan);

		// Update the ANN
		state.state = CubeMessage.Type.CONN_NEI_ANN_SUCC;
		send(new CubeMessage(cubeState.addr, state.ann, state.state, client));
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
	 * ANN must respond to neighbor indication of willingness to connect to client.
	 * 
	 * Algorithm: record this fact, and if all neighbors have reported in, move to Phase 3
	 */
	private void conn_nei_ann_ack(CubeMessage msg)
	{
		// Ensure we are in the correct state

	}

	/**
	 * ANN must respond to neighbor indication of failed SocketChannel to client.
	 * 
	 * Algorithm: instruct all neighbors to tear down their connections, and inform client and INN
	 */
	private void conn_nei_ann_fail(CubeMessage msg)
	{
		// Ensure we are in the correct state

	}

	/**
	 * ANN must respond to neighbor indication of unwillingness to connect to client.
	 * 
	 * Algorithm: clean up state and inform INN
	 */
	private void conn_nei_ann_nak(CubeMessage msg)
	{
		// Ensure we are in the correct state

	}

	/**
	 * ANN must respond to neighbor indication of successful SocketChannel to client.
	 * 
	 * Algorithm: record this fact, and if all neighbors have reported in, instruct them to advertise their
	 * CubeAddresses
	 */
	private void conn_nei_ann_succ(CubeMessage msg)
	{
		// Ensure we are in the correct state

	}

	/**
	 * Client must respond to neighbor's indication of its CubeAddress
	 * 
	 * Algorithm: store this information
	 */
	private void conn_nei_ext_ack(CubeMessage msg) throws IOException
	{
		// Ensure the message is properly formatted
		CubeAddress nAddr = msg.getSrc();
		SocketChannel chan = msg.getChannel();
		CubeAddress none = CubeAddress.INVALID_ADDRESS;
		if (!checkMsg(msg, nAddr, cubeState.addr, null))
		{
			new CubeMessage(cubeState.addr, none, CubeMessage.Type.INVALID_MSG, msg).send(chan);
			chan.close();
			cltState.annChan.close();
			return;
		}

		// Ensure we are in the correct state
		if (cltState.state != CubeMessage.Type.CONN_EXT_ANN_ACK)
		{
			new CubeMessage(cubeState.addr, none, CubeMessage.Type.INVALID_STATE,
					new Enum[] { cltState.state, CubeMessage.Type.CONN_NEI_EXT_ACK }).send(chan);
			chan.close();
			cltState.annChan.close();
			return;
		}

		// Is the advertised address actually my neighbor?
		int link = cubeState.addr.relativeLink(nAddr);
		if (-1 == link)
		{
			new CubeMessage(cubeState.addr, none, CubeMessage.Type.INVALID_DATA,
					new CubeAddress[] { cubeState.addr, nAddr }).send(chan);
			chan.close();
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
	 * Client must respond to neighbor's offer to connect.
	 * 
	 * Algorithm: respond with the correct message (including the nonces), if we're willing to accept the connection
	 */
	private void conn_nei_ext_offer(CubeMessage msg) throws IOException
	{
		// Ensure the message is properly formatted
		SocketChannel chan = msg.getChannel();
		CubeAddress none = CubeAddress.INVALID_ADDRESS;
		if (!checkMsg(msg, none, cubeState.addr, null))
		{
			new CubeMessage(none, none, CubeMessage.Type.INVALID_MSG, msg).send(chan);
			chan.close();
			cltState.annChan.close();
			return;
		}

		// Ensure we are in the correct state
		if (cltState.state != CubeMessage.Type.CONN_EXT_ANN_ACK)
		{
			new CubeMessage(none, none, CubeMessage.Type.INVALID_STATE,
					new Enum[] { cltState.state, CubeMessage.Type.CONN_NEI_EXT_OFFER }).send(chan);
			chan.close();
			cltState.annChan.close();
			return;
		}

		// Are we willing to make this connection?
		cltState.nbrChans.add(chan);
		if (amWilling((InetSocketAddress) chan.getLocalAddress()))
			new CubeMessage(cubeState.addr, none, CubeMessage.Type.CONN_EXT_NEI_ACK, cltState.nonces).send(chan);
		else
		{
			// Close existing channels and wait for new ANN to contact me to try again
			new CubeMessage(cubeState.addr, none, CubeMessage.Type.CONN_EXT_NEI_NAK, null).send(chan);
			for (SocketChannel c : cltState.nbrChans)
				c.close();
			cltState.annChan.close();
		}
	}

	/**
	 * Client must respond to received data message.
	 * 
	 * Algorithm: if the message is meant for me, add it to my local received message queue; otherwise, forward it.
	 */
	private void data_msg(CubeMessage msg) throws IOException
	{
		/*
		 * Lazily update Cube dimension. Worst case scenario: a neighbor maliciously sends forged CubeMessages having
		 * ever-increasing source addresses. In this case, the neighbor will become able to support many new
		 * connections.
		 */
		int len = msg.getSrc().bitCount();
		if (len == cubeState.dim + 1)
			cubeState.dim = len;

		// If this message is for someone else, forward it, otherwise add it to my queue
		if (!cubeState.addr.equals(msg.getDst()))
		{
			System.err.println(Thread.currentThread() + " ==> forwarding ");
			send(msg);
		} else
			queued.add(msg);
	}

	/*
	 * Utility methods
	 */

	// Ensure that a CubeMessage has the proper source, destination, and state
	private boolean checkMsg(CubeMessage msg, CubeAddress src, Class<?> clz)
	{
		return (src == null || msg.getSrc().equals(src))
				&& (null == clz || null != msg.getData() && msg.getData().getClass().isAssignableFrom(clz));
	}

	// Join a connecting client to this node (acting as ANN), expanding if necessary
	private boolean join_client(InetSocketAddress addr) throws IOException
	{
		// Receive and check the reply
		CubeMessage reply = CubeMessage.recv(annChan);
		if (reply.getType() != CubeMessage.Type.CONN_EXT_ANN_ACK
				|| !checkMsg(reply, peer, CubeAddress.INVALID_ADDRESS, null))
		{
			annChan.close();
			return false;
		}

		// Send an offer to connect (as a new neighbor)
		SocketChannel nbrChan = SocketChannel.open(addr);
		new CubeMessage(none, peer, CubeMessage.Type.CONN_NEI_EXT_OFFER, null).send(nbrChan);
		reply = CubeMessage.recv(nbrChan);
		if (reply.getType() != CubeMessage.Type.CONN_EXT_NEI_ACK
				|| !checkMsg(reply, peer, CubeAddress.INVALID_ADDRESS, ArrayList.class))
		{
			annChan.close();
			return false;
		}
		@SuppressWarnings("unchecked")
		ArrayList<Integer> replyNonces = (ArrayList<Integer>) reply.getData();
		if (replyNonces.size() != 1 || replyNonces.get(0) != nonce)
		{
			annChan.close();
			return false;
		}

		// Set up my neighbor information and Cube state
		Neighbor n = new Neighbor(peer, nbrChan);
		if (isExpanding)
			cubeState.neighbors.setSize(cubeState.dim++);
		cubeState.neighbors.add(link, n);
		cubeState.links = new CubeAddress(cubeState.links.setBit(link).toString());
		listener.register(nbrChan);

		// Complete the handshake
		new CubeMessage(cubeState.addr, peer, CubeMessage.Type.CONN_NEI_EXT_ACK, null).send(nbrChan);
		new CubeMessage(cubeState.addr, peer, CubeMessage.Type.CONN_ANN_EXT_CONN_SUCC, cubeState.dim).send(annChan);
		return true;
	}

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
		cltState.state = CubeMessage.Type.CONN_EXT_INN_REQ;
		new CubeMessage(CubeAddress.INVALID_ADDRESS, CubeAddress.INVALID_ADDRESS, cltState.state, myAddr)
				.send(cltState.innChan);
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
		if (msg.getDst().bitCount() > cubeState.dim)
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
				// Never happens
				System.err.println("Connectivity failure in send()!");
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
