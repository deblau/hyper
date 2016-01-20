package hyper;

import java.io.IOException;
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
 * The connection process operates in three phases.
 * </p>
 * 
 * <h4>Phase 1</h4>
 * <p>
 * The first phase is executed by the INN in response to receiving a request from an external client to join the Cube.
 * The INN relays, to other nodes in the Cube, the request with the client's information, asking for any nodes that are
 * both able to accept the connection (because they have a vacancy in their connectivity table) and are willing to
 * accept the connection (based on client information, currently an {@link InetSocketAddress} of the client). This is
 * done by sending broadcast {@link CubeMessage}s having successively increasing hop counts, until at least one other
 * node accepts the request. The INN designates this node as the address negotiating node (ANN), and hands off the
 * remainder of the process to the ANN. Because address negotiation can fail, the ANN is required to reply with a
 * success-or-fail status to the INN. If the negotiation succeeds, the INN can terminate its participation in the
 * addressing protocol, while if the negotiation fails, the INN continues searching.
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
 * However, ability to connect is an issue of address space size, which is easily fixed within the protocol. Therefore,
 * an INN that cannot place the new client in the Cube's existing address space will increase the dimension of the Cube
 * itself. This is done by instructing a (randomly selected) ANN, that indicated only an inability to attach the new
 * client, to attach it anyway, using a higher Cube dimension.
 * </p>
 * 
 * <h4>Phase 2</h4>
 * <p>
 * The second phase of the connection protocol is carried out by the ANN to find an acceptable {@link CubeAddress} for
 * the new node. The ANN first selects a vacant, neighbor <code>CubeAddress</code> as the possible address of the new
 * client. (Such an address exists, since the ANN indicated ability to connect.) The ANN then sends client connection
 * requests to each neighbor of the possible address, asking only for willingness to connect. (With a little thought, it
 * can be seen that each such neighbor already is able to connect the new address, if the Cube routing information is
 * consistent.) During this process, each willing neighbor transmits a random nonce to the ANN, used in the third phase
 * for authentication. If any prospective neighbor signals its unwillingness, the ANN chooses another vacancy and tries
 * again. If all such vacancies have at least one unwilling neighbor, the ANN relays that information to the INN and the
 * second phase terminates unsuccessfully for the ANN.
 * </p>
 * 
 * <h4>Phase 3</h4>
 * <p>
 * The third phase of the connection protocol begins once an ANN finds a collection of nodes that are willing (and able)
 * to connect to the client. The third phase begins with the ANN notifying the new client of the client's new
 * {@link CubeAddress} and the list of nonces from its new neighbors. This is done without revealing the ANN's
 * <code>CubeAddress</code>, because the client cannot yet be trusted with that information. It is also done without
 * revealing an association between each nonce and a corresponding Cube node. Once the client acknowledges the address
 * and the nonces, the ANN communicates this fact to each of the new neighbors, who contact the client with empty
 * messages. In response, the new client must reply with both its new <code>CubeAddress</code> and the set of nonces.
 * Each neighbor verifies that (1) the new <code>CubeAddress</code> is a valid neighbor, and (2) that the list of nonces
 * contains the nonce generated by the neighbor and has length equal to the current dimension of the Cube. The neighbor
 * reports success or failure of the verification to the ANN. Once the ANN concludes that all verifications were
 * successful, it provides the client with the ANN's own <code>CubeAddress</code>, then instructs the neighbors that it
 * is safe for them to provide their addresses as well.
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
		case CONN_INN_ANN_EXPAND:
			conn_inn_ann_expand(msg);
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
		case ROUTE_REQ:
			break;
		case ROUTE_RESP_RCHBL:
			break;
		case ROUTE_RESP_UNRCH:
			break;
		default:
			System.err.println(Thread.currentThread() + " received unknown message type " + msg.getType());
			break;
		}
	}

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
		// Ensure we are in the correct state

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
	 * INN must respond to initial request from client to connect.
	 * 
	 * Algorithm: send a message to each of my neighbors, asking them to be ANN for this connection.
	 */
	private void conn_ext_inn_req(CubeMessage msg) throws IOException
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
		InetSocketAddress addr = (InetSocketAddress) msg.getData();
		if (innStates.containsKey(addr))
		{
			new CubeMessage(none, none, CubeMessage.Type.INVALID_STATE,
					new Enum[] { innStates.get(addr).state, CubeMessage.Type.CONN_EXT_INN_REQ }).send(chan);
			chan.close();
			return;
		}

		// Edge cases: I might be the only node in the Cube, or I might have an open slot
		if (cubeState.dim == 0 || cubeState.dim > cubeState.neighbors.size())
		{
			// Act as ANN and join the client directly to me
			if (!expanding_join(addr))
				new CubeMessage(CubeAddress.INVALID_ADDRESS, CubeAddress.INVALID_ADDRESS,
						CubeMessage.Type.CONN_INN_EXT_CONN_REFUSED, null).send(chan);
			// chan.close();
			return;
		}

		// Regular processing: initialize state and send the initial broadcast messages
		innStates.put(addr, new INNState(chan));
		msg = new CubeMessage(cubeState.addr, CubeAddress.ZERO_HOPS, CubeMessage.Type.CONN_INN_REQ_ANN, addr);
		for (Neighbor n : cubeState.neighbors)
			msg.send(n.chan);
	}

	/**
	 * Neighbor must respond to client acknowledging connection
	 * 
	 * Algorithm: if my nonce is listed, report negotiation success to ANN; otherwise, report negotiation failure
	 */
	private void conn_ext_nei_ack(CubeMessage msg)
	{
		// Ensure we are in the correct state

	}

	/**
	 * ANN must respond to INN instruction to attach new client
	 * 
	 * Algorithm: attach the new client
	 */
	private void conn_inn_ann_expand(CubeMessage msg) throws IOException
	{
		// Ensure the message is properly formatted
		if (!checkMsg(msg, null, null, InetSocketAddress.class))
		{
			reply(msg, CubeMessage.Type.INVALID_MSG, null);
			return;
		}

		// Ensure we are in the correct state
		InetSocketAddress addr = (InetSocketAddress) msg.getData();
		if (annStates.containsKey(addr))
		{
			reply(msg, CubeMessage.Type.INVALID_STATE,
					new Enum[] { annStates.get(addr).state, CubeMessage.Type.CONN_INN_ANN_EXPAND });
			return;
		}

		// Expand
		expanding_join(addr);
	}

	/**
	 * ANN must respond to INN instruction to become ANN.
	 * 
	 * Algorithm: initialize ANN state and contact prospective neighbors
	 */
	private void conn_inn_ann_handoff(CubeMessage msg)
	{
		// Ensure we are in the correct state

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
	 * Cube node must respond to INN request to become ANN and connect client.
	 * 
	 * Algorithm: determine whether I am able to connect, then whether I am willing to connect. Because the second
	 * determination could potentially take some time, do it last. Reply to the INN with the result.
	 * 
	 * @throws IOException
	 */
	private void conn_inn_req_ann(CubeMessage msg) throws IOException
	{
		// Ensure the message is meant for me
		if (!CubeAddress.ZERO_HOPS.equals(msg.getDst()))
		{
			fwd_broadcast(msg);
			return;
		}

		// Ensure the message is properly formatted
		if (!checkMsg(msg, null, null, InetSocketAddress.class))
		{
			reply(msg, CubeMessage.Type.INVALID_MSG, null);
			return;
		}

		// Ensure we are in the correct state
		InetSocketAddress addr = (InetSocketAddress) msg.getData();
		if (annStates.containsKey(addr))
		{
			reply(msg, CubeMessage.Type.INVALID_STATE,
					new Enum[] { annStates.get(addr).state, CubeMessage.Type.CONN_INN_REQ_ANN });
			return;
		}

		// Am I able to connect?
		if (cubeState.neighbors.size() == cubeState.dim)
		{
			reply(msg, CubeMessage.Type.CONN_NODE_INN_UNABLE, addr);
			return;
		}

		// Am I willing to connect?
		if (amWilling(addr))
			reply(msg, CubeMessage.Type.CONN_NODE_INN_ACK, addr);
		else
			reply(msg, CubeMessage.Type.CONN_NODE_INN_UNWILLING, addr);
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
		SocketChannel chan = msg.getChannel();
		CubeAddress none = CubeAddress.INVALID_ADDRESS;
		if (!checkMsg(msg, null, cubeState.addr, null))
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
		CubeAddress nAddr = msg.getSrc();
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
	 * INN must respond to Cube node indicating willingness to be ANN.
	 * 
	 * Algorithm: hand off negotiation to Cube node to begin Phase 2
	 */
	private void conn_node_inn_ack(CubeMessage msg)
	{
		// Ensure we are in the correct state

	}

	/**
	 * INN must respond to Cube node indicating its inability to act as ANN.
	 * 
	 * Algorithm: record this fact, and determine whether to expand the Cube
	 */
	private void conn_node_inn_unable(CubeMessage msg) throws IOException
	{
		// Ensure the message is properly formatted
		SocketChannel chan = msg.getChannel();
		CubeAddress none = CubeAddress.INVALID_ADDRESS;
		if (!checkMsg(msg, none, cubeState.addr, InetSocketAddress.class))
		{
			new CubeMessage(none, none, CubeMessage.Type.INVALID_MSG, msg).send(chan);
			return;
		}

		// Ensure we are in the correct state
		InetSocketAddress addr = (InetSocketAddress) msg.getData();
		INNState state = innStates.get(addr);
		if (null == state || state.state != CubeMessage.Type.CONN_INN_REQ_ANN)
		{
			new CubeMessage(none, none, CubeMessage.Type.INVALID_STATE,
					new Enum[] { state.state, CubeMessage.Type.CONN_NODE_INN_UNABLE }).send(chan);
			return;
		}

		// Process the notice
		state.unable.add(msg.getSrc());
		check_expand(addr);
	}

	/**
	 * INN must respond to Cube node indicating its unwillingness to act as ANN.
	 * 
	 * Algorithm: record this fact, and determine whether to expand the Cube
	 */
	private void conn_node_inn_unwilling(CubeMessage msg) throws IOException
	{
		// Ensure the message is properly formatted
		SocketChannel chan = msg.getChannel();
		CubeAddress none = CubeAddress.INVALID_ADDRESS;
		if (!checkMsg(msg, none, cubeState.addr, InetSocketAddress.class))
		{
			new CubeMessage(none, none, CubeMessage.Type.INVALID_MSG, msg).send(chan);
			return;
		}

		// Ensure we are in the correct state
		InetSocketAddress addr = (InetSocketAddress) msg.getData();
		INNState state = innStates.get(addr);
		if (null == state || state.state != CubeMessage.Type.CONN_INN_REQ_ANN)
		{
			new CubeMessage(none, none, CubeMessage.Type.INVALID_STATE,
					new Enum[] { state.state, CubeMessage.Type.CONN_NODE_INN_UNWILLING }).send(chan);
			return;
		}

		// Process the notice
		state.unwilling.add(msg.getSrc());
		check_expand(addr);
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
			send(msg);
		else
			queued.add(msg);
	}

	/*
	 * Utility methods
	 */

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
			if (unable + unwill < 1 << (state.hops - 1))
				return;

			// Increase the hop count
			++state.hops;
			CubeAddress hopAddr = new CubeAddress(Integer.toString(-1 - state.hops));
			CubeMessage msg = new CubeMessage(cubeState.addr, hopAddr, CubeMessage.Type.CONN_INN_REQ_ANN, clientAddr);
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

	// Ensure that a CubeMessage has the proper source, destination, and state
	private boolean checkMsg(CubeMessage msg, CubeAddress src, CubeAddress dst, Class<?> clz)
	{
		return (src == null || msg.getSrc().equals(src)) && (dst == null || msg.getDst().equals(dst))
				&& (null == clz || null != msg.getData() && msg.getData().getClass().isAssignableFrom(clz));
	}

	// Expand the Cube by joining a connecting client to this node (acting as ANN)
	private boolean expanding_join(InetSocketAddress addr) throws IOException
	{
		if (!amWilling(addr))
			return false;

		// Connect the new client manually, blocking as required (since nothing else can be going on anyway)
		CubeAddress none = CubeAddress.INVALID_ADDRESS;
		CubeAddress peer = new CubeAddress(cubeState.addr.setBit(cubeState.dim).toString());

		// We have to separately connect to the client in our capacity as ANN to offer a connection
		SocketChannel annChan = SocketChannel.open(addr);

		// Send the first message (as ANN)
		ArrayList<Integer> nonces = new ArrayList<>();
		int nonce = (int) (Math.random() * Integer.MAX_VALUE);
		nonces.add(nonce);
		new CubeMessage(none, peer, CubeMessage.Type.CONN_ANN_EXT_OFFER, nonces).send(annChan);

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
		cubeState.neighbors.setSize(cubeState.dim);
		cubeState.neighbors.add(cubeState.dim, n);
		cubeState.links = new CubeAddress(cubeState.links.setBit(cubeState.dim).toString());
		cubeState.dim++;
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
	 * Send a message through the Cube using Katseff Algorithm 3 (with LSB instead of MSB ordering).
	 * 
	 * FIXME to handle transient link failures
	 */
	public void send(CubeMessage msg) throws IOException
	{
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
	public void reply(CubeMessage request, CubeMessage.Type type, Object data) throws IOException
	{
		send(new CubeMessage(cubeState.addr, request.getSrc(), type, data));
	}

	/**
	 * Broadcast a message through the Cube.
	 */
	public void broadcast(CubeMessage msg) throws IOException
	{
		msg.setDst(null);
		msg.setTravel(BigInteger.ZERO.setBit(cubeState.dim).subtract(BigInteger.ONE));
		fwd_broadcast(msg);
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
}
