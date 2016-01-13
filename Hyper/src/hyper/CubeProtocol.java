package hyper;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.channels.SocketChannel;
import java.util.ArrayList;

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
 * The Cube protocol uses a modified version of Katseff's Algorithm 3 for routing, and of Algorithm 6 for broadcast
 * messaging. In particular, Katseff's Algorithm 3 assumes that there is no route backtracking; that is, that there
 * always exists a link between a given node and the destination that has one fewer bit of relative address. It is
 * simple to construct counterexamples, especially considering that nodes may come and go at any time, an issue for
 * which Katseff did not have to account. Therefore, the Cube protocol provides a route discovery mechanism that employs
 * backtracking, used for initial and broken contacts between nodes, and a route caching mechanism for subsequent
 * contacts.
 * </p>
 * 
 * <p>
 * There are two major functions provided by the protocol that require many messages to be passed: connecting new
 * clients to the Cube, and route discovery within the Cube given that nodes are almost certainly missing. These are now
 * addressed in turn.
 * </p>
 * 
 * <h3>New connections</h3>
 * <p>
 * The paramount concern in this area of the protocol is maintaining the anonymity of the link between an
 * {@link InetAddress} and a {@link CubeAddress}. Obviously, each Cube must provide one or more ingress negotiation
 * nodes (INNs) that act as gateways for the new CubeAddress discovery process, and the <code>InetAddress</code> of each
 * of these INNs must be discoverable outside the protocol. The discovery process for INNs is outside the scope of this
 * protocol; Cube communities may develop their own standards. However, the protocol nevertheless shields the revelation
 * of any <code>CubeAddress</code> to a connecting client until the last possible moment, after it has been approved to
 * join the Cube.
 * </p>
 * 
 * <p>
 * The connection process operates in three phases. The first phase is executed by the INN in response to receiving a
 * request from an external client to join the Cube. The INN relays, to other nodes in the Cube, the request with the
 * client's information, asking for any nodes that are both able to accept the connection (because they have a vacancy
 * in their connectivity table) and are willing to accept the connection (based on client information, currently an
 * {@link InetSocketAddress} of the client). This is done by sending broadcast {@link CubeMessage}s having successively
 * increasing hop counts, until at least one other node accepts the request. The INN designates this node as the address
 * negotiating node (ANN), and hands off the remainder of the process to the ANN. Because address negotiation can fail,
 * the ANN is required to reply with a success-or-fail status to the INN. If the negotiation succeeds, the INN can
 * terminate its participation in the addressing protocol, while if the negotiation fails, the INN continues searching.
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
 * 
 * <h3>Routing in the Cube</h3>
 */
public class CubeProtocol
{
	private CubeState cubeState = new CubeState();
	private ArrayList<INNState> innStates = new ArrayList<>();
	private ArrayList<ANNState> annStates = new ArrayList<>();
	private MessageListener listener;

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
		System.err.println(Thread.currentThread() + " got a message, type " + msg.getType());
		switch (msg.getType())
		{
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
		case CONN_ANN_NEI_FAIL:
			conn_ann_nei_fail(msg);
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
		case CONN_INN_BCAST:
			conn_inn_bcast(msg);
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
			send(msg);
			break;
		case INVALID_MSG:
			// This shouldn't happen
			break;
		case ROUTE_REQ:
			break;
		case ROUTE_RESP_RCHBL:
			break;
		case ROUTE_RESP_UNRCH:
			break;
		default:
			break;
		}
	}

	/**
	 * Client must respond to an offer of a new CubeAddress from an ANN.
	 * 
	 * Algorithm: reply that the offer is accepted.
	 * 
	 * @throws IOException
	 */
	@SuppressWarnings("unchecked")
	private void conn_ann_ext_offer(CubeMessage msg) throws IOException
	{
		if (msg.getDst() instanceof CubeAddress && msg.getData() instanceof ArrayList<?>)
		{
			cubeState.addr = msg.getDst();
			cubeState.nonces = (ArrayList<Double>) msg.getData();
			new CubeMessage(cubeState.addr, CubeAddress.NO_ADDRESS, CubeMessage.Type.CONN_EXT_ANN_ACK, null).send(msg
					.getChannel());
		} else
		{
			new CubeMessage(CubeAddress.NO_ADDRESS, CubeAddress.NO_ADDRESS, CubeMessage.Type.INVALID_MSG, msg).send(msg
					.getChannel());
		}

	}

	/**
	 * INN must respond to an indication of successful address negotiation from an ANN.
	 * 
	 * Algorithm:
	 */
	private void conn_ann_inn_succ(CubeMessage msg)
	{
		// TODO Auto-generated method stub

	}

	private void conn_ann_inn_unable(CubeMessage msg)
	{
		// TODO Auto-generated method stub

	}

	private void conn_ann_inn_unwilling(CubeMessage msg)
	{
		// TODO Auto-generated method stub

	}

	private void conn_ann_nei_fail(CubeMessage msg)
	{
		// TODO Auto-generated method stub

	}

	private void conn_ann_nei_req(CubeMessage msg)
	{
		// TODO Auto-generated method stub

	}

	private void conn_ann_nei_succ(CubeMessage msg)
	{
		// TODO Auto-generated method stub

	}

	private void conn_ext_ann_ack(CubeMessage msg)
	{
		// TODO Auto-generated method stub

	}

	/**
	 * INN must respond to initial request from client to connect. Note that the client has already closed the
	 * {@link SocketChannel}.
	 * 
	 * Algorithm: send a message to each of my neighbors, asking them to be ANN for this connection.
	 */
	private void conn_ext_inn_req(CubeMessage msg) throws IOException
	{
		// The client has already closed their end, might as well tidy up ours
		msg.getChannel().close();

		if (msg.getData() instanceof InetSocketAddress)
		{
			InetSocketAddress addr = (InetSocketAddress) msg.getData();

			// Edge case: I might be the only node in the Cube! If so, and if I'm willing to add him, then add him.
			if (0 == cubeState.dim)
			{
				if (amWilling(addr))
				{
					// Become the ANN for this client, and jump ahead in the protocol to phase three.
					ANNState state = new ANNState(CubeAddress.NODE_ZERO, addr);
					annStates.add(state);

					// Connect to the provided address and set up the CubeState and MessageListener
					Neighbor n = new Neighbor(new CubeAddress("1"), SocketChannel.open(addr), state.nonce);
					cubeState.neighbors.add(n);

					// Invite the client to join
					ArrayList<Double> nonces = new ArrayList<>();
					nonces.add(state.nonce);
					new CubeMessage(CubeAddress.NO_ADDRESS, n.addr, CubeMessage.Type.CONN_ANN_EXT_OFFER, nonces).send(n.chan);

					// Don't forget to register the new channel! And do it after sending the offer message, since we
					// have to be in blocking mode to register
					listener.register(n.chan);
				}
				return;
			}

			// Bail in the unlikely event that I'm not the only node but all of my neighbors have disconnected
			if (cubeState.neighbors.isEmpty())
			{
				System.err.println("In conn_ext_inn_req() with no neighbors!");
				// System.exit(1);
				return;
			}

			// Record that I'm acting as INN for this request
			innStates.add(new INNState(addr));

			// Send the initial broadcast messages
			for (Neighbor n : cubeState.neighbors)
				send(new CubeMessage(cubeState.addr, n.addr, CubeMessage.Type.CONN_INN_BCAST, addr));
		}
	}

	private void conn_ext_nei_ack(CubeMessage msg)
	{
		// TODO Auto-generated method stub

	}

	private void conn_inn_ann_expand(CubeMessage msg)
	{
		// TODO Auto-generated method stub

	}

	private void conn_inn_ann_handoff(CubeMessage msg)
	{
		// TODO Auto-generated method stub

	}

	/**
	 * Cube node must respond to INN request from client to connect.
	 * 
	 * Algorithm: determine whether I am able to connect, then whether I am willing to connect. Because the second
	 * determination could potentially take some time, do it last. Reply to the INN with the result.
	 * 
	 * @throws IOException
	 */
	private void conn_inn_bcast(CubeMessage msg) throws IOException
	{
		if (msg.getData() instanceof InetSocketAddress)
		{
			InetSocketAddress addr = (InetSocketAddress) msg.getData();

			// Am I able to connect?
			if (cubeState.neighbors.size() == cubeState.dim)
				reply(msg, CubeMessage.Type.CONN_NODE_INN_UNABLE, addr);

			// Am I willing to connect?
			if (amWilling(addr))
				reply(msg, CubeMessage.Type.CONN_NODE_INN_ACK, addr);
			else
				reply(msg, CubeMessage.Type.CONN_NODE_INN_UNWILLING, addr);

		} else
		{
			reply(msg, CubeMessage.Type.INVALID_MSG, msg);
		}
	}

	private void conn_nei_ann_ack(CubeMessage msg)
	{
		// TODO Auto-generated method stub

	}

	private void conn_nei_ann_fail(CubeMessage msg)
	{
		// TODO Auto-generated method stub

	}

	private void conn_nei_ann_nak(CubeMessage msg)
	{
		// TODO Auto-generated method stub

	}

	private void conn_nei_ann_succ(CubeMessage msg)
	{
		// TODO Auto-generated method stub

	}

	private void conn_nei_ext_ack(CubeMessage msg)
	{
		// TODO Auto-generated method stub

	}

	private void conn_nei_ext_offer(CubeMessage msg)
	{
		// TODO Auto-generated method stub

	}

	/**
	 * INN must respond to Cube node indicating acceptance to be ANN.
	 * 
	 * Algorithm: hand off negotiation to Cube node to begin phase two once all Cube nodes have reported in.
	 */
	private void conn_node_inn_ack(CubeMessage msg)
	{
		if (msg.getData() instanceof InetSocketAddress)
		{
			InetSocketAddress addr = (InetSocketAddress) msg.getData();
		}
	}

	private void conn_node_inn_unable(CubeMessage msg)
	{
		// TODO Auto-generated method stub

	}

	private void conn_node_inn_unwilling(CubeMessage msg)
	{
		// TODO Auto-generated method stub

	}

	/**
	 * Send a message through the Cube. Invokes the route caching and discovery.
	 */
	private void send(CubeMessage msg) throws IOException
	{
		// Handle loopback protocol messages
		if (cubeState.addr == msg.getDst())
		{
			process(msg);
			return;
		}

		// Consult the cache for the route
		Neighbor nextHop = cubeState.routeCache.get(msg.getDst());
		if (null != nextHop)
		{
			msg.send(nextHop.chan);
			return;
		}

		// If the cache came up empty, invoke route discovery
	}

	/**
	 * Reply to a message with a new message type and data.
	 */
	private void reply(CubeMessage request, CubeMessage.Type type, Object data) throws IOException
	{
		send(new CubeMessage(cubeState.addr, request.getSrc(), type, data));
	}

	/**
	 * Determine whether I am willing to allow a connection from a given address.
	 */
	private boolean amWilling(InetSocketAddress addr)
	{
		// TODO Auto-generated method stub
		return true;
	}

}
