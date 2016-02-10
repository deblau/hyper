package hyper;

import java.math.BigInteger;
import java.nio.channels.SocketChannel;

/**
 * A class holding connection state. Each INN, ANN, NBR, and peer that participates to connect the peer includes an
 * instance of this class at some point during the process.
 */
class CxnState
{
	// The current state of the connection, as seen from this node, as given by the last protocol message sent
	CubeMessageType state;

	// SocketChannel between INN and peer -- used by INN and peer
	SocketChannel innChan = null;

	// CubeAddress of INN -- used by ANN
	CubeAddress innAddr = CubeAddress.INVALID_ADDRESS;

	// SocketChannel between ANN and peer -- used by ANN and peer (and INN if acting as ANN)
	SocketChannel annChan = null;

	// CubeAddress of ANN -- used by INN, NBR, and peer
	CubeAddress annAddr = CubeAddress.INVALID_ADDRESS;

	// SocketChannel between NBR and peer -- used by NBR
	SocketChannel nbrChan = null;

	// CubeAddress of peer -- used by ANN and NBR
	CubeAddress peerAddr = CubeAddress.INVALID_ADDRESS;
	
	// CubeAddress topology -- used by INN
//	Topology topology = null;
	
	// Bitmap of ANNs that have been tried
	BigInteger triedANNs = BigInteger.ZERO;

	// Count of neighbor nodes that have replied to instructions -- used by ANN
	int replies = 0;
	
	/*
	 * Temporary fields that will be removed after the protocol is simplified
	 */
	BigInteger unwilling = BigInteger.ZERO;
	BigInteger able = BigInteger.ZERO;
	BigInteger invalid = BigInteger.ZERO;
}
