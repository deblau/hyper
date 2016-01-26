package hyper;

import java.util.ArrayList;

/**
 * State variables associated with acting as ANN. The {@link CubeProtocol} class includes a list of these, one for each
 * simultaneously connecting client.
 */
class ANNState extends State
{
	// Initiating INN
	CubeAddress inn;

	// Proposed peer address
	CubeAddress peerAddr = null;

	// Count of successful nodes at each phase
	int success = 0;

	// List of invalid nodes
	ArrayList<CubeAddress> invalid = new ArrayList<>();

	// List of nonces from all neighbors (including me)
	ArrayList<Integer> nonces = new ArrayList<>();

	public ANNState(CubeAddress inn)
	{
		this.inn = inn;
	}

	@Override
	public String toString()
	{
		return "State: " + state + "\nINN, Peer: " + inn + ", " + peerAddr + "\nWilling, Invalid, Nonces: " + success + ", "
				+ invalid.toString() + ", " + nonces.toString();
	}
}