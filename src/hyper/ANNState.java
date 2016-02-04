package hyper;

import java.math.BigInteger;

/**
 * State variables associated with acting as ANN. The {@link CubeProtocol} class includes a list of these, one for each
 * simultaneously connecting client.
 */
class ANNState extends State
{
	// Initiating INN
	CubeAddress inn;

	// Count of successful neighbor nodes at each phase
	int success = 0;

	// Bitmap of invalid nodes
	BigInteger invalid = BigInteger.ZERO;

	// Bitmap of unwilling nodes
	BigInteger unwilling = BigInteger.ZERO;

	// Bitmap of willing and able nodes
	BigInteger able = BigInteger.ZERO;

	// Proposed peer address
	CubeAddress peerAddr = null;
	
	// Is this proposal an expanding join?
	boolean isExpanding = false;

	public ANNState(CubeAddress inn) {
		this.inn = inn;
	}

	@Override
	public String toString()
	{
		return "State: " + state + "\nINN, Peer: " + inn + ", " + peerAddr + "\nSuccess, Unwilling, Able: " + success
				+ ", " + unwilling.toString() + ", " + able.toString();
	}
}