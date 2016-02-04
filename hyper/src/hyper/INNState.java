package hyper;

import java.math.BigInteger;
import java.nio.channels.SocketChannel;

/**
 * State variables associated with acting as INN. The {@link CubeProtocol} class includes a list of these, one for each
 * simultaneously connecting client.
 */
class INNState extends State
{
	// Socket channel for connecting client
	SocketChannel chan;

	// Bitmap of unwilling nodes
	BigInteger unwilling = BigInteger.ZERO;

	// Bitmap of willing and able nodes
	BigInteger able = BigInteger.ZERO;
	
	// ANN for which negotiation is currently handed off
	CubeAddress ann = null;

	INNState(SocketChannel chan) {
		this.chan = chan;
	}

	@Override
	public String toString()
	{
		return "State: " + state + "\nUnwilling/Able: " + unwilling.toString() + ", " + able.toString();
	}
}