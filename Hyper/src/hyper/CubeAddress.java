package hyper;

import java.math.BigInteger;

/**
 * An address in the Cube protocol. This address corresponds to a node whose IP address is unknown to the local node
 * unless the local node and the other node are neighbors in the hypercube. Non-negative addresses represent individual
 * nodes; negative addresses represent hop counts used for sending broadcast messages.
 */
public class CubeAddress extends BigInteger
{
	private static final long serialVersionUID = 1205974176746394843L;

	// An invalid address, used to ensure proper message format
	public static final CubeAddress INVALID_ADDRESS = new CubeAddress("-1");

	/*
	 * The "processing broadcast" address, indicating that the message should be forwarded using the "travel" vector (if
	 * possible) AND processed by the local node
	 */
	static final CubeAddress BCAST_PROCESS = new CubeAddress("-2");

	/*
	 * The "forwarding broadcast" address, indicating that the message should only be processed if the "travel" vector
	 * is all zeroes (that is, if it cannot be further forwarded), as part of a data gathering operation
	 */
	static final CubeAddress BCAST_FORWARD = new CubeAddress("-3");

	/*
	 * The "reverse broadcast" address, indicating that the message is one of potentially several that should be
	 * aggregated for return to the broadcast originator, as part of a data gathering operation
	 */
	static final CubeAddress BCAST_REVERSE = new CubeAddress("-4");

	CubeAddress(String arg0) {
		super(arg0);
	}

	/**
	 * Returns the link by which the other CubeAddress can be reached, or -1 if the other CubeAddress is not a neighbor
	 */
	public int relativeLink(CubeAddress other)
	{
		BigInteger xor = xor(other);
		int link = xor.getLowestSetBit();
		if (1 == xor.bitCount())
			return link;
		else
			return -1;
	}

	public CubeAddress followLink(int index)
	{
		return new CubeAddress(flipBit(index).toString());
	}
}
