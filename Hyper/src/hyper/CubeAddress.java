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
	public static final CubeAddress ZERO = new CubeAddress("0");
	public static final CubeAddress INVALID_ADDRESS = null;
	static final CubeAddress ZERO_HOPS = new CubeAddress("-1");

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
