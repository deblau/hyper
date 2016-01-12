package hyper;

import java.math.BigInteger;

/**
 * An address in the Cube protocol. This address corresponds to a node whose IP address is unknown to the local node
 * unless the local node and the other node are neighbors in the hypercube.
 */
public class CubeAddress extends BigInteger
{
	private static final long serialVersionUID = 1205974176746394843L;
	public static final CubeAddress NO_ADDRESS = new CubeAddress("-1");
	public static final CubeAddress NODE_ZERO = new CubeAddress("0");

	public CubeAddress(String arg0)
	{
		super(arg0);
	}

	public static CubeAddress getBcast(int dim)
	{
		return (CubeAddress) ZERO.setBit(dim).subtract(ONE);
	}

	public int relativeLink(CubeAddress other)
	{
		return xor(other).getLowestSetBit();
	}

	public CubeAddress followLink(int index)
	{
		return new CubeAddress(flipBit(index).toString());
	}
}
