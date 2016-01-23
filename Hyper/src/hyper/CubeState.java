package hyper;

import java.math.BigInteger;
import java.util.Vector;

/**
 * State variables associated with my connection to the Cube.
 */
class CubeState
{
	// Hypercube dimension
	int dim = 0;

	// My CubeAddress
	CubeAddress addr = CubeAddress.ZERO;

	// My connected neighbor nodes
	Vector<Neighbor> neighbors = new Vector<>();

	// Bitmap of which nodes are connected; this is used by the broadcast algorithm, and must be a new Object since
	// BigInteger.ZERO is final
	CubeAddress links = new CubeAddress("0");

	@Override
	public String toString()
	{
		return "Dim: " + dim + "\nMy address: " + addr + "\nLinks/Neighbors: " + links + ", " + neighbors.toString();
	}

	// Do I have any vacant links?
	boolean vacancy()
	{
		return !BigInteger.ZERO.setBit(dim).subtract(BigInteger.ONE).equals((BigInteger) links);
	}

	// Add a neighbor
	void addNeighbor(int link, Neighbor n)
	{
		neighbors.add(link, n);
		links = new CubeAddress(links.setBit(link).toString());
	}
}
