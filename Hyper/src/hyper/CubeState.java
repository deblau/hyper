package hyper;

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
}
