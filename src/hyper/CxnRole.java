package hyper;

/**
 * Provides roles used by various nodes during and after the Cube connection process.
 */
enum CxnRole {
	/*
	 * A connecting node. Connecting nodes are not yet part of the routing table, and may or may not have a CubeAddress.
	 */
	EXT,

	/*
	 * An ingress negotiation node
	 */
	INN,

	/*
	 * An address negotiation node
	 */
	ANN,

	/*
	 * A potential neighbor node for both an EXT and an ANN
	 */
	NBR,

	/*
	 * A node that is not presently playing a direct role in the connection process
	 */
	NONE
}
