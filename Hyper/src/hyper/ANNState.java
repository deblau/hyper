package hyper;

/**
 * State variables associated with acting as ANN. The {@link CubeProtocol} class includes a list of these, one for each
 * simultaneously connecting client.
 */
class ANNState
{
	// Initiating INN
	CubeAddress inn;

	// Proposed peer address
	CubeAddress peerAddr = null;

	// Count of willing nodes
	int willing = 0;

	// Phase 2 state of the ANN, used for protocol state validation
	CubeMessage.Type state = null;

	public ANNState(CubeAddress inn) {
		this.inn = inn;
	}
}