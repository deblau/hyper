package hyper;

import java.util.ArrayList;

/**
 * State variables associated with acting as ANN. The {@link CubeProtocol} class includes a list of these, one for each
 * simultaneously connecting client.
 */
class ANNState
{
	// Initiating INN
	CubeAddress inn;

	// List of unable nodes
	ArrayList<CubeAddress> unable = new ArrayList<>();

	// List of unwilling nodes
	ArrayList<CubeAddress> unwilling = new ArrayList<>();

	// Phase 2 state of the ANN, used for protocol state validation
	CubeMessage.Type state = CubeMessage.Type.CONN_INN_ANN_HANDOFF;

	public ANNState(CubeAddress inn)
	{
		this.inn = inn;
	}
}