package hyper;

import java.nio.channels.SocketChannel;
import java.util.ArrayList;

/**
 * State variables associated with acting as INN. The {@link CubeProtocol} class includes a list of these, one for each
 * simultaneously connecting client.
 */
class INNState
{
	// Socket channel for connecting node
	SocketChannel chan;

	// List of unable nodes
	ArrayList<CubeAddress> unable = new ArrayList<>();

	// List of unwilling nodes
	ArrayList<CubeAddress> unwilling = new ArrayList<>();

	// Phase 1 state of the INN, used for protocol state validation
	CubeMessage.Type state = CubeMessage.Type.CONN_EXT_INN_REQ;

	INNState(SocketChannel chan) {
		this.chan = chan;
	}
}