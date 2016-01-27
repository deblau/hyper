package hyper;

import java.net.InetSocketAddress;

import hyper.CubeMessage.Type;

public class TestClient
{
	private CubeProtocol protocol;

	public TestClient(int port) {
		MessageListener listener = new MessageListener(new InetSocketAddress(port), false);
		listener.start();
		protocol = new CubeProtocol(listener);
	}

	public void request_join(int port) throws CubeException
	{
		// Assume the INN is running locally
		protocol.connect(new InetSocketAddress(port));
	}

	private boolean send(CubeAddress addr, String data)
	{
		CubeState state = protocol.getCubeState();
		return protocol.send(new CubeMessage(state.addr, addr, CubeMessage.Type.DATA_MSG, data));
	}

	private Message recv() throws CubeException
	{
		return protocol.recv();
	}

	private Message recvNow() throws CubeException
	{
		return protocol.recvNow();
	}

	public static void main(String[] args) throws CubeException
	{
		int node0port = 20000;

		// Set up initial node, will get CubeAddress 0
		TestClient client0 = new TestClient(node0port);

		// First client, will get CubeAddress 1
		TestClient client1 = new TestClient(node0port + 1000);
		client1.request_join(node0port);

		// Second client, will get CubeAddress 2 OR 3, depending on a coin flip
		TestClient client2 = new TestClient(node0port + 2000);
		client2.request_join(node0port);

		// Test the message passing algorithm. Send data to both 0 and 1, so we show at least one two-hopper
		client2.send(new CubeAddress("0"), "Data for Node 0");
		client2.send(new CubeAddress("1"), "Data for Node 1");
		Message msg = client1.recvNow();

		// Third client, will get CubeAddress 3 OR 2, whichever is available
		TestClient client3 = new TestClient(node0port + 3000);
		client3.request_join(node0port);

		// Test message passing in both directions.
		client3.send(new CubeAddress("0"), "Data for Node 0");
		client3.send(new CubeAddress("1"), "Data for Node 1");
		client3.send(new CubeAddress("2"), "Data for Node 2");

		// Test broadcast
		client0.protocol.broadcast(new Message(CubeAddress.INVALID_ADDRESS, "this is a test"));

		// Fake a failure of client #2
		client2.protocol.shutdown();
		
		// Retest broadcast
		client0.protocol.broadcast(new Message(CubeAddress.INVALID_ADDRESS, "uh oh guys, one of the nodes went down"));
	}
}
