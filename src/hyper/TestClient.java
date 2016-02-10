package hyper;

import java.net.InetSocketAddress;

public class TestClient
{
	private CubeProtocol startClient(InetSocketAddress addr)
	{
		MessageListener listener = new MessageListener(addr, false);
		listener.start();
		return new CubeProtocol(listener);
	}

	public static void main(String[] args) throws CubeException
	{
		int port = 20000;
		InetSocketAddress inn = new InetSocketAddress(port);
		TestClient tc = new TestClient();

		// Set up initial node, will get CubeAddress 0
		CubeProtocol client0 = tc.startClient(inn);

		// First client, will get CubeAddress 1
		CubeProtocol client1 = tc.startClient(new InetSocketAddress(++port));
		client1.connect(inn);
		System.out.println("client1 connected with CubeAddress " + client1.getCubeAddress());

		// Second client, will get CubeAddress 2 OR 3, depending on a coin flip
		CubeProtocol client2 = tc.startClient(new InetSocketAddress(++port));
		client2.connect(inn);
		System.out.println("client2 connected with CubeAddress " + client2.getCubeAddress());

		// Test the message passing algorithm. Send data to both 0 and 1, so we show at least one two-hopper
		client2.send(new Message(new CubeAddress("0"), "Data for Node 0"));
		client2.send(new Message(new CubeAddress("1"), "Data for Node 1"));
		System.out.println(client1.recv());

		// Third client, will get CubeAddress 3 OR 2, whichever is available
		CubeProtocol client3 = tc.startClient(new InetSocketAddress(++port));
		client3.connect(inn);
		System.out.println("client3 connected with CubeAddress " + client3.getCubeAddress());

		// Test message passing in both link directions
		client3.send(new Message(new CubeAddress("0"), "Data for Node 0"));
		client3.send(new Message(new CubeAddress("1"), "Data for Node 1"));
		client3.send(new Message(new CubeAddress("2"), "Data for Node 2"));

		// Test broadcast
		client0.broadcast("this is a test");

		// Fake a failure of client #2
		client1.shutdown();

		// Retest broadcast
		client0.broadcast("uh oh guys, my neighbor went down");

		// Add two more nodes
		client1 = tc.startClient(new InetSocketAddress(++port));
		client1.connect(inn);
		System.out.println("client1 reconnected, now with CubeAddress " + client1.getCubeAddress());
		System.exit(0);
	}
}
