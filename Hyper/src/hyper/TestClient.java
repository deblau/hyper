package hyper;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;

public class TestClient
{
	private MessageListener listener;
	private CubeProtocol protocol;

	public TestClient(int port) throws UnknownHostException, IOException, InterruptedException
	{
		listener = new MessageListener(new InetSocketAddress(port), false);
		listener.start();
		protocol = new CubeProtocol();
		listener.setProtocol(protocol);
		protocol.setListener(listener);
	}

	private void request_join(int port) throws IOException 
	{
		protocol.connect(new InetSocketAddress(port), (InetSocketAddress) listener.getAddress());
	}

	private void send_data(CubeAddress addr, String data) throws IOException
	{
		CubeState state = protocol.getCubeState();
		protocol.send(new CubeMessage(state.addr, addr, CubeMessage.Type.DATA_MSG, data));
	}

	public static void main(String[] args) throws IOException, InterruptedException
	{
		int node0port = 20000;
		
		// Set up initial node, will get CubeAddress 0
		new TestClient(node0port);

		// First client, will get CubeAddress 1
		TestClient client1 = new TestClient(node0port+1000);
		client1.request_join(node0port);

		// Second client, will get CubeAddress 2 OR 3, depending on a coin flip
		TestClient client2 = new TestClient(node0port+2000);
		client2.request_join(node0port);
		
		// Test the message passing algorithm. Send data to both 0 and 1, so we show at least one two-hopper 
		client2.send_data(new CubeAddress("0"), "Data for Node 0");
		client2.send_data(new CubeAddress("1"), "Data for Node 1");
	}
}
