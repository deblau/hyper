package hyper;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;

public class TestClient
{
	private MessageListener listener;
	private CubeProtocol protocol;

	public TestClient(int port) throws UnknownHostException, IOException
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
		
		// Set up initial node
		TestClient node0 = new TestClient(node0port);

		// First client
		TestClient client1 = new TestClient(node0port+1000);
		client1.request_join(node0port);
		client1.send_data(CubeAddress.NODE_ZERO, "test data");

		TestClient client2 = new TestClient(node0port+2000);
		client2.request_join(node0port);
		client2.send_data(new CubeAddress("1"), "I got you some data");
	}
}
