package hyper;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.SocketChannel;

class Utilities
{
	static void quietClose(SocketChannel chan)
	{
		try {
			chan.close();
		} catch (IOException e) {
			// Fail silently
		}
	}

	static InetSocketAddress quietRemote(SocketChannel chan)
	{
		try {
			return (InetSocketAddress) chan.getRemoteAddress();
		} catch (IOException e) {
			// The channel isn't connected
			return null;
		}
	}

	static InetSocketAddress quietLocal(SocketChannel chan)
	{
		try {
			return (InetSocketAddress) chan.getLocalAddress();
		} catch (IOException e) {
			// The channel isn't connected
			return null;
		}
	}
}
