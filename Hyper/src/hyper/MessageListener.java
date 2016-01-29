package hyper;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.channels.*;
import java.util.ArrayList;

/**
 * Provides a {@link Selector} for all incoming communications.
 */
public class MessageListener extends Thread
{
	// Our bound protocol address
	private SocketAddress local;

	// Our bound SOCKS5 address (if any)
	private SocketAddress socks = new InetSocketAddress(1080);

	/**
	 * Returns the {@link SocketAddress} of the bound listener channel.
	 * 
	 * @return the {@link SocketAddress}
	 */
	public SocketAddress getAddress()
	{
		return local;
	}

	// Selector
	private Selector sel = null;

	// Whether we should shut down
	private boolean shutdown = false;

	// CubeProtocol instance for dispatching messages
	private CubeProtocol protocol = null;

	void setProtocol(CubeProtocol protocol)
	{
		this.protocol = protocol;
	}

	/**
	 * Create a {@link MessageListener} object, bind it to a local address, and open a {@link Selector}.
	 * 
	 * @param local
	 *            A {@link SocketAddress} to which to bind the server socket, or <code>null</code> for the
	 *            <code>anyLocal</code> address.
	 */
	public MessageListener(SocketAddress local, boolean socks) {
		try
		{
			this.local = local;

			ServerSocketChannel svrChan = ServerSocketChannel.open();
			svrChan.bind(local);

			sel = Selector.open();
			svrChan.configureBlocking(false);
			svrChan.register(sel, SelectionKey.OP_ACCEPT);

			if (socks)
			{
				ServerSocketChannel socksChan = ServerSocketChannel.open();
				socksChan.bind(this.socks);
				socksChan.configureBlocking(false);
				socksChan.register(sel, SelectionKey.OP_ACCEPT);
			}
		} catch (IOException e)
		{
			e.printStackTrace();
		}
	}

	// Called by the {@link CubeProtocol} to shut down the {@link MessageListener}.
	void shutdown()
	{
		shutdown = true;
		sel.wakeup();
	}

	// Main loop
	public void run()
	{
		while (true)
		{
			try
			{
				// Remove stale connections and determine how long to wait
				// long wait = removeStales();
				long wait = 0;

				// Wait for a channel to become active
				int numKeys = sel.select(wait);
				// System.err.println(Thread.currentThread() + " awake with " + numKeys + " keys");

				// Are we shutting down?
				if (shutdown)
					break;

				// Were we woken up or interrupted for some other reason?
				if (0 == numKeys)
					continue;

				// We have some keys that need attention, process them
				processKeys();
			} catch (IOException e)
			{
				e.printStackTrace();
			} catch (InterruptedException e)
			{
				// Only happens if our Queue runs out of memory and we were interrupted trying to add to it
				e.printStackTrace();
			}
		}

		// Close all connected channels nicely
		for (SelectionKey key : sel.keys())
		{
			try
			{
				key.channel().close();
			} catch (IOException e)
			{
				// Ignore errors
			}
		}

		// Close the selector
		try
		{
			sel.close();
		} catch (IOException e)
		{
			// Ignore errors
		}
	}

	/**
	 * Process selected keys.
	 * 
	 * @throws IOException
	 * @throws InterruptedException
	 */
	private void processKeys() throws IOException, InterruptedException
	{
		/*
		 * Okay, here's some stupid shit. CubeMessage sends and receives itself using ObjectOutputStream and
		 * ObjectInputStream. To make this "old" java.io work with java.nio, I create the streams using the Channels
		 * utility class method, which require that the channel be in blocking mode. However, our channel is already
		 * registered with this Selector in non-blocking mode, so we can't change the mode to be blocking or we get an
		 * IllegalBlockingModeException. To switch the channel over to blocking, we have to cancel the key. But once the
		 * key is canceled and the read is performed, we can no longer reset the channel to non-blocking and register
		 * with the Selector again until after the next select(), or we'll get a CanceledKeyException. So we have to
		 * call selectNow() to flush the canceled key set before we can re-register the channel we just read from. But
		 * then, what if selectNow() returns additional channels that require attention? Hence, a big loop around the
		 * whole method. Dumb.
		 */

		ArrayList<SocketChannel> reregister = new ArrayList<>();
		do
		{
			for (SelectionKey key : sel.selectedKeys())
			{
				sel.selectedKeys().remove(key);
				if (key.isAcceptable())
				{
					System.err.println(Thread.currentThread() + " accepting");
					// If someone tries to connect, accept and wait for them to contact us
					SocketChannel chan = ((ServerSocketChannel) key.channel()).accept();
					if (null != chan)
					{
						chan.configureBlocking(false);
						chan.register(sel, SelectionKey.OP_READ);
						// timeoutMap.put(System.currentTimeMillis() + acceptTimeout, chan);
					}

				} else if (key.isReadable())
				{
					// If someone is sending us a CubeMessage, read it
					SocketChannel chan = (SocketChannel) key.channel();

					// Allow blocking reads
					key.cancel();
					chan.configureBlocking(true);

					try
					{
						// Perform the read
						CubeMessage msg = CubeMessage.recv(chan);
						if (null != msg)
						{
							// Schedule it for re-registration
							reregister.add(chan);

							// Now (finally!) we can process the message
							protocol.process(msg);
						}
					} catch (Exception e)
					{
						// Peer closed connection
						protocol.closedCxn(chan);
						chan.close();
					}
				} else
				{
					System.err.println(Thread.currentThread() + " goofy key: " + key.readyOps());
					key.cancel();
				}
			}

			// Now that we're done processing all active channels, flush the canceled key set
			sel.selectNow();

			// Flushing may have discovered more active channels and reset SelectedKeys, so repeat as necessary
		} while (!sel.selectedKeys().isEmpty());

		// Now that we really are done processing all active channels, re-register the channels
		for (SocketChannel sc : reregister)
			if (sc.isOpen())
			{
				// Reset the blocking mode
				sc.configureBlocking(false);
				sc.register(sel, SelectionKey.OP_READ);
			}
	}

	/**
	 * Called by {@link CubeProtocol} when establishing a new neighbor.
	 */
	void register(SocketChannel chan) throws IOException
	{
		chan.configureBlocking(false);
		chan.register(sel, SelectionKey.OP_READ);
	}
}
