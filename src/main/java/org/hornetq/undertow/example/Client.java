/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2013, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.hornetq.undertow.example;

import static io.undertow.util.Headers.UPGRADE;
import static io.undertow.util.Methods.GET;
import static org.xnio.OptionMap.EMPTY;
import static org.xnio.Options.KEEP_ALIVE;
import static org.xnio.Options.TCP_NODELAY;
import static org.xnio.Options.WORKER_IO_THREADS;
import static org.xnio.Options.WORKER_NAME;

import java.io.IOException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import io.undertow.client.ClientCallback;
import io.undertow.client.ClientConnection;
import io.undertow.client.ClientExchange;
import io.undertow.client.ClientRequest;
import io.undertow.client.ClientResponse;
import io.undertow.client.UndertowClient;
import io.undertow.util.HeaderMap;
import io.undertow.util.HttpString;
import io.undertow.util.StringReadChannelListener;
import org.xnio.ByteBufferSlicePool;
import org.xnio.IoUtils;
import org.xnio.OptionMap;
import org.xnio.StreamConnection;
import org.xnio.Xnio;
import org.xnio.XnioWorker;

/**
 * @author <a href="http://jmesnil.net/">Jeff Mesnil</a> (c) 2013 Red Hat inc.
 */
public class Client {

    public static final String HORNETQ_REMOTING = "hornetq-remoting";
    public static final String SERVER_URL = "http://localhost:8080/";

    public static void main(String[] args) throws Exception {
        final OptionMap options = OptionMap.builder()
                .set(WORKER_IO_THREADS, 8)
                .set(TCP_NODELAY, true)
                .set(KEEP_ALIVE, true)
                .set(WORKER_NAME, "Client")
                .getMap();
        final Xnio xnio = Xnio.getInstance();
        final XnioWorker worker = xnio.createWorker(null, options);
        final UndertowClient client = UndertowClient.getInstance();

        final URI serverAddress = new URI(SERVER_URL);
        final ClientConnection connection = client.connect(serverAddress, worker, new ByteBufferSlicePool(1024, 1024), EMPTY).get();

        final CountDownLatch latch = new CountDownLatch(1);

        try {
            connection.getIoThread().execute(new Runnable() {
                @Override
                public void run() {
                    final ClientRequest request = new ClientRequest().setMethod(GET).setPath("/");
                    request.getRequestHeaders().add(UPGRADE, HORNETQ_REMOTING);
                    String secretKey = HandshakeUtil.createSecretKey();
                    request.getRequestHeaders().add(HttpString.tryFromString(HandshakeUtil.SEC_HORNETQ_REMOTING_KEY), secretKey);
                    connection.sendRequest(request, createClientCallback(latch, secretKey));
                }
            });
            latch.await(10, TimeUnit.MINUTES);
            if (connection.isUpgraded()) {
                StreamConnection streamConnection = connection.performUpgrade();
                switchToHornetQProtocol(streamConnection);
            }
        } finally {
            IoUtils.safeClose(connection);
            worker.shutdown();
        }
    }

    private static void switchToHornetQProtocol(StreamConnection streamConnection) throws IOException {
        ByteBuffer buffer = ByteBuffer.wrap("Hello, HornetQ!".getBytes("UTF-8"));
        streamConnection.getSinkChannel().write(buffer);
        streamConnection.getSinkChannel().flush();
    }

    private static void verifyHandshake(ClientResponse response, String secretKey) throws IOException {
        HeaderMap headers = response.getResponseHeaders();
        String acceptValue = headers.getFirst(HandshakeUtil.SEC_HORNETQ_REMOTING_ACCEPT);
        if (acceptValue == null) {
            throw new IOException(HandshakeUtil.SEC_HORNETQ_REMOTING_ACCEPT + " header not found");
        }
        String expectedResponse = HandshakeUtil.createExpectedResponse(secretKey);
        if(!acceptValue.equals(expectedResponse)) {
            throw new IOException(HandshakeUtil.SEC_HORNETQ_REMOTING_ACCEPT + " value of " + acceptValue + " did not match expected " + expectedResponse);
        }
    }

    private static ClientCallback<ClientExchange> createClientCallback(final CountDownLatch latch, final String secretKey) {
        return new ClientCallback<ClientExchange>() {
            @Override
            public void completed(ClientExchange result) {
                result.setResponseListener(new ClientCallback<ClientExchange>() {
                    @Override
                    public void completed(final ClientExchange result) {
                        new StringReadChannelListener(result.getConnection().getBufferPool()) {

                            @Override
                            protected void stringDone(String string) {
                                ClientResponse response = result.getResponse();
                                try {
                                    verifyHandshake(response, secretKey);
                                } catch (IOException e) {
                                    failed(e);
                                } finally {
                                    latch.countDown();
                                }
                            }

                            @Override
                            protected void error(IOException e) {
                                e.printStackTrace();

                                latch.countDown();
                            }
                        }.setup(result.getResponseChannel());
                    }

                    @Override
                    public void failed(IOException e) {
                        e.printStackTrace();

                        latch.countDown();
                    }
                });
            }

            @Override
            public void failed(IOException e) {
                e.printStackTrace();
                latch.countDown();
            }
        };
    }
}
