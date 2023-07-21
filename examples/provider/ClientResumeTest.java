/* ClientResumeTest.java
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

import java.net.InetAddress;
import java.security.Provider;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;

import com.wolfssl.provider.jsse.WolfSSLDebug;
import com.wolfssl.provider.jsse.WolfSSLProvider;
import com.wolfssl.provider.jsse.WolfSSLSocket;
import com.wolfssl.WolfSSL;
import java.security.PrivateKey;
import java.security.Security;
import javax.net.ssl.KeyManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.SSLServerSocket;
import java.security.cert.X509Certificate;
import java.security.cert.Certificate;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.ConcurrentHashMap;


public class ClientResumeTest {

    String provider = "wolfJSSE";
    //String provider = "SunJSSE";

    String serverJKS   = "../provider/server.jks";
    String serverCaJKS = "../provider/ca-client.jks";
    String serverPswd  = "wolfSSL test";

    String clientJKS  = "../provider/client.jks";
    String caJKS      = "../provider/ca-server.jks";
    String clientPswd = "wolfSSL test";
    String caPswd = "wolfSSL test";

    /* Start port for servers to start on, and clients to connect to */
    int startPort = 11111;
    String serverHost = "127.0.0.1";

    String version = "TLS";
    int sslVersion = -1;                   /* default to downgrade */
    boolean listSuites = false;           /* list all supported suites */
    boolean listEnabledProtocols = false; /* show enabled protocols */
    String cipherList = null;             /* default ciphersuite list */


    /* Number of server threads and client connections to make. Increments
     * port number from startPort value */
    int numConnections = 12;

    /* Map of session IDs for initial client connections, keyed on port */
    ConcurrentHashMap<Integer, byte[]> initialIDs = new ConcurrentHashMap<>();

    /* Map of session IDs for resumed client connections, keyed on port */
    ConcurrentHashMap<Integer, byte[]> resumedIDs = new ConcurrentHashMap<>();
    ConcurrentHashMap<Integer, Boolean> reused = new ConcurrentHashMap<>();

    /**
     * Inner ServerThread class, represents SSLSocket server thread.
     * Starts up a server using SSLServerSocket.accept(), waits for and
     * handles one client connection, closes socket, re-opens a new
     * SSLServerSocket, and handles a resumed client connection.
     */
    class ServerThread extends Thread
    {
        /* Server port for this thread, set by constructor */
        int serverPort = 0;

        /* SSLContext used by server thread */
        SSLContext ctx = null;

        /* Latch that counts down as server sockets get created. Used to
         * wait for all server threads to start before starting up
         * client threads */
        CountDownLatch openLatch = null;

        /* Latch that counts down as server thread re-opens for a resumed
         * connection. Used to wait for all server threads to finish initial
         * connections then re-open again before starting client resumptions */
        CountDownLatch openLatchResume = null;

        /* Latch that counts down as server threads close. Used to wait for
         * all server threads to finish before shutting down executor */
        CountDownLatch closedLatch = null;

        public ServerThread(SSLContext ctx, int serverPort,
            CountDownLatch openLatch, CountDownLatch closedLatch,
            CountDownLatch openLatchResume) {

            this.serverPort = serverPort;
            this.ctx = ctx;
            this.openLatch = openLatch;
            this.closedLatch = closedLatch;
            this.openLatchResume = openLatchResume;
        }

        public void run() {

            try {
                SSLServerSocket ss =
                    (SSLServerSocket)ctx.getServerSocketFactory()
                        .createServerSocket(serverPort);
                if (cipherList != null) {
                    ss.setEnabledCipherSuites(cipherList.split(":"));
                }

                /* Open server and handle client connection */
                this.openLatch.countDown();
                System.out.println(
                    "Started server thread: port " + serverPort);
                SSLSocket sock = (SSLSocket)ss.accept();
                sock.startHandshake();
                sock.close();

                /* Open server and handle resumed client connection */
                this.openLatchResume.countDown();
                sock = (SSLSocket)ss.accept();
                sock.startHandshake();
                sock.close();

                this.closedLatch.countDown();

            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    } /* end ServerThread */

    public ExecutorService LaunchServerThreads(int firstPort,
        String version, CountDownLatch openLatch,
        CountDownLatch closedLatch, CountDownLatch openLatchResume)
            throws Exception {

        /* Server KeyStore, using serverJKS */
        KeyStore serverKeystore = KeyStore.getInstance("JKS");
        serverKeystore.load(new FileInputStream(serverJKS),
            serverPswd.toCharArray());

        /* Server TrustStore, using serverCaJKS */
        KeyStore serverTruststore = KeyStore.getInstance("JKS");
        serverTruststore.load(new FileInputStream(serverCaJKS),
            caPswd.toCharArray());

        /* Server TrustManagerFactory, init with TrustStore */
        TrustManagerFactory serverTm =
            TrustManagerFactory.getInstance("SunX509", provider);
        serverTm.init(serverTruststore);

        /* Server KeyManagerFactory, init with KeyStore */
        KeyManagerFactory serverKm =
            KeyManagerFactory.getInstance("SunX509", provider);
        serverKm.init(serverKeystore, caPswd.toCharArray());

        /* Create SSLContext for server threads */
        SSLContext serverCtx = SSLContext.getInstance(version, provider);
        serverCtx.init(serverKm.getKeyManagers(),
                       serverTm.getTrustManagers(), null);

        /* Create list of ServerThread objects, used with ExecutorService */
        List<ServerThread> serverList = new ArrayList<ServerThread>();

        for (int i = 0; i < numConnections; i++) {
            serverList.add(new ServerThread(serverCtx, firstPort + i,
                                openLatch, closedLatch, openLatchResume));
        }

        /* Create new ExecutorService with fixed thread pool that matches
         * number of server threads / threads, then start each one up */
        ExecutorService executor =
            Executors.newFixedThreadPool(serverList.size());

        for (final ServerThread s : serverList) {
            executor.execute(s);
        }

        /* Wait for all server threads to be started and in
         * SSLServerSocket.accept() state before continuing on to connect
         * client threads */
        openLatch.await();

        System.out.println("All servers started");

        return executor;
    }

    public void LaunchClientThreads(String version, int firstPort,
        CountDownLatch openLatchResume)
        throws Exception {

        /* Trust manager (certificates) */
        KeyStore cert = KeyStore.getInstance("JKS");
        cert.load(new FileInputStream(caJKS), caPswd.toCharArray());
        TrustManagerFactory tm = TrustManagerFactory.getInstance(
            "SunX509", provider);
        tm.init(cert);

        /* Load private key */
        KeyStore pKey = KeyStore.getInstance("JKS");
        pKey.load(new FileInputStream(clientJKS), clientPswd.toCharArray());
        KeyManagerFactory km = KeyManagerFactory.getInstance(
            "SunX509", provider);
        km.init(pKey, clientPswd.toCharArray());

        /* Setup context with certificate and private key */
        SSLContext ctx = SSLContext.getInstance(version, provider);
        ctx.init(km.getKeyManagers(), tm.getTrustManagers(), null);

        System.out.printf("Using SSLContext provider %s\n", ctx.getProvider().
                getName());

        SocketFactory sf = ctx.getSocketFactory();
        InetAddress peerAddr = InetAddress.getByName(serverHost);

        System.out.println("\nStarting initial client connections");

        /* new connections */
        for (int i = 0; i < numConnections; i++) {
            SSLSocket sock = (SSLSocket)sf.createSocket(peerAddr, firstPort + i);
            if (cipherList != null) {
                sock.setEnabledCipherSuites(cipherList.split(":"));
            }
            sock.startHandshake();
            byte[] sessId = sock.getSession().getId();
            initialIDs.put((firstPort + i), sessId);
            sock.close();
        }

        System.out.println("Completed " + numConnections +
            " initial client connections");
        openLatchResume.await();

        System.out.println("Starting resumed client connections");

        /* resume connections */
        firstPort = startPort + numConnections - 1;
        for (int i = numConnections; i > 0; i--) {
            SSLSocket sock = (SSLSocket)sf.createSocket(peerAddr, firstPort);
            if (cipherList != null) {
                sock.setEnabledCipherSuites(cipherList.split(":"));
            }
            sock.startHandshake();
            byte[] sessId = sock.getSession().getId();
            resumedIDs.put(firstPort, sessId);
            reused.put(firstPort, ((WolfSSLSocket)sock).sessionResumed());
            sock.close();
            sock = null;
            firstPort--;
        }

        System.out.println("Completed " + numConnections +
            " resumed client connections");
    }

    private void PrintSessionIDs() {

        System.out.println("Recorded " + initialIDs.size() +
                           " initial client session IDs");

        /* Print initial session connection IDs */
        for (Map.Entry<Integer, byte[]> entry: initialIDs.entrySet()) {
            System.out.print(entry.getKey() + ": ");
            byte[] sesID = entry.getValue();
            for (int i = 0; i < sesID.length; i++) {
                System.out.printf("%02x", sesID[i]);
            }
            System.out.print("\n");
        }

        System.out.println("Recorded " + resumedIDs.size() +
                           " resumed client session IDs");

        /* Print resumed session connection IDs */
        for (Map.Entry<Integer, byte[]> entry: resumedIDs.entrySet()) {
            System.out.print(entry.getKey() + ": ");
            byte[] sesID = entry.getValue();
            for (int i = 0; i < sesID.length; i++) {
                System.out.printf("%02x", sesID[i]);
            }
            byte[] initialID = initialIDs.get(entry.getKey());
            if (!Arrays.equals(sesID, initialID)) {
                System.out.print(" [NOT RESUMED]");
            }
            System.out.print(": " + reused.get(entry.getKey()));
            System.out.print("\n");
        }
    }

    /**
     * ClientResumeTest run() method.
     *   1. Starts up given number of server threads
     *   2. Waits for server threads to all be open
     *   3. Creates and connects client SSLSocket's to each server
     *   4. Waits for all server handshakes to finish
     *   5. Creates and connects client SSLSocket's to each server again,
     *      which should do session resumption (or do a full handshake if
     *      resumption is not possible).
     *   6. Waits for all server threads to finish, then shuts down the
     *      ExecutorService.
     */
    public void run(String[] args) throws Exception {

        /* pull in command line options from user */
        for (int i = 0; i < args.length; i++)
        {
            String arg = args[i];

            if (arg.equals("-help")) {
                printUsage();

            } else if (arg.equals("-n")) {
                if (args.length < i+2) {
                    printUsage();
                }
                numConnections = Integer.parseInt(args[++i]);

            } else if (arg.equals("-v")) {
                if (args.length < i+2)
                    printUsage();
                if (args[i+1].equals("d")) {
                    i++;
                    sslVersion = -1;
                }
                else {
                    sslVersion = Integer.parseInt(args[++i]);
                    if (sslVersion < 0 || sslVersion > 4) {
                        printUsage();
                    }
                }

            } else if (arg.equals("-e")) {
                listSuites = true;

            } else if (arg.equals("-l")) {
                if (args.length < i+2) {
                    printUsage();
                }
                cipherList = args[++i];
                System.out.println("cipherList: " + cipherList);

            } else if (arg.equals("-getp")) {
                listEnabledProtocols = true;
            }
        }

        switch (sslVersion) {
            case -1: version = "TLS"; break;
            case 0:  version = "SSLv3"; break;
            case 1:  version = "TLSv1"; break;
            case 2:  version = "TLSv1.1"; break;
            case 3:  version = "TLSv1.2"; break;
            case 4:  version = "TLSv1.3"; break;
            default:
                printUsage();
                return;
        }
        System.out.println("SSL/TLS version selected: " + version);

        /* Create CountDownLatches to keep track of server thread states */
        CountDownLatch openLatch = new CountDownLatch(numConnections);
        CountDownLatch openLatchResume = new CountDownLatch(numConnections);
        CountDownLatch closedLatch = new CountDownLatch(numConnections);

        if (listSuites) {
            SSLContext tmpCtx = SSLContext.getInstance(version, provider);
            tmpCtx.init(null, null, null);
            System.out.println("Available Cipher Suites:");
            String[] suites = tmpCtx.getDefaultSSLParameters()
                .getCipherSuites();
            for (String x : suites) {
                System.out.println("\t" + x);
            }
            return;
        }

        if (listEnabledProtocols) {
            SSLContext tmpCtx = SSLContext.getInstance(version, provider);
            tmpCtx.init(null, null, null);
            System.out.println("Available Protocols:");
            String[] protolist = tmpCtx.getDefaultSSLParameters()
                .getProtocols();
            for (String str : protolist) {
                System.out.println("\t" + str);
            }
            return;
        }

        /* ------------------------------------------------------------------ */
        /* Setup and start server threads
         * Returns an ExecutorService holding reference to all server
         * threads, handle is used later to shutdown ExecutorService */
        /* ------------------------------------------------------------------ */
        ExecutorService executor = LaunchServerThreads(
            startPort, version, openLatch, closedLatch,
            openLatchResume);

        /* ------------------------------------------------------------------ */
        /* Setup and start client threads */
        /* ------------------------------------------------------------------ */
        LaunchClientThreads(version, startPort,
            openLatchResume);

        System.out.println(
            "\n\n------------------------------------------------------------");
        PrintSessionIDs();
        System.out.println(
            "\n\n------------------------------------------------------------");
        System.out.println("\nDONE\n");

        closedLatch.await();
        executor.shutdown();
    }

    private void showPeer(SSLSocket sock) {
        int i = 0;
        byte[] sessionId = null;
        SSLSession session = sock.getSession();
        System.out.println("SSL version is " + session.getProtocol());
        System.out.println("SSL cipher suite is " + session.getCipherSuite());

        sessionId = session.getId();
        if (sessionId != null) {
            System.out.format("Session ID (%d bytes): ", sessionId.length);
            for (i = 0; i < sessionId.length; i++) {
                System.out.format("%02x", sessionId[i]);
            }
            System.out.println("");
        }
        System.out.println("Session created: " + session.getCreationTime());
        System.out.println("Session accessed: " + session.getLastAccessedTime());

        if (WolfSSLDebug.DEBUG) {
            try {
                Certificate[] certs = session.getPeerCertificates();
                if (certs != null && certs.length > 0) {
                    System.out.println(((X509Certificate)certs[0]).toString());
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private void printUsage() {
        System.out.println("Session resumption example and tester:");
        System.out.println("-?\t\tHelp, print this usage");
        System.out.println("-n <num>\tNumber of threads/connections");
        System.out.println("-v <num>\tSSL version [0-4], SSLv3(0) - " +
                           "TLS1.3(4)), default 3 : use 'd' for downgrade");
        System.out.println("-e\t\tGet all supported cipher suites");
        System.out.println("-l <str>\tCipher list");
        System.out.println("-getp\t\tGet enabled protocols");
        System.out.println("-setp <protocols> \tSet enabled protocols " +
                           "e.g \"TLSv1.1 TLSv1.2\"");
        System.exit(1);
    }

    public static void main(String[] args) {
        WolfSSL.loadLibrary();
        Security.insertProviderAt(new WolfSSLProvider(), 1);

        System.setProperty("javax.net.debug", "sessioncache,session");

        ClientResumeTest client = new ClientResumeTest();
        try {
            client.run(args);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
