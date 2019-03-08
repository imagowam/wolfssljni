/* WolfSSLSocketFactoryTest.java
 *
 * Copyright (C) 2006-2018 wolfSSL Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

package com.wolfssl.provider.jsse.test;

import org.junit.Test;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import static org.junit.Assert.*;

import java.util.ArrayList;

import com.wolfssl.provider.jsse.WolfSSLSocketFactory;

import java.io.FileInputStream;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import java.net.InetAddress;
import java.net.SocketException;
import java.security.Security;
import java.security.Provider;
import java.security.KeyStore;

import java.io.IOException;
import java.io.FileNotFoundException;
import java.security.KeyStoreException;
import java.security.KeyManagementException;
import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;

import com.wolfssl.provider.jsse.WolfSSLProvider;

public class WolfSSLSocketFactoryTest {

    public final static String clientJKS = "./examples/provider/client.jks";
    public final static char[] jksPass = "wolfSSL test".toCharArray();

    private static String allProtocols[] = {
        "TLSV1",
        "TLSV1.1",
        "TLSV1.2",
        "TLS"
    };

    private static ArrayList<String> enabledProtocols =
        new ArrayList<String>();

    /* list of SSLSocketFactories for each protocol supported */
    private static ArrayList<SSLSocketFactory> sockFactories =
        new ArrayList<SSLSocketFactory>();

    @BeforeClass
    public static void testSetupSocketFactory() throws NoSuchProviderException,
        NoSuchAlgorithmException, IllegalStateException,
        KeyManagementException, Exception {

        SSLContext ctx;
        KeyManagerFactory km;
        TrustManagerFactory tm;
        KeyStore pKey, cert;

        System.out.println("WolfSSLSocketFactory Class");

        /* install wolfJSSE provider at runtime */
        Security.addProvider(new WolfSSLProvider());

        Provider p = Security.getProvider("wolfJSSE");
        assertNotNull(p);

        /* populate enabledProtocols */
        for (int i = 0; i < allProtocols.length; i++) {
            try {
                ctx = SSLContext.getInstance(allProtocols[i], "wolfJSSE");
                enabledProtocols.add(allProtocols[i]);

            } catch (NoSuchAlgorithmException e) {
                /* protocol not enabled */
            }
        }

        try {
            /* set up KeyStore */
            pKey = KeyStore.getInstance("JKS");
            pKey.load(new FileInputStream(clientJKS), jksPass);
            cert = KeyStore.getInstance("JKS");
            cert.load(new FileInputStream(clientJKS), jksPass);

            /* trust manager (certificates) */
            tm = TrustManagerFactory.getInstance("SunX509");
            tm.init(cert);

            /* load private key */
            km = KeyManagerFactory.getInstance("SunX509");
            km.init(pKey, jksPass);

        } catch (KeyStoreException kse) {
            throw new Exception(kse);
        } catch (FileNotFoundException fnfe) {
            throw new Exception(fnfe);
        } catch (IOException ioe) {
            throw new Exception(ioe);
        }

        for (int i = 0; i < enabledProtocols.size(); i++) {
            ctx = SSLContext.getInstance(enabledProtocols.get(i), "wolfJSSE");

            ctx.init(km.getKeyManagers(), tm.getTrustManagers(), null);

            SSLSocketFactory sf = ctx.getSocketFactory();
            sockFactories.add(sf);
        }
    }

    @Test
    public void testGetDefaultCipherSuites()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        System.out.print("\tgetDefaultCipherSuites()");

        for (int i = 0; i < sockFactories.size(); i++) {
            SSLSocketFactory sf = sockFactories.get(i);
            String[] cipherSuites = sf.getDefaultCipherSuites();

            if (cipherSuites == null) {
                System.out.println("\t... failed");
                fail("SSLSocketFactory.getDefaultCipherSuites() failed");
            }
        }

        System.out.println("\t... passed");
    }

    @Test
    public void testGetSupportedCipherSuites()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        System.out.print("\tgetSupportedCipherSuites()");

        for (int i = 0; i < sockFactories.size(); i++) {
            SSLSocketFactory sf = sockFactories.get(i);
            String[] cipherSuites = sf.getSupportedCipherSuites();

            if (cipherSuites == null) {
                System.out.println("\t... failed");
                fail("SSLSocketFactory.getSupportedCipherSuites() failed");
            }
        }

        System.out.println("\t... passed");
    }

    @Test
    public void testCreateSocket()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               IOException {

        System.out.print("\tcreateSocket()");

        for (int i = 0; i < sockFactories.size(); i++) {
            String addrStr = "www.example.com";
            InetAddress addr = InetAddress.getByName("www.example.com");
            int port = 443;
            SSLSocketFactory sf = sockFactories.get(i);
            SSLSocket s = null;

            try {

                /* no arguments */
                s = (SSLSocket)sf.createSocket();
                if (s == null) {
                    System.out.println("\t\t\t... failed");
                    fail("SSLSocketFactory.createSocket() failed");
                }

                /* InetAddress, int */
                s = (SSLSocket)sf.createSocket(addr, port);
                if (s == null) {
                    System.out.println("\t\t\t... failed");
                    fail("SSLSocketFactory.createSocket(Ii) failed");
                }

                /* String, int */
                s = (SSLSocket)sf.createSocket(addrStr, port);
                if (s == null) {
                    System.out.println("\t\t\t... failed");
                    fail("SSLSocketFactory.createSocket(Si) failed");
                }

            } catch (SocketException e) {
                System.out.println("\t\t\t... failed");
                throw e;
            }
        }

        System.out.println("\t\t\t... passed");
    }
}
