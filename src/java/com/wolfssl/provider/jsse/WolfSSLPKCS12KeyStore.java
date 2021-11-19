/* WolfSSLPKCS12KeyStore.java
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
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


package com.wolfssl.provider.jsse;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreSpi;

import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import java.util.Date;
import java.util.Enumeration;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.ManagerFactoryParameters;

public class WolfSSLPKCS12KeyStore extends KeyStoreSpi {

    public synchronized Key engineGetKey(String alias, char[] password)
        throws NoSuchAlgorithmException, UnrecoverableKeyException
    {
        return null;
    }

    public synchronized Certificate[] engineGetCertificateChain(String alias)
    {
        return null;
    }

    public synchronized Certificate engineGetCertificate(String alias)
    {
        return null;
    }

    public synchronized Date engineGetCreationDate(String alias)
    {
        return null;
    }

    public synchronized void engineSetKeyEntry(String alias, Key key,
            char[] password, Certificate[] chain) throws KeyStoreException
    {
    }

    public synchronized void engineSetKeyEntry(String alias, byte[] key,
            Certificate[] chain) throws KeyStoreException
    {
    }

    public synchronized void engineSetCertificateEntry(String alias,
            Certificate cert) throws KeyStoreException
    {
    }

    public synchronized void engineDeleteEntry(String alias)
        throws KeyStoreException
    {
    }

    public synchronized Enumeration<String> engineAliases()
    {
        return null;
    }

    public synchronized boolean engineContainsAlias(String alias)
    {
        return false;
    }

    public synchronized int engineSize()
    {
        return 0;
    }

    public synchronized boolean engineIsKeyEntry(String alias)
    {
        return false;
    }

    public synchronized boolean engineIsCertificateEntry(String alias)
    {
        return false;
    }

    public synchronized String engineGetCertificateAlias(Certificate cert)
    {
        return null;
    }

    public synchronized void engineStore(OutputStream stream, char[] password)
        throws IOException, NoSuchAlgorithmException, CertificateException
    {
    }

    public synchronized void engineStore(KeyStore.LoadStoreParameter param)
        throws IOException, NoSuchAlgorithmException, CertificateException
    {
    }

    public synchronized void engineLoad(InputStream stream, char[] password)
        throws IOException, NoSuchAlgorithmException, CertificateException
    {
    }

    public synchronized void engineLoad(KeyStore.LoadStoreParameter param)
        throws IOException, NoSuchAlgorithmException, CertificateException
    {
    }

    public synchronized KeyStore.Entry engineGetEntry(String alias,
            KeyStore.ProtectionParameter protParam)
        throws KeyStoreException, NoSuchAlgorithmException,
               UnrecoverableEntryException
    {
        return null;
    }

    public synchronized void engineSetEntry(String alias,
            KeyStore.Entry entry, KeyStore.ProtectionParameter protParam)
        throws KeyStoreException
    {
    }

    public synchronized boolean engineEntryInstanceOf(String alias,
            Class<? extends KeyStore.Entry> entryClass)
    {
        return false;
    }
}

