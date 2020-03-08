package com.satyy.ldaps.trustsore;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Satyam Singh (satyamsingh00@gmail.com)
 */
public abstract class TruststoreSSLSocketFactory extends SSLSocketFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(TruststoreSSLSocketFactory.class);

    private static final String[] CIPHER_SUITES = new String[] {
            // ...
    };

    private final SSLSocketFactory delegate;

    public TruststoreSSLSocketFactory() {
        this.delegate = loadWithTrustStore(this.getTrustStoreLocation(), getTruststorePassword());
    }

    private static SSLSocketFactory loadWithTrustStore(String truststorePath, char[] truststorePassword) {

        SSLContext sslContext;
        try {
            sslContext = SSLContext.getInstance("TLSv1.2");
        } catch (NoSuchAlgorithmException e) {
            LOGGER.warn("TLS 1.2 not available", e);
            throw new RuntimeException("TLS 1.2 not available", e);
        }

        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance("PKCS12");
        } catch (KeyStoreException e) {
            LOGGER.warn("PKCS12 not supported", e);
            throw new RuntimeException("PKCS12 not supported", e);
        }

        try (FileInputStream fileInputStream = new FileInputStream(truststorePath)) {
            keyStore.load(fileInputStream, truststorePassword);
        } catch (GeneralSecurityException | IOException e) {
            LOGGER.warn("Could not load from: " + truststorePath, e);
            throw new RuntimeException("Could not load from: " + truststorePath, e);
        }

        String defaultTrustManagerAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
        TrustManagerFactory trustManagerFactory;
        try {
            trustManagerFactory = TrustManagerFactory.getInstance(defaultTrustManagerAlgorithm);
        } catch (NoSuchAlgorithmException e) {
            LOGGER.warn("Default algorithm not supported: " + defaultTrustManagerAlgorithm, e);
            throw new RuntimeException("Default algorithm not supported: " + defaultTrustManagerAlgorithm, e);
        }

        try {
            trustManagerFactory.init(keyStore);
        } catch (KeyStoreException e) {
            LOGGER.warn("Could not initialize trust manager factory", e);
            throw new RuntimeException("Could not initialize trust manager factory", e);
        }

        try {
            sslContext.init(null, trustManagerFactory.getTrustManagers(), null);
        } catch (KeyManagementException e) {
            LOGGER.warn("Could not initialize ssl context", e);
            throw new RuntimeException("Could not initialize ssl context", e);
        }

        return sslContext.getSocketFactory();
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        return delegate.createSocket(address, port, localAddress, localPort);
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        return delegate.createSocket(host, port);
    }

    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
        return delegate.createSocket(s, host, port, autoClose);
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException, UnknownHostException {
        return delegate.createSocket(host, port, localHost, localPort);
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
        return delegate.createSocket(host, port);
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return CIPHER_SUITES;
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return CIPHER_SUITES;
    }

    @Override
    public Socket createSocket() throws IOException {
        return delegate.createSocket();
    }

    @Override
    public Socket createSocket(Socket s, InputStream consumed, boolean autoClose) throws IOException {
        return delegate.createSocket(s, consumed, autoClose);
    }

    protected abstract String getTrustStoreLocation();

    protected abstract char[] getTruststorePassword();

}