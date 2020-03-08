package com.satyy.ldaps.trustsore;

import javax.net.SocketFactory;

/**
 * @author Satyam Singh (satyamsingh00@gmail.com)
 */
public class CustomDomainSSLSocketFactory extends TruststoreSSLSocketFactory {

    public static SocketFactory getDefault() {
        return new CustomDomainSSLSocketFactory();
    }

    /**
     * Update this value to the Truststore password.
     * @return TrustStore password.
     */
    @Override
    protected char[] getTruststorePassword() {
        return "password".toCharArray();
    }

    /**
     * Update this value to point to TrustStore.
     * @return Truststore path containing public certificate of LDAP Server.
     */
    @Override
    protected String getTrustStoreLocation() {
        return "/home/satyy/certificates/ldaptest/ldaptruststore.p12";
    }

}