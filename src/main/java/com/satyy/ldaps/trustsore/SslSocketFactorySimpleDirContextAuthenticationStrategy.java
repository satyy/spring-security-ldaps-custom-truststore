package com.satyy.ldaps.trustsore;

import java.util.Hashtable;

import javax.net.ssl.SSLSocketFactory;

import org.springframework.ldap.core.support.SimpleDirContextAuthenticationStrategy;

/**
 * @author Satyam Singh (satyamsingh00@gmail.com)
 */
final public class SslSocketFactorySimpleDirContextAuthenticationStrategy extends SimpleDirContextAuthenticationStrategy {

    private final Class<? extends SSLSocketFactory> sslSocketFactoryClass;

    public SslSocketFactorySimpleDirContextAuthenticationStrategy(Class<? extends SSLSocketFactory> sslSocketFactoryClass) {
        this.sslSocketFactoryClass = sslSocketFactoryClass;
    }

    Class<? extends SSLSocketFactory> getSslSocketFactoryClass() {
        return sslSocketFactoryClass;
    }

    @Override
    public void setupEnvironment(Hashtable<String, Object> env, String userDn, String password) {
        super.setupEnvironment(env, userDn, password);
        env.put("java.naming.ldap.factory.socket", this.sslSocketFactoryClass.getName());
    }

}