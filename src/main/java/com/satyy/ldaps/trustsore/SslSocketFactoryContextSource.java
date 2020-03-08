package com.satyy.ldaps.trustsore;

import java.util.Hashtable;

import javax.net.ssl.SSLSocketFactory;

import org.springframework.ldap.core.support.DirContextAuthenticationStrategy;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;

/**
 * @author Satyam Singh (satyamsingh00@gmail.com)
 */
public final class SslSocketFactoryContextSource extends DefaultSpringSecurityContextSource {

    private DirContextAuthenticationStrategy authenticationStrategy;

    public SslSocketFactoryContextSource(String providerUrl) {
        super(providerUrl);
    }

    @Override
    public void setAuthenticationStrategy(DirContextAuthenticationStrategy authenticationStrategy) {
        this.authenticationStrategy = authenticationStrategy;
        super.setAuthenticationStrategy(authenticationStrategy);
    }

    @Override
    protected Hashtable<String, Object> getAuthenticatedEnv(String principal, String credentials) {
        Hashtable<String, Object> env = super.getAuthenticatedEnv(principal, credentials);
        if (this.authenticationStrategy instanceof SslSocketFactorySimpleDirContextAuthenticationStrategy) {
            Class<? extends SSLSocketFactory> sslSocketFactoryClass = ((SslSocketFactorySimpleDirContextAuthenticationStrategy) this.authenticationStrategy).getSslSocketFactoryClass();
            env.put("java.naming.ldap.factory.socket", sslSocketFactoryClass.getName());
        }
        return env;
    }

}