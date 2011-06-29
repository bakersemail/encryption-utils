package com.google.code.encryptionutils;

import static org.junit.Assert.fail;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.junit.Before;
import org.junit.Test;

public class CertificateDownloadTest {
	private static final String HOST = "myozbills.cloudfoundry.com";
	private static final char[] KEYSTORE_PASSWORD = "changeit".toCharArray();
	private static final String SOURCE_KEYSTORE = "cf.jks";
	private static final String TARGET_KEYSTORE = "target/cf.keystore";
	
	@Before
	public void setup() {
		new File(TARGET_KEYSTORE).delete();
	}

	@Test
    public void downloadCertToFile() throws Exception {
        KeyStore ks = loadKeystore(getClass().getClassLoader().getResourceAsStream(SOURCE_KEYSTORE));

        SSLContext context = SSLContext.getInstance("TLS");
        TrustManagerFactory tmf =
            TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        X509TrustManager defaultTrustManager = (X509TrustManager)tmf.getTrustManagers()[0];
        SavingTrustManager tm = new SavingTrustManager(defaultTrustManager);
        context.init(null, new TrustManager[] {tm}, null);
        SSLSocketFactory factory = context.getSocketFactory();

        SSLSocket socket = (SSLSocket)factory.createSocket(HOST, 443);
        socket.setSoTimeout(10000);
        try {
            socket.startHandshake();
            socket.close();
            fail("Should have failed SSL verification, is the keystore empty?");
        } catch (SSLException e) {
            //expected
        }

        X509Certificate[] chain = tm.chain;
        if (chain == null) {
        	fail("Could not obtain server certificate chain");
            return;
        }

        MessageDigest sha1 = MessageDigest.getInstance("SHA1");
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        for (int i = 0; i < chain.length; i++) {
            X509Certificate cert = chain[i];
            sha1.update(cert.getEncoded());
            md5.update(cert.getEncoded());
        }

        int k = 0;
        X509Certificate cert = chain[k];
        String alias = HOST + "-" + (k + 1);
        ks.setCertificateEntry(alias, cert);

        OutputStream out = new FileOutputStream(TARGET_KEYSTORE);
        ks.store(out, KEYSTORE_PASSWORD);
        out.close();

        verifyCertInstalled(loadKeystore(new FileInputStream(TARGET_KEYSTORE)));
    }

	private KeyStore loadKeystore(InputStream in) throws Exception {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(in, KEYSTORE_PASSWORD);
        in.close();
		return ks;
	}

    private void verifyCertInstalled(KeyStore ks) throws Exception {
        SSLContext context = SSLContext.getInstance("TLS");
        TrustManagerFactory tmf =
            TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        X509TrustManager defaultTrustManager = (X509TrustManager)tmf.getTrustManagers()[0];
        SavingTrustManager tm = new SavingTrustManager(defaultTrustManager);
        context.init(null, new TrustManager[] {tm}, null);
        SSLSocketFactory factory = context.getSocketFactory();

        SSLSocket socket = (SSLSocket)factory.createSocket(HOST, 443);
        socket.setSoTimeout(10000);
        socket.startHandshake();
        socket.close();
	}

    private static class SavingTrustManager implements X509TrustManager {

        private final X509TrustManager tm;
        private X509Certificate[] chain;

        public SavingTrustManager(X509TrustManager tm) {
            this.tm = tm;
        }

        public X509Certificate[] getAcceptedIssuers() {
            throw new UnsupportedOperationException();
        }

        public void checkClientTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
            throw new UnsupportedOperationException();
        }

        public void checkServerTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
            this.chain = chain;
            tm.checkServerTrusted(chain, authType);
        }
    }

}
