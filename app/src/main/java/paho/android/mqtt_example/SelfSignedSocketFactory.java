package paho.android.mqtt_example;

import android.util.Log;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.security.cert.CertificateException;
import timber.log.Timber;

/**
 * Original SocketFactory file taken from https://github.com/owntracks/android
 */

public class SelfSignedSocketFactory extends javax.net.ssl.SSLSocketFactory {
    private javax.net.ssl.SSLSocketFactory factory;


    public static class SocketFactoryOptions {

        private InputStream caCrtInputStream;
        private InputStream caClientBksInputStream;
        private String caClientBksPassword;


        /**
         *
         * @param stream the self-signed Root CA Certificate's stream
         * @return
         */
        public SocketFactoryOptions withCaInputStream(InputStream stream) {
            this.caCrtInputStream = stream;
            return this;
        }


        /**
         *
         * @param stream the self-signed client Certificate's stream .
         * @return
         */
        public SocketFactoryOptions withClientBksInputStream(InputStream stream) {
            this.caClientBksInputStream = stream;
            return this;
        }


        public SocketFactoryOptions withClientBksPassword(String password) {
            this.caClientBksPassword = password;
            return this;
        }


        public boolean hasCaCrt() {
            return caCrtInputStream != null;
        }


        public boolean hasClientBksCrt() {
            return caClientBksPassword != null;
        }


        public InputStream getCaCrtInputStream() {
            return caCrtInputStream;
        }


        public InputStream getCaClientBksInputStream() {
            return caClientBksInputStream;
        }


        public String getCaClientBksPassword() {
            return caClientBksPassword;
        }


        public boolean hasClientBksPassword() {
            return (caClientBksPassword != null) && !caClientBksPassword.equals("");
        }
    }


    public SelfSignedSocketFactory()
        throws CertificateException, KeyStoreException, NoSuchAlgorithmException, IOException, KeyManagementException,
               java.security.cert.CertificateException, UnrecoverableKeyException {
        this(new SocketFactoryOptions());
    }


    private TrustManagerFactory tmf;


    public SelfSignedSocketFactory(SocketFactoryOptions options)
        throws KeyStoreException, NoSuchAlgorithmException, IOException, KeyManagementException,
               java.security.cert.CertificateException, UnrecoverableKeyException {
        Log.v(this.toString(), "initializing CustomSocketFactory");

        tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("X509");

        if (options.hasCaCrt()) {
            Log.v(this.toString(), "MQTT_CONNECTION_OPTIONS.hasCaCrt(): true");
            // CA certificate is used to authenticate server
            CertificateFactory cAf = CertificateFactory.getInstance("X.509");
            X509Certificate ca = (X509Certificate) cAf.generateCertificate(options.getCaCrtInputStream());
            KeyStore caKs = KeyStore.getInstance(KeyStore.getDefaultType());
            caKs.load(null, null);
            caKs.setCertificateEntry("ca-certificate", ca);
            tmf.init(caKs);
        } else {
            Timber.v("CA sideload: false, using system keystore");
            KeyStore keyStore = KeyStore.getInstance("AndroidCAStore");
            keyStore.load(null);
            tmf.init(keyStore);
        }

        if (options.hasClientBksCrt()) {
            Log.v(this.toString(), "MQTT_CONNECTION_OPTIONS.hasClientBksCrt(): true");

            // init client key store
            KeyStore clientkeyStore = KeyStore.getInstance("BKS");
            clientkeyStore.load(options.getCaClientBksInputStream(),
                options.hasClientBksPassword() ? options.getCaClientBksPassword().toCharArray() : new char[0]);
            kmf.init(clientkeyStore,
                options.hasClientBksPassword() ? options.getCaClientBksPassword().toCharArray() : new char[0]);

        } else {
            Log.v(this.toString(), "Client .bks sideload: false, using null CLIENT cert");
            kmf.init(null, null);
        }

        // Create an SSLContext that uses our TrustManager
        SSLContext context = SSLContext.getInstance("TLSv1.2");
        context.init(kmf.getKeyManagers(), getTrustManagers(), null);
        this.factory = context.getSocketFactory();

    }


    public TrustManager[] getTrustManagers() {
        return tmf.getTrustManagers();
    }


    @Override
    public String[] getDefaultCipherSuites() {
        return this.factory.getDefaultCipherSuites();
    }


    @Override
    public String[] getSupportedCipherSuites() {
        return this.factory.getSupportedCipherSuites();
    }


    @Override
    public Socket createSocket() throws IOException {
        SSLSocket r = (SSLSocket) this.factory.createSocket();
        r.setEnabledProtocols(new String[] { "TLSv1", "TLSv1.1", "TLSv1.2" });
        return r;
    }


    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
        SSLSocket r = (SSLSocket) this.factory.createSocket(s, host, port, autoClose);
        r.setEnabledProtocols(new String[] { "TLSv1", "TLSv1.1", "TLSv1.2" });
        return r;
    }


    @Override
    public Socket createSocket(String host, int port) throws IOException {

        SSLSocket r = (SSLSocket) this.factory.createSocket(host, port);
        r.setEnabledProtocols(new String[] { "TLSv1", "TLSv1.1", "TLSv1.2" });
        return r;
    }


    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
        SSLSocket r = (SSLSocket) this.factory.createSocket(host, port, localHost, localPort);
        r.setEnabledProtocols(new String[] { "TLSv1", "TLSv1.1", "TLSv1.2" });
        return r;
    }


    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        SSLSocket r = (SSLSocket) this.factory.createSocket(host, port);
        r.setEnabledProtocols(new String[] { "TLSv1", "TLSv1.1", "TLSv1.2" });
        return r;
    }


    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
        throws IOException {
        SSLSocket r = (SSLSocket) this.factory.createSocket(address, port, localAddress, localPort);
        r.setEnabledProtocols(new String[] { "TLSv1", "TLSv1.1", "TLSv1.2" });
        return r;
    }
}
