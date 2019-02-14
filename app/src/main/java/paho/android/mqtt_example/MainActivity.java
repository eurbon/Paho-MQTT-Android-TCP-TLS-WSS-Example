package paho.android.mqtt_example;

import android.content.Context;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;

import org.eclipse.paho.android.service.MqttAndroidClient;
import org.eclipse.paho.client.mqttv3.IMqttActionListener;
import org.eclipse.paho.client.mqttv3.IMqttDeliveryToken;
import org.eclipse.paho.client.mqttv3.IMqttToken;
import org.eclipse.paho.client.mqttv3.MqttCallback;
import org.eclipse.paho.client.mqttv3.MqttClient;
import org.eclipse.paho.client.mqttv3.MqttConnectOptions;
import org.eclipse.paho.client.mqttv3.MqttException;
import org.eclipse.paho.client.mqttv3.MqttMessage;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

/**
 * This is an implementation of MQTT Paho library MQTT Service which allows you to
 * connect to MQTT server via WebSockets, TCP or TLS with a stored certificate in resources folder
 * How to use:
 * Just uncomment desired BROKER and launch the application, then check logs for MQTT data
 */

public class MainActivity extends AppCompatActivity {


    /**
     * Test servers from http://test.mosquitto.org and tps://www.hivemq.com/try-out/
     */

    //public static final String BROKER = "ssl://test.mosquitto.org:8883";
    //pblic static final String BROKER = "tcp://test.mosquitto.org:1883";
    public static final String BROKER = "ws://broker.hivemq.com:8000";

    //# Means subscribe to everything
    public static final String TOPIC = "#";

    //Optional
    public static final String USERNAME = "YOUR_USERNAME";
    public static final String PASSWORD = "YOUR_PASSWORD";


    public MqttAndroidClient CLIENT;
    public MqttConnectOptions MQTT_CONNECTION_OPTIONS;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(paho.android.mqtt_example.R.layout.activity_main);


        MqttSetup(this);
        MqttConnect();

        CLIENT.setCallback(new MqttCallback() {
            @Override
            public void connectionLost(Throwable cause) {

            }

            //background notification
            @Override
            public void messageArrived(String topic, MqttMessage message) throws Exception {
                Log.d("topic:" + topic, "message:" + message.toString());
            }

            @Override
            public void deliveryComplete(IMqttDeliveryToken token) {

            }
        });
    }

    void MqttSetup(Context context) {


        CLIENT = new MqttAndroidClient(getBaseContext(), BROKER, MqttClient.generateClientId());
        MQTT_CONNECTION_OPTIONS = new MqttConnectOptions();


        /**
         * Depending on your MQTT broker, you might want to set these
         */

        //MQTT_CONNECTION_OPTIONS.setUserName(USERNAME);
        //MQTT_CONNECTION_OPTIONS.setPassword(PASSWORD.toCharArray());


        /**
         * SSL broker requires a certificate to authenticate their connection
         * Certificate can be found in resources folder /res/raw/
         */
        if (BROKER.contains("ssl")) {
            SelfSignedSocketFactory.SocketFactoryOptions socketFactoryOptions = new SelfSignedSocketFactory.SocketFactoryOptions();
            try {
                socketFactoryOptions.withCaInputStream(context.getResources().openRawResource(R.raw.ca))
                    .withClientBksInputStream(getResources().openRawResource(R.raw.client_bks))
                .withClientBksPassword("shinestb");
                MQTT_CONNECTION_OPTIONS.setSocketFactory(new SelfSignedSocketFactory(socketFactoryOptions));
                /*socketFactoryOptions.withCaInputStream(context.getResources().openRawResource(paho.android.mqtt_example.R.raw.mosquitto_org));
                MQTT_CONNECTION_OPTIONS.setSocketFactory(new SocketFactory(socketFactoryOptions));*/
            } catch (IOException | NoSuchAlgorithmException | KeyStoreException | CertificateException | KeyManagementException | UnrecoverableKeyException e) {
                e.printStackTrace();
            }
        }
    }

    void MqttConnect() {
        try {

            final IMqttToken token = CLIENT.connect(MQTT_CONNECTION_OPTIONS);
            token.setActionCallback(new IMqttActionListener() {
                @Override
                public void onSuccess(IMqttToken asyncActionToken) {
                    // We are connected
                    Log.d("mqtt:", "connected, token:" + asyncActionToken.toString());
                    subscribe(TOPIC, (byte) 1);
                }

                @Override
                public void onFailure(IMqttToken asyncActionToken, Throwable exception) {
                    // Something went wrong e.g. connection timeout or firewall problems
                    Log.d("mqtt:", "not connected" + asyncActionToken.toString());
                }
            });
        } catch (MqttException e) {
            e.printStackTrace();
        }
    }

    void subscribe(String topic, byte qos) {

        try {
            IMqttToken subToken = CLIENT.subscribe(topic, qos);
            subToken.setActionCallback(new IMqttActionListener() {
                @Override
                public void onSuccess(IMqttToken asyncActionToken) {
                    Log.d("mqtt:", "subscribed" + asyncActionToken.toString());
                }

                @Override
                public void onFailure(IMqttToken asyncActionToken,
                                      Throwable exception) {

                    Log.d("mqtt:", "subscribing error");
                }
            });
        } catch (MqttException e) {
            e.printStackTrace();
        }
    }

    void publish(String topic, String msg) {

        //0 is the Qos
        MQTT_CONNECTION_OPTIONS.setWill(topic, msg.getBytes(), 0, false);
        try {
            IMqttToken token = CLIENT.connect(MQTT_CONNECTION_OPTIONS);
            token.setActionCallback(new IMqttActionListener() {
                @Override
                public void onSuccess(IMqttToken asyncActionToken) {
                    Log.d("mqtt:", "send done" + asyncActionToken.toString());
                }

                @Override
                public void onFailure(IMqttToken asyncActionToken, Throwable exception) {
                    Log.d("mqtt:", "publish error" + asyncActionToken.toString());
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    void unsubscribe(String topic) {

        try {
            IMqttToken unsubToken = CLIENT.unsubscribe(topic);
            unsubToken.setActionCallback(new IMqttActionListener() {
                @Override
                public void onSuccess(IMqttToken asyncActionToken) {

                    Log.d("mqtt:", "unsubcribed");
                }

                @Override
                public void onFailure(IMqttToken asyncActionToken,
                                      Throwable exception) {


                    Log.d("mqtt:", "couldnt unregister");
                }
            });
        } catch (MqttException e) {
            e.printStackTrace();
        }
    }

    void disconnect() {
        try {
            IMqttToken disconToken = CLIENT.disconnect();
            disconToken.setActionCallback(new IMqttActionListener() {
                @Override
                public void onSuccess(IMqttToken asyncActionToken) {
                    Log.d("mqtt:", "disconnected");
                }

                @Override
                public void onFailure(IMqttToken asyncActionToken,
                                      Throwable exception) {


                    Log.d("mqtt:", "couldnt disconnect");
                }
            });
        } catch (MqttException e) {
            e.printStackTrace();
        }

    }
}
