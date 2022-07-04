package kr.ac.snu.mmlab.apm.client;

import static android.content.Context.DEVICE_POLICY_SERVICE;
import static kr.ac.snu.mmlab.apm.client.ApmEnums.Command;
import static kr.ac.snu.mmlab.apm.client.ApmEnums.Command.*;
import static kr.ac.snu.mmlab.apm.client.ApmEnums.Regulation;
import static kr.ac.snu.mmlab.apm.client.ApmEnums.Restriction;
import static kr.ac.snu.mmlab.apm.client.ApmEnums.Restriction.*;
import static kr.ac.snu.mmlab.apm.client.ApmEnums.Request;
import static kr.ac.snu.mmlab.apm.client.ApmEnums.Response;
import static kr.ac.snu.mmlab.apm.client.ApmEnums.RsaEnc;

import android.app.Service;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.os.IBinder;
import android.util.Base64;
import android.util.Log;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

public class AdminService extends Service {

    private static final String LOG_TAG = "APM_SERVICE";
    private static final int POLLING_INTERVAL = 3000; // 3 sec
    private static int MAX_VALID_NONCE = 10; // POLLING_INTERVAL * MAX_VALID_NONCE = NONCE lifetime
    private static final String VERSION =  "0.1"; // prototype
    private static final int NONCE_SIZE_BYTE = 32;  // 256 bit
    private static final String MAGIC = "APM";

    static final String EXTRA_USER_ID = "USER_ID";
    static final String EXTRA_UAM_ID = "UAM_ID";
    static final String EXTRA_SERVER_IP = "SERVER_IP";
    static final String EXTRA_SERVER_PORT = "SERVER_PORT";

    DevicePolicyManager mDpm;
    ComponentName mComponentName;

    String mUserId;
    String mUamId;
    String mServIp;
    String mServPort;
    String mDeviceMsg;
    String mServerMsg;
    SSLSocketFactory mSslSocketFactory;
    SSLSocket mSocket;
    Thread mNetworkThread;
    SecureRandom mSecureRandom = new SecureRandom();
    List<byte[]> mValidNonces = new ArrayList<>();
    boolean mIsPolling;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String cmd = intent.getAction();
        Log.i(LOG_TAG, "onStartCommand: " + cmd);
        mUserId = intent.getStringExtra(EXTRA_USER_ID);
        mUamId = intent.getStringExtra(EXTRA_UAM_ID);
        mServIp = intent.getStringExtra(EXTRA_SERVER_IP);
        mServPort = intent.getStringExtra(EXTRA_SERVER_PORT);
        if (mDpm == null) {
            mDpm = (DevicePolicyManager) getSystemService(DEVICE_POLICY_SERVICE);
        }
        if (mComponentName == null) {
            mComponentName = AdminReceiver.getComponentName(getApplicationContext());
        }

        try {
            mDeviceMsg = getMsg(cmd);
        } catch (Exception e) {
            e.printStackTrace();
        }
        mIsPolling = ApmEnums.Command.Start.toString().equals(cmd);
        setupSslContext();
        sendToServer();
        return START_NOT_STICKY;
    }

    private void sendToServer() {
        if (mNetworkThread != null && mNetworkThread.isAlive()) {
            activityLog("Interrupt existing network thread.");
            mNetworkThread.interrupt();
        }

        mNetworkThread = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    do {
                        mSocket = (SSLSocket) mSslSocketFactory.createSocket(mServIp,
                                Integer.parseInt(mServPort));
                        mSocket.setEnabledProtocols(mSocket.getEnabledProtocols());
                        mSocket.setEnabledCipherSuites(mSocket.getSupportedCipherSuites());

                        BufferedReader reader = new BufferedReader(
                                new InputStreamReader(mSocket.getInputStream()));

                        BufferedWriter bw = new BufferedWriter(
                                new OutputStreamWriter(mSocket.getOutputStream()));
                        PrintWriter writer = new PrintWriter(bw, true /*auto flush*/);

                        writer.println(mDeviceMsg);
                        activityLog("Sent: " + mDeviceMsg);

                        mServerMsg = reader.readLine();
                        activityLog("Received: " + mServerMsg);
                        parseServerMsg();

                        if (mIsPolling) {
                            Thread.sleep(POLLING_INTERVAL);
                        }

                    } while(mIsPolling);
                } catch (Exception e) {
                    e.printStackTrace();
                } finally {
                    if (mSocket != null && !mSocket.isClosed()) {
                        try {
                            mSocket.close();
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
                }
            }
        });
        mNetworkThread.start();
    }

    private void parseServerMsg() throws Exception {
        JSONObject servMsg = new JSONObject(mServerMsg);
        // 1. check magic
        String servMagic = servMsg.getString(Response.Magic.toString());
        if (!MAGIC.equals(servMagic)) {
            Log.i(LOG_TAG, "parseServerMsg(): invalid magic. - " + servMagic);
            return;
        }

        // 2. verify signature
        JSONArray regulation = servMsg.getJSONArray(Response.Regulation.toString());
        String servSign = servMsg.getString(Response.Signature.toString());
        if (!isValidSignature(regulation.toString(), servSign)) {
            Log.i(LOG_TAG, "parseServerMsg(): invalid signature. - " + servSign);
            return;
        }

        // 3. check nonce
        JSONObject servNonceObj = regulation.getJSONObject(Regulation.Nonce.ordinal());
        String servNonce = servNonceObj.getString(Regulation.Nonce.toString());

        if (!isValidNonce(servNonce)) {
            Log.i(LOG_TAG, "parseServerMsg(): invalid nonce - " + servNonce
                    + " (size: " + servNonce.length() + ")");
            return;
        }

        // 4. check version
        // Version value will be used to set range of restriction functionality for forward or
        // backward compatibility. Note that it won't drop or block APM policy application if
        // version is not ridiculous value.
        JSONObject servVerObj = regulation.getJSONObject(Regulation.Version.ordinal());
        double ServApmVer = Double.parseDouble(servVerObj.getString(Regulation.Version.toString()));
        if (ServApmVer == 0) {
            Log.i(LOG_TAG, "parseServerMsg(): invalid version - " + ServApmVer);
            return;
        }

        // 4. apply
        JSONObject restrictionObj = regulation.getJSONObject(Regulation.Restriction.ordinal());
        JSONArray restrictionList = restrictionObj.getJSONArray(Regulation.Restriction.toString());
        if (restrictionList == null || restrictionList.length() == 0) {
            Log.i(LOG_TAG, "parseServerMsg(): invalid or empty restriction");
            return;
        }

        for (int i = 0 ; i < restrictionList.length() ; i++) {
            JSONObject servRestriction = restrictionList.getJSONObject(i);
            for (Restriction r : Restriction.values()) {
                if (servRestriction.has(r.toString())) {
                    Object enforced = servRestriction.get(r.toString());
                    switch (r) {
                        case SetCameraDisabled :
                            mDpm.setCameraDisabled(mComponentName, (boolean) enforced);
                            activityLog("SetCameraDisabled: " + enforced);
                            break;
                        case SetMasterVolumeMuted :
                            mDpm.setMasterVolumeMuted(mComponentName, (boolean) enforced);
                            activityLog("SetMasterVolumeMuted: " + enforced);
                            break;
                        case SetUamWindowBlurred :
                            activityLog("SetUamWindowBlurred: " + enforced);
                            break;
                    }
                }
            }
        }
    }

    private boolean isValidNonce(String servNonce) {
        byte[] servNonceBytes = Base64.decode(servNonce, Base64.URL_SAFE);
        String servNonceStr = Arrays.toString(servNonceBytes);
        for (byte[] nonce : mValidNonces) {
            if (servNonceStr.equals(Arrays.toString(nonce))) {
                return true;
            }
        }
        return false;
    }

    private boolean isValidSignature(String signed, String sign) throws Exception {
        byte[] signBytes = Base64.decode(sign, Base64.DEFAULT);
        Signature verifier = Signature.getInstance("SHA256withRSA/PSS", new BouncyCastleProvider());
        verifier.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
                32 , 1));
        verifier.initVerify(loadCert());
        Log.i(LOG_TAG, "isValidSignature(), signed: " + signed);
        verifier.update(signed.getBytes(StandardCharsets.UTF_8));
        return verifier.verify(signBytes);
    }

    private String getMsg(String cmd) throws Exception {

        if (Hello.toString().equals(cmd)) {
            return "Hello! This is a client device.";
        }

        if (Start.toString().equals(cmd)) {
            JSONObject reqMsg = new JSONObject();
            reqMsg.put(Request.Magic.toString(), MAGIC);

            JSONArray plainReqMsg = new JSONArray();
            plainReqMsg.put(new JSONObject().put(RsaEnc.UserId.toString(), mUserId));
            plainReqMsg.put(new JSONObject().put(RsaEnc.Version.toString(), VERSION));
            plainReqMsg.put(new JSONObject().put(RsaEnc.Command.toString(), ApmEnums.Command.Start));
            plainReqMsg.put(new JSONObject().put(RsaEnc.Nonce.toString(), getNonce()));

            reqMsg.put(Request.RsaEnc.toString(), encryptRsa(plainReqMsg.toString()));
            reqMsg.put(Request.KeyAlias.toString(), getKeyAlias());
            return reqMsg.toString();
        }

        if (Stop.toString().equals(cmd)) {
            JSONObject stopMsg = new JSONObject();
            stopMsg.put(Request.Magic.toString(), MAGIC);

            JSONArray plainStopMsg = new JSONArray();
            plainStopMsg.put(new JSONObject().put(RsaEnc.UserId.toString(), mUserId));
            plainStopMsg.put(new JSONObject().put(RsaEnc.Version.toString(), VERSION));
            plainStopMsg.put(new JSONObject().put(RsaEnc.Command.toString(), ApmEnums.Command.Stop));
            plainStopMsg.put(new JSONObject().put(RsaEnc.Nonce.toString(), getNonce()));

            stopMsg.put(Request.RsaEnc.toString(), encryptRsa(plainStopMsg.toString()));
            stopMsg.put(Request.KeyAlias.toString(), getKeyAlias());

            // release current restrictions
            mDpm.setCameraDisabled(mComponentName, false);
            mDpm.setMasterVolumeMuted(mComponentName, false);
            activityLog("SetCameraDisabled: false");
            activityLog("SetMasterVolumeMuted: false");
            activityLog("SetUamWindowBlurred: false");

            return stopMsg.toString();
        }

        return null;
    }

    private String encryptRsa(String plainText) throws CertificateException, NoSuchPaddingException,
            NoSuchAlgorithmException, UnsupportedEncodingException, BadPaddingException,
            IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException {
        Certificate cert = loadCert();
        PublicKey publicKey = cert.getPublicKey();
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPwithSHA-256andMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, new OAEPParameterSpec("SHA-256", "MGF1",
                MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT));
        byte[] cipherBytes = cipher.doFinal(plainText.getBytes("UTF-8"));
        return Base64.encodeToString(cipherBytes, Base64.NO_WRAP);
    }

    private String getKeyAlias() {
        return MAGIC + "_" + mUamId;
    }

    private String getNonce() {
        byte[] newNonce = new byte[ NONCE_SIZE_BYTE ];
        mSecureRandom.nextBytes(newNonce);
        String nonceString = Base64.encodeToString(newNonce, Base64.URL_SAFE);
        mValidNonces.add(newNonce);
        if (mValidNonces.size() == MAX_VALID_NONCE) { // valid nonce lifetime is 30 seconds
            mValidNonces.remove(0); // remove oldest one
        }

        return nonceString;
    }

    private void setupSslContext() {
        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            keyStore.setCertificateEntry("ca", loadCert());

            // create TrustManager
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(keyStore);

            // create SSLContext
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, tmf.getTrustManagers(), null);
            mSslSocketFactory = sslContext.getSocketFactory();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private Certificate loadCert() throws CertificateException {
        // Note. change this to read check-in handler msg
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        InputStream caInput = null;
        if ("UAM1".equals(mUamId)) {
            caInput = getResources().openRawResource(R.raw.apm_uam1_cert);
        }
        if ("UAM2".equals(mUamId)) {
            caInput = getResources().openRawResource(R.raw.apm_uam2_cert);
        }
        return cf.generateCertificate(caInput);
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    private void activityLog(String msg) {
        Intent intent = new Intent(MainActivity.ACTIVITY_LOG);
        intent.putExtra(MainActivity.ACTIVITY_LOG, msg);
        sendBroadcast(intent);
    }
}
