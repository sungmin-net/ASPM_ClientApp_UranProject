package kr.ac.snu.mmlab.apm.client;

import android.app.Activity;
import android.app.admin.DevicePolicyManager;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.Bundle;
import android.text.method.ScrollingMovementMethod;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import java.text.SimpleDateFormat;
import java.util.Date;

import static kr.ac.snu.mmlab.apm.client.ApmEnums.Command;

public class MainActivity extends Activity {

    final String LOG_TAG = "APM_MAIN";

    public static final String ACTIVITY_LOG = "ACTIVITY_LOG";
    public static final SimpleDateFormat TIME_FORMAT = new SimpleDateFormat("yy.MM.dd HH:mm:ss");

    DevicePolicyManager mDpm;
    ConnectivityManager mCm;
    
    TextView mActivityLog;
    TextView mAdminState;

    Button mBtnRemoveAdmin;
    Button mBtnClearLog;
    Button mBtnTestTls;
    Button mBtnAllowCamara;
    Button mBtnDisallowCamara;
    Button mBtnMuteVolume;
    Button mBtnUnmuteVolume;
    Button mBtnStartApm;
    Button mBtnStopApm;

    EditText mUserId;
    EditText mUamId;
    EditText mServerIp;
    EditText mServerPort;

    String mPackageName;

    Intent mServiceIntent;
    IntentFilter mIntentFilter;
    ComponentName mComponentName;

    boolean mIsPolling = false;

    BroadcastReceiver mReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            switch(action) {
                case DevicePolicyManager.ACTION_DEVICE_OWNER_CHANGED :
                    refreshUI();
                    break;

                case ACTIVITY_LOG:
                    activityLog(intent.getStringExtra(ACTIVITY_LOG));
                    break;

                default:
                    throw new IllegalStateException("Unexpected value: " + intent.getAction());
            }
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        mDpm = (DevicePolicyManager) getSystemService(Context.DEVICE_POLICY_SERVICE);
        mCm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
        mPackageName = getApplicationContext().getPackageName();
        mComponentName = AdminReceiver.getComponentName(getApplicationContext());
        mServiceIntent = new Intent(getApplicationContext(), AdminService.class);

        mIntentFilter = new IntentFilter();
        mIntentFilter.addAction(mDpm.ACTION_DEVICE_OWNER_CHANGED);
        mIntentFilter.addAction(ACTIVITY_LOG);

        mAdminState = findViewById(R.id.txtAdminState);
        mUserId = findViewById(R.id.etUserId);
        mUamId = findViewById(R.id.etUamId);
        mServerIp = findViewById(R.id.etServerIp);
        mServerPort = findViewById(R.id.etServerPort);

        mBtnRemoveAdmin = findViewById(R.id.btnRemoveAdmin);
        mBtnRemoveAdmin.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                mDpm.clearDeviceOwnerApp(mPackageName);
                activityLog("APM admin cleared.");
                refreshUI();
            }
        });

        mBtnClearLog = findViewById(R.id.btnClearLog);
        mBtnClearLog.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                mActivityLog.setText("");
                activityLog("Activity logger cleared.\n");
            }
        });

        mBtnTestTls = findViewById(R.id.btnTestTls);
        mBtnTestTls.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                mServiceIntent.setAction(Command.Hello.toString());
                appendCmdInfo();
                startService(mServiceIntent);
            }
        });

        mBtnStartApm = findViewById(R.id.btnStartApm);
        mBtnStartApm.setOnClickListener(new View.OnClickListener(){
            @Override
            public void onClick(View view) {
                mServiceIntent.setAction(Command.Start.toString());
                appendCmdInfo();
                startService(mServiceIntent);
                mIsPolling = true;
                refreshUI();
            }
        });

        mBtnStopApm = findViewById(R.id.btnStopApm);
        mBtnStopApm.setOnClickListener(new View.OnClickListener(){
            @Override
            public void onClick(View view) {
                mServiceIntent.setAction(Command.Stop.toString());
                appendCmdInfo();
                startService(mServiceIntent);
                mIsPolling = false;
                refreshUI();
            }
        });

        mBtnDisallowCamara = findViewById(R.id.btnDisallowCamera);
        mBtnDisallowCamara.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                mDpm.setCameraDisabled(mComponentName, true);
                activityLog("setCameraDisabled: true");
                refreshUI();
            }
        });

        mBtnAllowCamara = findViewById(R.id.btnAllowCamera);
        mBtnAllowCamara.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                mDpm.setCameraDisabled(mComponentName, false);
                activityLog("setCameraDisabled: false");
                refreshUI();
            }
        });

        mBtnMuteVolume = findViewById(R.id.btnMuteVolume);
        mBtnMuteVolume.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                mDpm.setMasterVolumeMuted(mComponentName, true);
                activityLog("setMasterVolumeMuted: true");
                refreshUI();
            }
        });

        mBtnUnmuteVolume = findViewById(R.id.btnUnmuteVolume);
        mBtnUnmuteVolume.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                mDpm.setMasterVolumeMuted(mComponentName, false);
                activityLog("setMasterVolumeMuted: false");
                refreshUI();
            }
        });

        enableActivityLog();
    }


    private void appendCmdInfo() {
        mServiceIntent.putExtra(AdminService.EXTRA_USER_ID, getUserId());
        mServiceIntent.putExtra(AdminService.EXTRA_UAM_ID, getUamId());
        mServiceIntent.putExtra(AdminService.EXTRA_SERVER_IP, getServerIp());
        mServiceIntent.putExtra(AdminService.EXTRA_SERVER_PORT, getServerPort());
    }

    @Override
    protected void onResume() {
        super.onResume();
        refreshUI();
        registerReceiver(mReceiver, mIntentFilter);
    }

    @Override
    protected void onPause() {
        super.onPause();
        unregisterReceiver(mReceiver);
    }

    private void refreshUI() {
        boolean isDeviceOwner = mDpm.isDeviceOwnerApp(mPackageName);
        mBtnRemoveAdmin.setEnabled(isDeviceOwner);
        if (isDeviceOwner) {
            mAdminState.setText("○ APM device admin is enabled");

            boolean isCameraDisabled = mDpm.getCameraDisabled(mComponentName);
            mBtnAllowCamara.setEnabled(isCameraDisabled);
            mBtnDisallowCamara.setEnabled(!isCameraDisabled);

            boolean isMasterVolumeMuted = mDpm.isMasterVolumeMuted(mComponentName);
            mBtnMuteVolume.setEnabled(!isMasterVolumeMuted);
            mBtnUnmuteVolume.setEnabled(isMasterVolumeMuted);

        } else {
            mAdminState.setText("○ APM device admin is NOT enabled.\n" +
                    "To enable, allow USB debugging and set below ADB command.\n" +
                    "\"adb shell dpm set-device-owner kr.ac.snu.mmlab.apm.client/.AdminReceiver\"");

            mBtnAllowCamara.setEnabled(false);
            mBtnDisallowCamara.setEnabled(false);
            mBtnMuteVolume.setEnabled(false);
            mBtnUnmuteVolume.setEnabled(false);
        }

        NetworkInfo activeNetwork = mCm.getActiveNetworkInfo();
        boolean isConnected = activeNetwork != null && activeNetwork.isConnected();
        mBtnTestTls.setEnabled(isConnected);

        mBtnStartApm.setEnabled((isDeviceOwner && isConnected && !mIsPolling));
        mBtnStopApm.setEnabled((isDeviceOwner && isConnected && mIsPolling));
    }

    private void enableActivityLog() {
        mActivityLog = findViewById(R.id.activityLog);
        mActivityLog.setMovementMethod(new ScrollingMovementMethod());
        mActivityLog.setText("[" + getTimeStamp() + "] Activity logger started.\n");
    }

    protected void activityLog(String msg) {
        mActivityLog.append("[" + getTimeStamp() + "] " + msg + "\n");
        Log.i(LOG_TAG, "activityLog(): " + msg);
    }

    private String getTimeStamp() {
        return TIME_FORMAT.format(new Date());
    }

    protected String getServerIp() {
        // Note. will be deprecated if check-in handler implemented
        return mServerIp.getText().toString();
    }

    protected String getUamId() {
        // Note. will be deprecated if check-in handler implemented
        return mUamId.getText().toString();
    }

    protected String getUserId() {
        // Note. will be deprecated if UID logic implemented(e.g., UAM ticket number)
        return mUserId.getText().toString();
    }

    protected String getServerPort() {
        // Note. will be deprecated if check-in handler implemented
        return mServerPort.getText().toString();
    }
}
