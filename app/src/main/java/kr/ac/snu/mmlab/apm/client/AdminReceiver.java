package kr.ac.snu.mmlab.apm.client;

import android.app.admin.DeviceAdminReceiver;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

public class AdminReceiver extends DeviceAdminReceiver {

    static final String LOG_TAG = "APM_RECEIVER";

    @Override
    public void onProfileProvisioningComplete(Context context, Intent intent) {
        // enable admin
        DevicePolicyManager dpm =
                (DevicePolicyManager) context.getSystemService(Context.DEVICE_POLICY_SERVICE);
        ComponentName cn = getComponentName(context);
        dpm.setProfileName(cn, "APM device admin");
    }

    public static ComponentName getComponentName(Context context) {
        return new ComponentName(context.getApplicationContext(), AdminReceiver.class);
    }

    @Override
    public void onReceive(Context context, Intent intent) {
        Log.i(LOG_TAG, "onReceive: " + intent.getAction());
        switch (intent.getAction()) {
            case(Intent.ACTION_BOOT_COMPLETED):
                // TODO check admin and start service if needed
                break;
        }
    }
}
