package house.heka.themis;

import android.content.Context;

import com.google.android.gms.iid.InstanceID;

public class Device {
    public String getDeviceId(Context context) {
        return InstanceID.getInstance(context).getId();
    }
}
