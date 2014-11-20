/*****************************************************************************
 *
 * File:    Fwknop.java
 *
 * Purpose: A JNI wrapper for Damien Stuart's implementation of fwknop client
 *
 *  Fwknop is developed primarily by the people listed in the file 'AUTHORS'.
 *  Copyright (C) 2009-2014 fwknop developers and contributors. For a full
 *  list of contributors, see the file 'CREDITS'.
 *
 *  License (GNU General Public License):
 *
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU General Public License for more details.
 *
 *     You should have received a copy of the GNU General Public License
 *     along with this program; if not, write to the Free Software
 *     Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 *     USA
 *
 *****************************************************************************
 */
package com.max2idea.android.fwknop;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.content.ComponentName;
import android.content.Context;
import android.widget.TextView;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.res.AssetManager;
import android.os.AsyncTask;
import android.os.Handler;
import android.os.Message;
import android.preference.PreferenceManager;
import android.util.AttributeSet;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.ArrayAdapter;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.Toast;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.URL;
import java.net.URL;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.http.HttpConnection;

public class Fwknop extends Activity {

    public View parent;
    public TextView mOutput;
    private boolean startApp = true;
    public Activity activity = this;

//    Generic Dialog box
    public static void UIAlert(String title, String body, Activity activity) {
        AlertDialog ad;
        ad = new AlertDialog.Builder(activity).create();
        ad.setTitle(title);
        ad.setMessage(body);
        ad.setButton("OK", new DialogInterface.OnClickListener() {

            public void onClick(DialogInterface dialog, int which) {
                return;
            }
        });
        ad.show();
    }
    private String output;
    private Spinner mAllowip;
    private EditText mPasswd;
    private EditText mHmac;
    private EditText mDestip;
    private EditText mTCPAccessPorts;
    private EditText mUDPAccessPorts;
    private EditText mFwTimeout;
    private ImageButton mUnlock;
    private String access_str;
    private String allowip_str;
    private String passwd_str;
    private String hmac_str;
    private String destip_str;
    private String fw_timeout_str;
    private CheckBox mCheck;
    private String externalIP = "";
    private String localIP = "";
    private int IPS_RESOLVED = 1000;
    private int LOCALIP_NOTRESOLVED = 1001;
    private int EXTIP_NOTRESOLVED = 1002;
    private int SPA_SENT = 1003;

    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        //Installer
        installNativeLibs();

        //Get IPs of client
        progDialog = ProgressDialog.show(activity, "Resolving External IP", "Please wait...", true);
        IPResolver p = new IPResolver();
        p.execute();

        //Setup UI
        this.setContentView(R.layout.main);
        this.setupWidgets();

    }

    public void sendSPA() {
        startSPASend();
    }

//    Intent for ConnectBot kickoff
    private void startApp() {
        Intent i = new Intent(Intent.ACTION_RUN);
        i.setComponent(new ComponentName("org.connectbot", "org.connectbot.HostListActivity"));
        PackageManager p = this.getPackageManager();
        List list = p.queryIntentActivities(i, p.COMPONENT_ENABLED_STATE_DEFAULT);
        if (list.isEmpty()) {
            Log.v("SPA", "ConnectBot is not installed");
            Toast.makeText(this, "ConnectBot is not installed", Toast.LENGTH_LONG).show();
        } else {
            Log.v("SPA", "Starting connectBot");
            Toast.makeText(this, "Starting ConnectBot", Toast.LENGTH_LONG);
            startActivity(i);
        }
    }
    // Define the Handler that receives messages from the thread and update the progress
    public Handler handler = new Handler() {

        @Override
        public synchronized void handleMessage(Message msg) {
            Bundle b = msg.getData();
            Integer messageType = (Integer) b.get("message_type");
            if (messageType != null && messageType == IPS_RESOLVED) {
                progDialog.dismiss();
            } else if (messageType != null && messageType == EXTIP_NOTRESOLVED) {
                progDialog.dismiss();
                UIAlert("Error", "Could not resolve your external IP. This means that "
                        + "you're not connected to the internet or ifconfig.me "
                        + "is not be accesible right now", activity);
            } else if (messageType != null && messageType == LOCALIP_NOTRESOLVED) {
                progDialog.dismiss();
                UIAlert("Error", "Could not find any IP, makes sure you have an internet connection", activity);
            } else if (messageType != null && messageType == SPA_SENT) {
                Toast.makeText(activity, output, Toast.LENGTH_LONG).show();
            }

        }
    };

//    Get Local and External IPs
    private void getClientIPs() {
        localIP = getLocalIpAddress();
        externalIP = getExternalIP();
        sendHandlerMessage(handler, IPS_RESOLVED);
    }

//    Generic Message to update UI
    public static void sendHandlerMessage(Handler handler, int message_type, String message_var, String message_value) {
        Message msg1 = handler.obtainMessage();
        Bundle b = new Bundle();
        b.putInt("message_type", message_type);
        b.putString(message_var, message_value);
        msg1.setData(b);
        handler.sendMessage(msg1);
    }

//    Sets  member variables to IPs
    private void setIPs() {

        String[] arraySpinner = {"Source IP", "", ""};
        if (this.localIP != null && !this.localIP.equals("")) {
            Log.v("setter", this.localIP);
            arraySpinner[1] = this.localIP;
        } else {
            sendHandlerMessage(handler, LOCALIP_NOTRESOLVED);
            return;
        }

        if (this.externalIP != null && !this.externalIP.equals("")) {
            arraySpinner[2] = this.externalIP;
            Log.v("setter", this.externalIP);
        } else {
            sendHandlerMessage(handler, EXTIP_NOTRESOLVED);
        }

        ArrayAdapter adapter1 = new ArrayAdapter(this, android.R.layout.simple_spinner_item, arraySpinner);
        adapter1.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        this.mAllowip.setAdapter(adapter1);
        this.mAllowip.invalidate();
    }
    private ProgressDialog progDialog;

//    Async task just in case things take a long time
    private class IPResolver extends AsyncTask<Void, Void, Void> {

        @Override
        protected Void doInBackground(Void... arg0) {
            getClientIPs();
            return null;
        }

        @Override
        protected void onPostExecute(Void test) {
            setIPs();
        }
    }

//    Another Generic Messanger
    public static void sendHandlerMessage(Handler handler, int message_type) {
        Message msg1 = handler.obtainMessage();
        Bundle b = new Bundle();
        b.putInt("message_type", message_type);
        msg1.setData(b);
        handler.sendMessage(msg1);
    }

    public class AutoScrollView extends ScrollView {

        public AutoScrollView(Context context, AttributeSet attrs) {
            super(context, attrs);
        }

        public AutoScrollView(Context context) {
            super(context);
        }
    }
    public AutoScrollView mLyricsScroll;

//   Main event function
//    Retrives values from saved preferences
    private void onStartButton() {

        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        SharedPreferences.Editor edit = prefs.edit();
//
        this.access_str = "";
        if (this.mTCPAccessPorts != null) {
            if(!this.mTCPAccessPorts.getText().toString().equals("")){
                String[] ports = this.mTCPAccessPorts.getText().toString().split(",");
                for(int i = 0; i < ports.length; i++){
                    try {
                        int port = Integer.parseInt(ports[i]);
                        if(i > 0)
                            this.access_str = this.access_str + ",";
                        this.access_str = this.access_str + "tcp/" + port;
                    } catch (Exception e) {
                        this.UIAlert("Input error", ports[i] + " is not a valid port number", this);
                        return;
                    }
                }
            }
            edit.putString("tcpAccessPorts_str", mTCPAccessPorts.getText().toString());
        }

        if (this.mUDPAccessPorts != null) {
            if(!this.mUDPAccessPorts.getText().toString().equals("")){
                String[] ports = this.mUDPAccessPorts.getText().toString().split(",");
                for(int i = 0; i < ports.length; i++){
                    try {
                        int port = Integer.parseInt(ports[i]);
                        if(this.access_str != null && !this.access_str.equals(""))
                            this.access_str = this.access_str + ",";
                        this.access_str = this.access_str + "udp/" + port;
                    } catch (Exception e) {
                        this.UIAlert("Input error", ports[i] + " is not a valid port number", this);
                        return;
                    }
                }
            }
            edit.putString("udpAccessPorts_str", mUDPAccessPorts.getText().toString());
        }

        if(this.access_str.equals("")){
            this.UIAlert("Input error", "Please enter a TCP or UDP port", this);
            return;
        }
        
        if (this.mAllowip != null && this.mAllowip.getSelectedItem() != null && !this.mAllowip.getSelectedItem().toString().trim().equals("")) {
            if(mAllowip.getSelectedItem().toString().trim().equals("Source IP")) {
                this.allowip_str = "0.0.0.0";
            } else {
                this.allowip_str = mAllowip.getSelectedItem().toString().trim();
            }

            edit.putString("allowip_str", this.allowip_str);
        } else {
            UIAlert("Input error", "Please use a valid IP address", this);
            return;
        }

        if (this.mPasswd != null && !this.mPasswd.getText().toString().trim().equals("")) {
            this.passwd_str = mPasswd.getText().toString();
            edit.putString("passwd_str", mPasswd.getText().toString());
        } else {
            this.UIAlert("Input error", "Please enter a key", this);
            return;
        }

        if (this.mHmac != null && !this.mHmac.getText().toString().trim().equals("")) {
            this.hmac_str = mHmac.getText().toString();
            edit.putString("hmac_str", mHmac.getText().toString());
        } else {
            // the HMAC is currently optional
            this.hmac_str = "";
            edit.putString("hmac_str", this.hmac_str);
        }

        if (this.mDestip != null && !this.mDestip.getText().toString().trim().equals("")) {
            this.destip_str = mDestip.getText().toString();
            edit.putString("destip_str", mDestip.getText().toString());
        } else {
            this.UIAlert("Input error", "Please enter a valid Server address", this);
            return;
        }

        if (this.mFwTimeout != null) {
            int fw_timeout;
            try {
                Integer.parseInt(this.mFwTimeout.getText().toString());
            } catch (Exception e) {
                this.UIAlert("Input error", "Please enter a valid timeout value", this);
                return;
            }
            this.fw_timeout_str = mFwTimeout.getText().toString();
            edit.putString("fw_timeout_str", mFwTimeout.getText().toString());
        }

        if (this.mCheck != null && this.mCheck.isChecked()) {
            this.startApp = true;
        } else {
            this.startApp = false;
        }
        edit.putBoolean("app_start", startApp);
        edit.commit();

        this.sendSPA();
    }

//    Setting up the UI
    public void setupWidgets() {

        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        this.mTCPAccessPorts = (EditText) findViewById(R.id.tcpAccessPorts);
        this.mTCPAccessPorts.setText(prefs.getString("tcpAccessPorts_str", "22"));
        this.mUDPAccessPorts = (EditText) findViewById(R.id.udpAccessPorts);
        this.mUDPAccessPorts.setText(prefs.getString("udpAccessPorts_str", null));

        this.mAllowip = (Spinner) findViewById(R.id.allowip);

        this.mDestip = (EditText) findViewById(R.id.destIP);
        this.mDestip.setText(prefs.getString("destip_str", ""));

        this.mFwTimeout = (EditText) findViewById(R.id.fwTimeout);
        this.mFwTimeout.setText(prefs.getString("fw_timeout_str", "60"));

        this.mCheck = (CheckBox) findViewById(R.id.startAppCheck);
        this.mCheck.setChecked(prefs.getBoolean("app_start", false));

        this.mPasswd = (EditText) findViewById(R.id.passwd);
        this.mPasswd.setText(prefs.getString("passwd_str", ""));

        this.mOutput = (TextView) findViewById(R.id.output);

        this.mHmac   = (EditText) findViewById(R.id.hmac);
        this.mHmac.setText(prefs.getString("hmac_str", ""));

        mUnlock = (ImageButton) findViewById(R.id.unlock);
        mUnlock.setOnClickListener(new OnClickListener() {

            public void onClick(View view) {
                onStartButton();

            }
        });


    }

    public native String sendSPAPacket();

    @Override
    public void onStop() {
        super.onStop();
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
    }

    private void installNativeLibs() {
        //Installation of C libs during apk installation, manual installation is not needed anymore
//        installNativeLib("libfwknop.so", "/data/data/com.max2idea.android.fwknop/lib");

        //Load the C library
        loadNativeLib("libfwknop.so", "/data/data/com.max2idea.android.fwknop/lib");
    }

    //This is not needed anymore, don't use
    private void installNativeLib(String lib, String destDir) {
        if (true) {
            try {
                String libLocation = destDir + "/" + lib;
                AssetManager am = this.getAssets();
                InputStream is = am.open(lib);
                OutputStream os = new FileOutputStream(libLocation);
                byte[] buf = new byte[8092];
                int n;
                while ((n = is.read(buf)) > 0) {
                    os.write(buf, 0, n);
                }
                os.close();
                is.close();
            } catch (Exception ex) {
                Log.e("JNIExample", "failed to install native library: " + ex);
            }
        }

    }

//    Load the shared lib
    private void loadNativeLib(String lib, String destDir) {
        if (true) {
            String libLocation = destDir + "/" + lib;
            try {
                System.load(libLocation);
            } catch (Exception ex) {
                Log.e("JNIExample", "failed to load native library: " + ex);
            }
        }

    }

//    Start calling the JNI interface
    public synchronized void startSPASend() {
        output = sendSPAPacket();
        sendHandlerMessage(handler, SPA_SENT);
        if (startApp) {
            startApp();
        }
    }

//    Not needed
    public static String sendHttpGet(String url) {
        HttpConnection hcon = null;
        DataInputStream dis = null;
        java.net.URL URL = null;
        try {
            URL = new java.net.URL(url);
        } catch (MalformedURLException ex) {
            Logger.getLogger(Fwknop.class.getName()).log(Level.SEVERE, null, ex);
        }
        StringBuffer responseMessage = new StringBuffer();

        try {
            // obtain a DataInputStream from the HttpConnection
            dis = new DataInputStream(URL.openStream());

            // retrieve the response from the server
            int ch;
            while ((ch = dis.read()) != -1) {
                responseMessage.append((char) ch);
            }//end while ( ( ch = dis.read() ) != -1 )
        } catch (Exception e) {
            e.printStackTrace();
            responseMessage.append(e.getMessage());
        } finally {
            try {
                if (hcon != null) {
                    hcon.close();
                }
                if (dis != null) {
                    dis.close();
                }
            } catch (IOException ioe) {
                ioe.printStackTrace();
            }//end try/catch
        }//end try/catch/finally
        return responseMessage.toString();
    }//end sendHttpGet( String )

//    Get the external IP from ifconfig.me
//    Other sites with similar services are whatismyip.com, whatismyip.org
    public static String getExternalIP() {
        URL Url = null;
        HttpURLConnection Conn = null;
        InputStream InStream = null;
        InputStreamReader Isr = null;
        String extIP = "";

        try {
            Url = new java.net.URL("http://ifconfig.me/ip");
            Conn = (HttpURLConnection) Url.openConnection();
            InStream = Conn.getInputStream();
            Isr = new java.io.InputStreamReader(InStream);
            BufferedReader Br = new java.io.BufferedReader(Isr);
            extIP = Br.readLine();
            Log.v("External IP", "Your external IP address is " + extIP);
        } catch (Exception ex) {
            Logger.getLogger(Fwknop.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
//            Isr.close();
//            InStream.close();
            Conn.disconnect();
        }
        return extIP;

    }

//    This is easier: traverse the interfaces and get the local IPs
    public static String getLocalIpAddress() {
        try {
            for (Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces(); en.hasMoreElements();) {
                NetworkInterface intf = en.nextElement();
                for (Enumeration<InetAddress> enumIpAddr = intf.getInetAddresses(); enumIpAddr.hasMoreElements();) {
                    InetAddress inetAddress = enumIpAddr.nextElement();
                    if (!inetAddress.isLoopbackAddress()) {
                        Log.v("Internal ip", inetAddress.getHostAddress().toString());
                        return inetAddress.getHostAddress().toString();
                    }
                }
            }
        } catch (SocketException ex) {
            Log.e("Internal IP", ex.toString());
        }
        return null;
    }
}
