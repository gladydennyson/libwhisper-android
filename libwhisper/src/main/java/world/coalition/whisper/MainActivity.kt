package world.coalition.whisper

import android.Manifest
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.content.Context
import android.content.DialogInterface
import android.content.Intent
import android.location.LocationManager
import android.os.Bundle
import android.provider.Settings
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import world.coalition.whisper.agathe.android.BluetoothLE
import world.coalition.whisper.agathe.android.BluetoothUtil


class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val context: Context = applicationContext

        if (!BluetoothUtil.checkBLEPermission(context)) {
            getBLEPermission()
        }

        Whisper.instance().start(context)

    }

    override fun onStart() {
        super.onStart()

    }

    fun getBLEPermission() {
        // request permission
        ActivityCompat.requestPermissions(
            this@MainActivity,
            arrayOf<String>(
                Manifest.permission.ACCESS_FINE_LOCATION,
                Manifest.permission.ACCESS_COARSE_LOCATION,
                Manifest.permission.BLUETOOTH
            )
            ,
            1);
    }

}
