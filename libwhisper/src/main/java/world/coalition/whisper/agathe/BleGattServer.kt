/*
 * This file is part of the Whisper Protocol distributed at https://github.com/NodleCode/whisper-tracing-android
 * Copyright (C) 2020  Coalition Network
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package world.coalition.whisper.agathe

import android.bluetooth.*
import android.content.Context
import android.util.Base64
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.protobuf.ProtoBuf
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import world.coalition.whisper.Whisper
import world.coalition.whisper.WhisperCore
import world.coalition.whisper.agathe.android.BluetoothUtil
import world.coalition.whisper.database.BleConnectEvent
import world.coalition.whisper.id.ECUtil
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import kotlin.math.abs

/**
 * @author Lucien Loiseau on 27/03/20.
 */
class BleGattServer(val core: WhisperCore) {

    class DeviceState {
        var readRequestResponseBuffer: ByteArray? = null
        var writeRequestBuffer: ByteArray? = null
    }


    private val log: Logger = LoggerFactory.getLogger(Whisper::class.java)
    private var mGattServer: BluetoothGattServer? = null
    private var mGattServerCallback: BluetoothGattServerCallback? = null

    //we need to store public key from alice but multiple requests will overwrite this value


    private var clientPubkey: ByteArray?= null
    private var symmetricKey: ByteArray?= null
    private var encryptedEncounter: ByteArray?= null

    /**
     * For each node that connect, we follow the following steps:
     *
     * step0... waiting for connection
     * step1... waiting for receiving a read request
     *          -> replying with pubkey
     * step2... waiting for receiving a write request (peer's pubkey)
     */
    private fun getGattServerCallback(context: Context): BluetoothGattServerCallback {
        return mGattServerCallback ?: let {
            mGattServerCallback = object : BluetoothGattServerCallback() {

                // FIXME add mutex everywhere
                val state = HashMap<BluetoothDevice, DeviceState>()
                private fun getState(device: BluetoothDevice): DeviceState {
                    return state[device] ?: let {
                        log.warn("device ${device.address} hasn't been properly initialized")
                        state[device] = DeviceState()
                        state[device]!!
                    }
                }

                override fun onConnectionStateChange(
                    device: BluetoothDevice?,
                    status: Int,
                    newState: Int
                ) {
                    super.onConnectionStateChange(device, status, newState)
                    if (newState == BluetoothProfile.STATE_CONNECTED && device != null) {
                        log.warn("device ${device.address} < connected")
                        state[device] = DeviceState()
                    }
                    if (newState == BluetoothProfile.STATE_DISCONNECTED && device != null) {
                        log.warn("device ${device.address} < disconnected")
                        state.remove(device)
                    }
                }
                // called on server, alice sends read req

                override fun onCharacteristicReadRequest(
                    device: BluetoothDevice,
                    requestId: Int,
                    offset: Int,
                    characteristic: BluetoothGattCharacteristic
                ) {
                    super.onCharacteristicReadRequest(device, requestId, offset, characteristic)
                    log.warn("device ${device.address} < read request, replying with pubkey")
                    return success(
                        device,
                        requestId,
                        offset,
                        response(device).sliceArray(offset until response(device).size)
                    )
                }

                private fun response(device: BluetoothDevice): ByteArray {

                    // to check if its the second read request
                    if (clientPubkey!=null){

                        val prvKey = core.getKeyPair(context).private
                        val privateKey = ECUtil.savePrivateKey(prvKey)
                        symmetricKey = ECUtil.computeSymmetricKey(privateKey,clientPubkey!!)

                        val encounter = core.getEncounter()

                        // create key used for cipher
                        val keySpec = SecretKeySpec(symmetricKey, "AES") // 4
                        // create cipher object for encrypting

                        val cipher: Cipher = Cipher.getInstance("AES/NoPadding")
                        // initialize it
                        // perform encryption on location
                        cipher.init(Cipher.ENCRYPT_MODE, keySpec)
                        // perform encryption
                        encryptedEncounter  = cipher.doFinal(encounter)

                    }

                    // check if public key from alice is not null
                    // if not null compute symmetric key and use it to encrypt location and time
                    // if null location will be null within payload
                    return getState(device).readRequestResponseBuffer ?: let {
                        val payload = ProtoBuf.dump(
                            AgattPayload.serializer(),
                            AgattPayload(
                                1,
                                core.whisperConfig.organizationCode,
                                ECUtil.savePublicKey(core.getPublicKey(context)),
                                //send encounter (location || time), send bob's encounter
                                encryptedEncounter
                            )
                        )
                        getState(device).readRequestResponseBuffer =
                            byteArrayOf(0x01, payload.size.toByte()) + payload
                        getState(device).readRequestResponseBuffer!!
                    }
                }

                override fun onCharacteristicWriteRequest(
                    device: BluetoothDevice?,
                    requestId: Int,
                    characteristic: BluetoothGattCharacteristic?,
                    preparedWrite: Boolean,
                    responseNeeded: Boolean,
                    offset: Int,
                    value: ByteArray?
                ) {
                    if (device == null) return
                    if (value == null) return fail(device, requestId)
                    if (value.size < 2) return fail(device, requestId)

                    log.info("device ${device.address} < write request - frame: size=${value.size} offset=${offset}")

                    getState(device).writeRequestBuffer =
                        getState(device).writeRequestBuffer?.plus(value) ?: value
                    val cmd = getState(device).writeRequestBuffer!![0].toInt()
                    val expectedPayloadSize = getState(device).writeRequestBuffer!![1].toInt()

                    if (getState(device).writeRequestBuffer!!.size < expectedPayloadSize + 2) {
                        // we need more data
                        return success(device, requestId, offset, value)
                    }

                    log.info("device ${device.address} < write request - recv full payload")
                    when (cmd) {
                        0x01 -> {
                            // alice ---pubkey---> bob, get alice's public key
                            try {
                                val payload = ProtoBuf.load(
                                    AgattPayload.serializer(),
                                    getState(device).writeRequestBuffer!!.sliceArray(2..1 + expectedPayloadSize)
                                )

                                log.debug("device: ${device.address} < write request - whisper pubkey ${Base64.encodeToString(payload.pubKey, Base64.NO_WRAP)}")
                                runBlocking {
                                    core.channel?.send(
                                        BleConnectEvent(
                                            false,
                                            device.address,
                                            System.currentTimeMillis(),
                                            payload.organization,
                                            1,
                                            payload.pubKey,
                                            -1
                                        )
                                    )
                                }

                                if (symmetricKey==null){
                                    clientPubkey = payload.pubKey
                                }

                                else {
                                    // get encounter from payload
                                    // get alice's encounter
                                    val encodedEncounter = payload.encounter
                                    // create key used for cipher
                                    val keySpec = SecretKeySpec(symmetricKey, "AES")
                                    // create cipher object for decrypting
                                    val cipher = Cipher.getInstance("AES/NoPadding")
                                    // initialize it
                                    cipher.init(Cipher.DECRYPT_MODE, keySpec)
                                    // perform decryption
                                    val peerEncounter = cipher.doFinal(encodedEncounter)
                                    // get this node's encounter
                                    val encounter = core.getEncounter()
                                    // separate location and time
                                    // perform proximity check
                                    val time = encounter[0].toLong() // most significant byte is time
                                    val peerTime = peerEncounter[0].toLong()
                                    val locationAsByteArray = encounter.sliceArray(1 until encounter.size)
                                    val peerLocationAsByteArray = peerEncounter.sliceArray(1 until encounter.size)
                                    // perform proximity check if times are "close" (2 minutes)
                                    if (abs(time - peerTime) <= 120000) {
                                         if (core.checkProximity(locationAsByteArray,peerLocationAsByteArray)){
                                             //store public key of peer
                                         }
                                    }
                                }

                            } catch (e: Exception) {
                                log.debug("device: ${device.address} < write request - parser failed! $e")
                                return fail(device, requestId)
                            }
                            // preemptive cleaning
                            state.remove(device)
                            return success(device, requestId, offset, value)
                        }
                        else -> {
                            log.info("device ${device.address} < frame type unknown")
                            // preemptive cleaning
                            state.remove(device)
                            return fail(device, requestId)
                        }
                    }
                }


                fun fail(device: BluetoothDevice, requestId: Int) {
                    mGattServer?.sendResponse(
                        device,
                        requestId,
                        BluetoothGatt.GATT_FAILURE,
                        0,
                        null
                    )
                }

                fun success(
                    device: BluetoothDevice,
                    requestId: Int,
                    offset: Int,
                    value: ByteArray
                ) {
                    mGattServer?.sendResponse(
                        device,
                        requestId,
                        BluetoothGatt.GATT_SUCCESS,
                        offset,
                        value
                    )
                }
            }

            mGattServerCallback!!
        }
    }




    fun checkGATTServer(context: Context) {
        if (!BluetoothUtil.checkBluetoothOn()) return
        if (!BluetoothUtil.checkBluetoothLE(context)) return

        if (mGattServer == null) {
            val whisperGattService = BluetoothGattService(
                core.whisperConfig.whisperServiceUUID,
                BluetoothGattService.SERVICE_TYPE_PRIMARY
            )

            val whisperGattCharacteristic = BluetoothGattCharacteristic(
                core.whisperConfig.whisperV3CharacteristicUUID,
                BluetoothGattCharacteristic.PROPERTY_READ or BluetoothGattCharacteristic.PROPERTY_WRITE or BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT,
                BluetoothGattCharacteristic.PERMISSION_READ or BluetoothGattCharacteristic.PERMISSION_WRITE
            )

            whisperGattService.addCharacteristic(whisperGattCharacteristic)

            mGattServer = (context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager?)
                ?.openGattServer(context, getGattServerCallback(context))
            mGattServer?.addService(whisperGattService)
        }
    }
}