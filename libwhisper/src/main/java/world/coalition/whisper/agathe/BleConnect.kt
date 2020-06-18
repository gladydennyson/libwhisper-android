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
import android.bluetooth.BluetoothGatt.GATT_SUCCESS
import android.content.Context
import android.util.Base64
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.sync.Mutex
import kotlinx.serialization.protobuf.ProtoBuf
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import world.coalition.whisper.Whisper
import world.coalition.whisper.WhisperCore
import world.coalition.whisper.database.BleConnectEvent
import world.coalition.whisper.id.ECUtil
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import kotlin.math.abs

/**
 * @author Lucien Loiseau on 30/03/20.
 */
class BleConnect(val core: WhisperCore) {

    private val log: Logger = LoggerFactory.getLogger(Whisper::class.java)

    /**
     * connectAndReadPeerId, this is blocking!
     * @param context the Android application Context
     * @param device to connect to
     * @param upstream channel to send read id
     */
    suspend fun connectAndReadPeerId(
        context: Context,
        device: BluetoothDevice,
        rssi: Int,
        upstream: Channel<BleConnectEvent>
    ) {
        /**
         * They are 7 asynchronous STEPS that must be performed syncronously.
         * If any step fail, we immediately disconnect (except for increase MTU)
         *
         * 1 ..... connect
         * 2 ..... try to increase MTU size (may be refused)
         * 3 ..... discover services
         * 4 ..... read whisper characteristic (peer pubkey) bob sends pubkey g^b to alice
         * 5 ..... write characteristic (current pubkey) alice sends pubkey g^a to bob
         * 5a ..... compute symmetric key and encrypt  g^ab
         * 5b ..... read whisper characterstic (loaction and time) bob sends location and time to alice
         * 5c ..... write whisper characterstic (loaction and time) alice sends location and time to bob
         * 6 ..... disconnect
         * 7 .... release the mutex
         */
        val mutex = Mutex(true)

        /**
         * STEP 1 - we connect to the device
         */
        log.debug("device: ${device.address} > connecting..")
        device.connectGatt(context, false, object : BluetoothGattCallback() {
            var step = 1
            private var peerPublicKey: ByteArray? = null
            private var symmetricKey: ByteArray? = null

            private var mtu = 20 // step 2

            private fun step2(gatt: BluetoothGatt) {
                step = 2
                log.debug("device: ${device.address} > request MTU 20 ...")
                if (!gatt.requestMtu(80)) {
                    log.debug("device: ${device.address} < request MTU failed (ignored)")
                    step3(gatt)
                }
            }

            private fun step3(gatt: BluetoothGatt) {
                step = 3
                log.debug("device: ${device.address} > discover services ...")
                if (!gatt.discoverServices()) {
                    log.debug("device: ${device.address} < discovery failed")
                    step6(gatt)
                }
            }

            private fun step4(gatt: BluetoothGatt) {
                step = 4
                var characteristic = gatt.services
                    .lastOrNull { it.uuid == core.whisperConfig.whisperServiceUUID }
                    ?.getCharacteristic(core.whisperConfig.whisperV3CharacteristicUUID)

                if (characteristic != null) {
                    log.debug("device: ${device.address} > read characteristic ${characteristic.uuid} ...")
                    if (!gatt.readCharacteristic(characteristic)) {
                        log.debug("device: ${device.address} < read failed!")
                        // should we disconnect or move onto next step
                        step5(gatt)
                    }
                } else {
                    step6(gatt)
                }
            }

            var timeout: Job? = null // FIXME we should not have to rely on this
            private fun step5(gatt: BluetoothGatt) {
                step = 5
                val characteristic = gatt.services
                    ?.lastOrNull { it.uuid == core.whisperConfig.whisperServiceUUID }
                    ?.getCharacteristic(core.whisperConfig.whisperV3CharacteristicUUID)

                if (characteristic != null) {
                    // if symmetric key exists, do the following
                    var encryptedEncounter: ByteArray = ByteArray(0)
                    if (symmetricKey != null) {
                        // create encounter (location || time)
                        val encounter = core.getEncounter()
                        // create key used for cipher
                        val keySpec = SecretKeySpec(symmetricKey, "AES")
                        // create cipher object for encrypting
                        val cipher = javax.crypto.Cipher.getInstance("AES/NoPadding")
                        // initialize it
                        cipher.init(Cipher.ENCRYPT_MODE, keySpec)
                        // perform encryption
                        encryptedEncounter = cipher.doFinal(encounter)
                    }

                    val payload = ProtoBuf.dump(
                        AgattPayload.serializer(),
                        AgattPayload(
                            1,
                            core.whisperConfig.organizationCode,
                            ECUtil.savePublicKey(core.getPublicKey(context)),
                            //send encounter (location || time)
                            encryptedEncounter
                        )
                    )

                    // sending it over
                    characteristic.value = byteArrayOf(0x01, payload.size.toByte()) + payload
                    log.debug("device: ${device.address} > writing pubkey...")
                    if (gatt.writeCharacteristic(characteristic)) {
                        // FIXME if MTU is too small and multiple GATT packet must be sent
                        // sometimes the onCharacteristicWrite callback is not called even though
                        // all gatt packets are received on the peer.
                        // the following timer is to avoid waiting 30 sec for the timeout
                        timeout = GlobalScope.launch {
                            delay(5000)
                            if (isActive) {
                                log.debug("device: ${device.address} > //fixme// timeout fired!")
                                timeout = null
                                step6(gatt)
                            }
                        }
                        return
                    }
                }

                log.debug("device: ${device.address} > writing failed!")
                step6(gatt)
            }

            // computes symmetric key
            // call next step of protocol (bob sends encounter to alice)
            private fun step5a(gatt: BluetoothGatt) {
                log.debug("device: ${device.address} > computing symmetric key")

                val dataFromPair = core.getKeyPair(context).private
                val privateKey = ECUtil.savePrivateKey(dataFromPair)

                symmetricKey = ECUtil.computeSymmetricKey(privateKey, peerPublicKey!!)

                step4(gatt)
            }

            private fun step6(gatt: BluetoothGatt) {
                step = 6
                log.debug("device: ${device.address} > disconnecting ...")
                gatt.disconnect()
            }

            private fun step7() {
                step = 7
                log.debug("device ${device.address} > unlocking mutex")
                mutex.unlock()
            }


            // step 1 and 6 callback
            override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
                log.debug("device: ${device.address} < connection changed $newState")
                if (status == GATT_SUCCESS && newState == BluetoothProfile.STATE_CONNECTED) {
                    step2(gatt)
                } else {
                    step7()
                }
            }

            // step 2 callback
            override fun onMtuChanged(gatt: BluetoothGatt?, newMtu: Int, status: Int) {
                log.debug("device: ${device.address} < mtu changed ($newMtu)")
                mtu = newMtu - 3 // todo: why do I seem to only be able to send MTU-3 bytes?!
                if (gatt == null) {
                    return step7()
                }
                step3(gatt)
            }

            // step3 callback
            override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
                log.debug("device: ${device.address} < service discovered ($status)")
                if (status == GATT_SUCCESS) {
                    return step4(gatt)
                }
                return step6(gatt)
            }

            // step 4 callback
            override fun onCharacteristicRead(
                gatt: BluetoothGatt?,
                characteristic: BluetoothGattCharacteristic?,
                status: Int
            ) {
                log.debug("device: ${device.address} < characteristic read ($status)")
                if (gatt == null) return step7()
                if (characteristic == null || status != GATT_SUCCESS) {
                    return step6(gatt)
                }

                runBlocking {
                    processAgattPayload(characteristic)
                }

                step5(gatt)
            }

            // callback step 5 (write pubkey)
            // calls function to compute symmetric key if it does not exist instead of disconnecting
            override fun onCharacteristicWrite(
                gatt: BluetoothGatt?,
                characteristic: BluetoothGattCharacteristic?,
                status: Int
            ) {
                timeout?.cancel()
                log.debug("device: ${device.address} < characteristic write pubkey ($status)")
                if (gatt == null) return step7()
                // call step 5a instead of step 6 if symmetric had not been computed
                if (symmetricKey == null) {
                    //compute symmetric key
                    step5a(gatt)
                } else {
                    step6(gatt)
                }
            }

            // We are changing this method to also extract the encrypted time and location from the
            // payload if present ()
            fun processAgattPayload(characteristic: BluetoothGattCharacteristic) {
                if (characteristic.uuid != core.whisperConfig.whisperV3CharacteristicUUID) return
                if (characteristic.value == null) return

                log.debug("device: ${device.address} < decoding wisper payload.. (size=${characteristic.value.size})")
                try {
                    if (characteristic.value.size < 2) throw Exception("header: missing")
                    val cmd = characteristic.value[0]
                    val payloadSize = characteristic.value[1]

                    if (cmd != 0x01.toByte()) throw Exception("header: unexpected type")
                    if (payloadSize + 2 > characteristic.value.size) throw Exception("header: wrong size")

                    val payload = ProtoBuf.load(
                        AgattPayload.serializer(),
                        characteristic.value.sliceArray(2..payloadSize + 1)
                    )
                    //*** save payload.pubkey to field
                    // If encounter is empty, then this is the first time alice reads something from
                    // bob -> we just get pubkey from payload and save it
                    if (payload.encounter.isEmpty()) {
                        peerPublicKey = payload.pubKey
                    } else {
                        // get encounter from payload
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

                        if(core.checkProximity(encounter, peerEncounter)){
                            // store public key of peer
                        }
                    }


                    log.debug("device: ${device.address} < whisper pubkey ${Base64.encodeToString(payload.pubKey, Base64.NO_WRAP)}")
                    CoroutineScope(Dispatchers.IO).launch {
                        upstream.send(
                            BleConnectEvent(
                                true,
                                device.address,
                                System.currentTimeMillis(),
                                payload.organization,
                                1,
                                payload.pubKey,
                                rssi
                            )
                        )
                    }
                } catch (e: Exception) {
                    log.debug("device: ${device.address} < parser failed! $e")
                }
                // badly formatted payload, do nothing
            }


        })

        mutex.lock()
    }
}