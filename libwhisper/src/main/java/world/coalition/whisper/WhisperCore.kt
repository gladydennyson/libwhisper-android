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

package world.coalition.whisper

import android.content.Context
import android.location.Location
import android.util.Base64
import ch.hsr.geohash.GeoHash
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import world.coalition.whisper.agathe.BleScanner
import world.coalition.whisper.database.BleConnectEvent
import world.coalition.whisper.database.WhisperDatabase
import world.coalition.whisper.exceptions.WhisperAlreadyStartedException
import world.coalition.whisper.exceptions.WhisperNotStartedException
import world.coalition.whisper.geo.GpsListener
import world.coalition.whisper.id.ECUtil
import java.security.KeyPair
import java.security.PublicKey
import java.util.*


/**
 * @author Lucien Loiseau on 03/04/20.
 */
class WhisperCore : Whisper {

    private val log: Logger = LoggerFactory.getLogger(Whisper::class.java)

    private var db: WhisperDatabase? = null

    private var gpsListener: GpsListener? = null

    private var lastPosition: Location? = null

    private var coreJob: Job? = null

    private var bleScanner: BleScanner? = null

    var channel: Channel<BleConnectEvent>? = null
        private set

    var whisperConfig: WhisperConfig = WhisperConfig()
        private set

    fun getDb(context: Context): WhisperDatabase {
        db = db ?: WhisperDatabase.persistent(context)
        return db!!
    }

    /** Public Methods - interface implementation **/
    @Throws(WhisperAlreadyStartedException::class)
    override fun start(context: Context) = start(context, WhisperConfig())

    @Throws(WhisperAlreadyStartedException::class)
    override fun start(context: Context, config: WhisperConfig): Whisper {
        if (coreJob != null) throw WhisperAlreadyStartedException()
        log.debug("[+] starting lib whisper..")

        coreJob = CoroutineScope(Dispatchers.IO).launch {
            var lastLocation: String? = null

            gpsListener = GpsListener(this@WhisperCore)
            bleScanner = BleScanner(this@WhisperCore)
            channel = Channel(capacity = Channel.UNLIMITED)
            gpsListener?.start(context) {
                lastLocation = GeoHash.withCharacterPrecision(it.latitude, it.longitude, 4).toBase32()
                lastPosition = it
            }
            bleScanner?.start(context, channel!!)

            for (interaction in channel!!) {
                val proof = ECUtil.getInteraction(
                    getKeyPair(context),
                    Base64.decode(interaction.advPeerPubKey, Base64.NO_WRAP)
                )
                getDb(context).addInteraction(interaction, proof, lastLocation)
            }
        }
        return this
    }

    @Throws(WhisperNotStartedException::class)
    override suspend fun stop() {
        if (coreJob == null) throw WhisperNotStartedException()
        log.debug("[+] stopping lib whisper..")
        gpsListener?.stop()
        bleScanner?.stop()
        channel?.close()
        coreJob!!.join()
        db?.close()
    }

    // function that computes and returns encounter
    // return 128-bit encounter
    // pads with zeros if less than 128 bits
    fun getEncounter(): ByteArray {
        val date = Date()
        val lat = lastPosition!!.latitude.toByte()
        val long = lastPosition!!.longitude.toByte()
        val time = date.time.toByte()
        val byteList: MutableList<Byte> = mutableListOf()
        byteList.add(time)
        byteList.add(lat)
        byteList.add(long)
        while (byteList.size < 16) byteList.add(0.toByte())
        val byteArray = byteList.toByteArray()
        return byteArray
    }

    override fun isStarted(): Boolean {
        return coreJob != null
    }

    fun getKeyPair(context: Context): KeyPair {
        return getDb(context).getCurrentKeyPair(
            System.currentTimeMillis() / 1000,
            whisperConfig.pubkeyValidityPeriodSec)
    }

    fun getPublicKey(context: Context): PublicKey {
        return getDb(context).getCurrentPublicKey(
            System.currentTimeMillis() / 1000,
            whisperConfig.pubkeyValidityPeriodSec)
    }

    override suspend fun getLastTellTokens(context: Context, periodSec: Long): List<GeoToken> {
        val sinceMsec = System.currentTimeMillis() - periodSec*1000
        return getDb(context).roomDb.privateEncounterTokenDao().getAllRemainingTellTokenSince(sinceMsec)
    }

    override suspend fun tellTokensShared(context: Context, tokens: List<String>) {
        getDb(context).tellTokensShared(tokens)
    }

    override suspend fun getLastHearTokens(context: Context, periodSec: Long): List<GeoToken> {
        val sinceMsec = System.currentTimeMillis() - periodSec*1000
        return getDb(context).roomDb.privateEncounterTokenDao().getAllHearTokenSince(sinceMsec)
    }

    override suspend fun processHearTokens(context: Context, infectedSet: List<String>, tag: String): Int {
        val sinceMsec = System.currentTimeMillis() - whisperConfig.incubationPeriod*1000
        return getDb(context).processTellTokens(infectedSet, tag,  sinceMsec)
    }

    override suspend fun getRiskExposure(context: Context, tag: String): Int =
        getDb(context).getRiskExposure(tag)


    // check current node's and peer's proximity
    fun checkProximity(currentLocation:ByteArray, peerLocation:ByteArray): Boolean {


        val currentLocLat = currentLocation[1].toDouble()
        val currentLocLng = currentLocation[2].toDouble()
        val peerLocLat = peerLocation[1].toDouble()
        val peerLocLng = peerLocation[2].toDouble()
        val latDistance = Math.toRadians(currentLocLat - peerLocLat);
        val lngDistance = Math.toRadians(currentLocLng - currentLocLng);
        val a = (Math.sin(latDistance / 2) * Math.sin(latDistance / 2)
                + (Math.cos(Math.toRadians(currentLocLat)) * Math.cos(Math.toRadians(peerLocLat))
                * Math.sin(lngDistance / 2) * Math.sin(lngDistance / 2)))
        val c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a))
        val distance = Math.round(whisperConfig.averageRadiusOfEarthKm * c).toInt();

        if (distance<100){
            return true
        }
        return false
    }

}