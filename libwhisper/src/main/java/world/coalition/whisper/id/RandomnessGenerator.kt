package world.coalition.whisper.id

import org.bouncycastle.crypto.digests.Blake2sDigest
import org.bouncycastle.crypto.prng.ThreadedSeedGenerator
import java.util.Timer
import java.util.TimerTask

class RandomnessGenerator(private val masterSeed: ByteArray) {

    private val EPHSEED_LIFETIME = 900000L // 15 minutes in ms

    private val SEED_SIZE = 16 //number of bytes in eseed

    private val ephSeedGenerator =  ThreadedSeedGenerator()

    private val ephSeeds = mutableListOf<ByteArray>()

    private fun generateSeedEphSeed() {
        val ephSeed = ephSeedGenerator.generateSeed(SEED_SIZE, false)
        ephSeeds.add(0, ephSeed) // add new seed to front
    }

    private fun doBlake2s(
        masterSeed: ByteArray,
        ephSeed: ByteArray
    ): ByteArray {
        val keyedHash = Blake2sDigest(256)
        val hash = ByteArray(keyedHash.digestSize)
        keyedHash.update(masterSeed, 0, masterSeed.size);
        keyedHash.update(ephSeed, 0, ephSeed.size);
        keyedHash.doFinal(hash, 0);
        return hash
    }
    
    init {
        val timer = Timer()
        val genereateNewSeed = object: TimerTask() {
            @Override
            override fun run() {
                generateSeedEphSeed()
            }
        }
        timer.schedule(genereateNewSeed, 0L, EPHSEED_LIFETIME)
    }
    
    fun getEphSeeds(): MutableList<ByteArray> {
        return ephSeeds
    }

    fun getRandomness(): ByteArray {
        return doBlake2s(masterSeed, ephSeeds[0])
    }
}