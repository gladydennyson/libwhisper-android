package world.coalition.whisper.id

import android.os.Build
import androidx.annotation.RequiresApi
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.interfaces.ECPublicKey
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import org.bouncycastle.jce.spec.ECPublicKeySpec
import org.bouncycastle.math.ec.ECCurve
import org.bouncycastle.math.ec.ECPoint
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.*
import java.security.spec.ECPrivateKeySpec
import java.security.spec.InvalidKeySpecException
import java.util.*


object KeyPairGen {
    var EcSpec: ECNamedCurveParameterSpec? = null
    private val mEcCurve: ECCurve? = null
    var Generator: ECPoint? = null
    var ec_server_key: BigInteger? = null
    @RequiresApi(Build.VERSION_CODES.N)
    fun GenSecKey(seed: ByteArray, ecspec: ECNamedCurveParameterSpec): BigInteger {
        var result: BigInteger
        val eccurve = ecspec.curve
        val order = eccurve.order
        val rrand = Random()
        val buffer: ByteBuffer = ByteBuffer.allocate(java.lang.Long.BYTES)
        buffer.put(seed)
        buffer.flip() //need flip

        val seedAsLong =  buffer.long
        rrand.setSeed(seedAsLong)
        do {
            result = BigInteger(order.bitLength(), rrand)
        } while (result >= order) //exclusive order
        return result
    }

    @Throws(
        InvalidKeySpecException::class,
        NoSuchProviderException::class,
        NoSuchAlgorithmException::class
    )
    fun GenPubKey(
        seckey: BigInteger,
        ecspec: ECNamedCurveParameterSpec
    ): PublicKey {
        val keyFactory =
            KeyFactory.getInstance("ECDSA", "BC")
        val Q = ecspec.g.multiply(seckey)
        val pubSpec =
            ECPublicKeySpec(Q, ecspec)
        return keyFactory.generatePublic(pubSpec)
    }

    @RequiresApi(Build.VERSION_CODES.N)
    @Throws(
        NoSuchAlgorithmException::class,
        NoSuchProviderException::class,
        InvalidAlgorithmParameterException::class,
        InvalidKeySpecException::class
    )
        fun genKeyPair(seed: ByteArray) : Pair<ByteArray, ByteArray> {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
        Security.insertProviderAt(BouncyCastleProvider(), 1)
        //        KeyPairGenerator kpgen = KeyPairGenerator.getInstance("EC", "BC");
//        // fake hash of master and eph seed
//        byte[] arr = {0, 1, 2, 3, 12, 13 , 14};
//        // Unable to use BC as provider because it does not support SecureRandom
//        // Defaulting to first provider that supports SHA1PRNG algorithm
//        SecureRandom sRandom = SecureRandom.getInstance("SHA1PRNG");
//        sRandom.setSeed(arr);
//        kpgen.initialize(new ECGenParameterSpec("secp192r1"), sRandom);
//        KeyPair pair = kpgen.generateKeyPair();
//
//
//        //ECPrivateKey ecPrivateKey = (ECPrivateKey) pair.getPrivate();
//
//        System.out.println(pair.getPublic().getEncoded());
        val ecspec =
            ECNamedCurveTable.getParameterSpec("secp224r1")
        val seckey = GenSecKey(seed, ecspec)
        val prvKey = seckey.toByteArray()
        val publickey = GenPubKey(seckey, ecspec)
        val pubkeyBouncyCastle =  publickey as ECPublicKey
        val bigintval = pubkeyBouncyCastle.parameters.n
        val pubKey = bigintval.toByteArray()
        return Pair(prvKey, pubKey)
    }
}