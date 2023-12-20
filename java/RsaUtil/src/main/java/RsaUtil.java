import java.io.ByteArrayOutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;


/**
 * java RSA 128  256
 * PS:RSA加密对明文的长度有所限制，规定需加密的明文最大长度=密钥长度-11（单位是字节，即byte），
 * 所以在加密和解密的过程中需要分块进行。而密钥默认是1024位，即1024位/8位-11=128-11=117字节。
 * 所以默认加密前的明文最大长度117字节，解密密文最大长度为128字。
 * 那么为啥两者相差11字节呢？是因为RSA加密使用到了填充模式（padding），即内容不足117字节时会自动填满，
 * 用到填充模式自然会占用一定的字节，而且这部分字节也是参与加密的。
 *
 * @author qqdyl
 */
public class RsaUtil {


    /**
     * RSA 1024  或者  2048  默认 2048
     */
    private static final int keySize = 2048;

    /**
     * 1024 RSA最大加密明文大小  117
     * 2048 RSA最大加密明文大小  245
     */
    private static final int MAX_ENCRYPT_BLOCK = 245;

    /**
     * 1024 RSA最大解密密文大小 128
     * 2048 RSA最大解密密文大小 256
     */
    private static final int MAX_DECRYPT_BLOCK = 256;



    /**
     * test
     *
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
        //KeyPair keyPair = getKeyPair(keySize);
        //System.out.println("privateKey:" + keyPair.getPrivate());
        //System.out.println("publicKey:" + keyPair.getPublic());
        PrivateKey privateKey=RsaUtil.getPrivateKey("MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC+NXpCCFfTcqTP2Pl8tyGqp8LBFwdb85zgdWNtUsw8QduRLtfdPcqYvdahHr1tQxzt26pZSU9tTDEkvrSud5b4K3ZKTmQKN1r6A30bwNFSV4ZzpKpi1xH6MWOVQ60YXhlasejS8yyr7+rF8jAtxKkbCrRJUxbfhiI9iHhbvalS51iXl/z/HPVWAmKWAMWErZ8e6g9lOsjOecnuvZxaK4xjCbx7Ky8XIOTAmgbqHxKwCTl+h7IGKH8cjszhGaQaQYDml9v2Vf4i9mtd3sKaguGUppIoTeDg6CCC2VobGYExJkHS73gc+2IM3EL/8quDorPzdKniqUzlovUgMFfygk2dAgMBAAECggEANQLAfRDIMWUdK9RDzA9Z8a7pp1jcszLVAPWWbUyLISwVnoPYo49qHGGkJKllj8MJl/0Fn/a/jS2T8LK5tnob+DRctl7coMBGubEpOAfoDrPYA/jbh8p69yi2oU4IOudW16EHy2r8gzrNSrex17+cha3ZCyp+EHPYrR+Qs7jLLRBT207xlF9lMBS2xFML5khydxpoQpaKnouZ8fc1g84HsDDM9RrCtuSmFzzypk1NJdggXVZM7G9yQY6lQY6R1ZUkgEM+mpEURGNHCZonFAE9+HKo37+yomCE4gw5Gcq4B615A+B2c5LKhy0nWSBv63X7rUcUMfGwezvCbxAaEfwofQKBgQDU5rGwOwJyHUlylGH+eZd//zHUaPbCQo6sMXOEV1GjK9Nwc33thyd0v6c71vNrTOG1Ys8PoirISWOOMziUIHkd0hQhmzdvelwx1c5cTuLKCmBHeTVtDDXy2jOYT2QiQDC7+3ANYJgKkP2xsT/nGMoaaDpJ+ctfXl0Z30t6wrNwGwKBgQDktsoA3ZlK19FpUC6Mm0NMXASKsZseCTQIrftft1cNRoK1oH7vqJEwCW1vCwrAlfjasR8ERGTjrPaIo16joX9AQk7ZET8Bn9IkYhs9BDXA+4ABLdGuUWvQpDeMT5m0var9ndf+IFiMT2bH00Nz122vSvf5jSYMLqWo3nBgTddEpwKBgQCILF4uuC+iSbU2wk3DdIZAaju2/sQGEIgs/xxB44/l7Bw7asN6791+wS74CU58rRoY6HBEMZdnr/krdPuVUwfk2P/jVuIoPX1GqthpFlPcorJeRNq1OwAuqv4hR3ZmqeQB+Jr9E3FsIL0DsLmM2MA8D7poootAHp0x9S7UAEDBTQKBgQCcvUwIddUk/mxsAOA1yf2/6dvO9NJ6LhJz1E/OE8ZbubPAJyJ2uY3uXreZfva6bszhirrX4MtHYHR/xX4JI5cigY6pofEM+us3teg205jHDVR2+mCVVwVNMg1DYhXTUJxLPI4WgTJNzeiBDx5N2Bg6JmV0py+o75rl9LMMvKvHRwKBgHYwUbhIDLoz7yeGu3yh+2ZXPVKJVgKEW5xpxULkbcCFb1mK2pKM2DvIVMW2X22Re7iM2afm8tNBbzD5zsYibql1SpRTYrS69x+hRlpQETcuiLhgtLA+3eG9uMh0yrU5em7Y3NF/TCq28SBr0N4gVm+HJ0wB2s9n3fRR0UBaCpBO");
        PublicKey publicKey= RsaUtil.getPublicKey("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvjV6QghX03Kkz9j5fLchqqfCwRcHW/Oc4HVjbVLMPEHbkS7X3T3KmL3WoR69bUMc7duqWUlPbUwxJL60rneW+Ct2Sk5kCjda+gN9G8DRUleGc6SqYtcR+jFjlUOtGF4ZWrHo0vMsq+/qxfIwLcSpGwq0SVMW34YiPYh4W72pUudYl5f8/xz1VgJilgDFhK2fHuoPZTrIznnJ7r2cWiuMYwm8eysvFyDkwJoG6h8SsAk5foeyBih/HI7M4RmkGkGA5pfb9lX+IvZrXd7CmoLhlKaSKE3g4OgggtlaGxmBMSZB0u94HPtiDNxC//Krg6Kz83Sp4qlM5aL1IDBX8oJNnQIDAQAB");
        KeyPair keyPair=new KeyPair(publicKey,privateKey);
        System.out.println("-------------------------------公钥加密 私钥解密----------------------------------------");
        String data="8896";
        System.out.println("明文长度："+data.getBytes().length);
        String encrypt = encrypt(data, keyPair.getPublic());
        System.out.println("公钥密文:" + encrypt);
        String decrypt = decrypt(encrypt, keyPair.getPrivate());
        System.out.println("私钥明文:" + decrypt);
        System.out.println("-------------------------------私钥加密 公钥解密----------------------------------------");
        String encrypt2 = encrypt(data, keyPair.getPrivate());
        System.out.println("私钥密文:" + encrypt2);
        String decrypt2 = decrypt(encrypt2, keyPair.getPublic());
        System.out.println("公钥明文:" + decrypt2);
        System.out.println("-------------------------------私钥签名 公钥验签----------------------------------------");
        String sign = RsaUtil.sign(data, keyPair.getPrivate());
        System.out.println("私钥签名："+sign);
        boolean verify = RsaUtil.verify(data, keyPair.getPublic(), sign);
        System.out.println("公钥验签："+verify);
    }

    /**
     * 获取密钥对
     *
     * @return 密钥对
     */
    public static KeyPair getKeyPair(int keySize) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(keySize);
        return generator.generateKeyPair();
    }

    /**
     * 获取私钥
     *
     * @param privateKey 私钥字符串
     * @return
     */
    public static PrivateKey getPrivateKey(String privateKey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        byte[] decodedKey = Base64.getDecoder().decode(privateKey.getBytes());
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
        return keyFactory.generatePrivate(keySpec);
    }

    /**
     * 获取公钥
     *
     * @param publicKey 公钥字符串
     * @return
     */
    public static PublicKey getPublicKey(String publicKey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        byte[] decodedKey = Base64.getDecoder().decode(publicKey.getBytes());
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);
        return keyFactory.generatePublic(keySpec);
    }

    /**
     * RSA 公钥 加密
     *
     * @param data      待加密数据
     * @param publicKey 公钥
     * @return
     */
    public static String encrypt(String data, PublicKey publicKey) throws Exception {

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        int inputLen = data.getBytes().length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offset = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段加密
        while (inputLen - offset > 0) {
            if (inputLen - offset > MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(data.getBytes(), offset, MAX_ENCRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(data.getBytes(), offset, inputLen - offset);
            }
            out.write(cache, 0, cache.length);
            i++;
            offset = i * MAX_ENCRYPT_BLOCK;
        }
        byte[] encryptedData = out.toByteArray();
        out.close();
        // 获取加密内容使用base64进行编码,并以UTF-8为标准转化成字符串
        // 加密后的字符串
        return new String(Base64.getEncoder().encode(encryptedData));
    }

    /**
     * RSA 私钥  加密
     *
     * @param data      待加密数据
     * @param privateKey 私钥
     * @return
     */
    public static String encrypt(String data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        int inputLen = data.getBytes().length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offset = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段加密
        while (inputLen - offset > 0) {
            if (inputLen - offset > MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(data.getBytes(), offset, MAX_ENCRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(data.getBytes(), offset, inputLen - offset);
            }
            out.write(cache, 0, cache.length);
            i++;
            offset = i * MAX_ENCRYPT_BLOCK;
        }
        byte[] encryptedData = out.toByteArray();
        out.close();
        // 获取加密内容使用base64进行编码,并以UTF-8为标准转化成字符串
        // 加密后的字符串
        return new String(Base64.getEncoder().encode(encryptedData));
    }

    /**
     * RSA解密
     *
     * @param data       待解密数据
     * @param privateKey 私钥
     * @return
     */
    public static String decrypt(String data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] dataBytes = Base64.getDecoder().decode(data);
        int inputLen = dataBytes.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offset = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段解密
        while (inputLen - offset > 0) {
            if (inputLen - offset > MAX_DECRYPT_BLOCK) {
                cache = cipher.doFinal(dataBytes, offset, MAX_DECRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(dataBytes, offset, inputLen - offset);
            }
            out.write(cache, 0, cache.length);
            i++;
            offset = i * MAX_DECRYPT_BLOCK;
        }
        byte[] decryptedData = out.toByteArray();
        out.close();
        // 解密后的内容
        return new String(decryptedData, "UTF-8");
    }

    /**
     * RSA 公钥 解密
     *
     * @param data       待解密数据
     * @param publicKey 公钥
     * @return
     */
    public static String decrypt(String data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] dataBytes = Base64.getDecoder().decode(data);
        int inputLen = dataBytes.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offset = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段解密
        while (inputLen - offset > 0) {
            if (inputLen - offset > MAX_DECRYPT_BLOCK) {
                cache = cipher.doFinal(dataBytes, offset, MAX_DECRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(dataBytes, offset, inputLen - offset);
            }
            out.write(cache, 0, cache.length);
            i++;
            offset = i * MAX_DECRYPT_BLOCK;
        }
        byte[] decryptedData = out.toByteArray();
        out.close();
        // 解密后的内容
        return new String(decryptedData, "UTF-8");
    }

    /**
     * 签名
     *
     * @param data       待签名数据
     * @param privateKey 私钥
     * @return 签名
     */
    public static String sign(String data, PrivateKey privateKey) throws Exception {
        byte[] keyBytes = privateKey.getEncoded();
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey key = keyFactory.generatePrivate(keySpec);
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(key);
        signature.update(data.getBytes());
        return new String(Base64.getEncoder().encode(signature.sign()));
    }

    /**
     * 验签
     *
     * @param srcData   原始字符串
     * @param publicKey 公钥
     * @param sign      签名
     * @return 是否验签通过
     */
    public static boolean verify(String srcData, PublicKey publicKey, String sign) throws Exception {
        byte[] keyBytes = publicKey.getEncoded();
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey key = keyFactory.generatePublic(keySpec);
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(key);
        signature.update(srcData.getBytes());
        return signature.verify(Base64.getDecoder().decode(sign.getBytes()));

    }

}
