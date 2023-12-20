using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Math;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Pkcs;
using System.Xml;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Ocsp;


namespace RsaUtil
{


    /// <summary>
    /// RSA 
    /// </summary>
    internal class RsaUtil
    {

        #region 生产密钥对

        /// <summary>
        /// 生成密钥  默认2048  
        /// <param name="privateKey">私钥</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="keySize">默认2048  密钥长度：512,1024,2048，4096，8192</param>
        /// </summary>
        public static void GeneratorNet(out string privateKey, out string publicKey, int keySize = 2048)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(keySize);
            privateKey = rsa.ToXmlString(true); //将RSA算法的私钥导出到字符串PrivateKey中 参数为true表示导出私钥 true 表示同时包含 RSA 公钥和私钥；false 表示仅包含公钥。
            publicKey = rsa.ToXmlString(false); //将RSA算法的公钥导出到字符串PublicKey中 参数为false表示不导出私钥 true 表示同时包含 RSA 公钥和私钥；false 表示仅包含公钥。  
        }


        /// <summary>
        /// 生成密钥  默认2048
        /// <param name="privateKey">私钥</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="keySize">默认2048  密钥长度：512,1024,2048，4096，8192</param>
        /// </summary>
        public static void GeneratorJava(out string privateKey, out string publicKey, int keySize = 2048)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(keySize);
            privateKey = RsaPrivateKeyDotNet2Java( rsa.ToXmlString(true)); //将RSA算法的私钥导出到字符串PrivateKey中 参数为true表示导出私钥 true 表示同时包含 RSA 公钥和私钥；false 表示仅包含公钥。
            publicKey =RsaPublicKeyDotNet2Java(rsa.ToXmlString(false)); //将RSA算法的公钥导出到字符串PublicKey中 参数为false表示不导出私钥 true 表示同时包含 RSA 公钥和私钥；false 表示仅包含公钥。  
        }

        #endregion

        #region 加解密



        /// <summary>
        /// RSA 公钥 分段加密
        /// </summary>
        /// <param name="publicKey">公钥</param>
        /// <param name="encryptstring">待加密的字符串</param>
        public static string RsaEncrypt(string publicKey, string encryptstring)
        {
            using (var rsaProvider = new RSACryptoServiceProvider())
            {
                var inputBytes = Encoding.UTF8.GetBytes(encryptstring);//有含义的字符串转化为字节流

                var xmlPublicKey= RSAPublicKeyJava2DotNet(publicKey);
                rsaProvider.FromXmlString(xmlPublicKey);//载入公钥
                int bufferSize = (rsaProvider.KeySize / 8) - 11;//单块最大长度
                var buffer = new byte[bufferSize];
                using (MemoryStream inputStream = new MemoryStream(inputBytes), outputStream = new MemoryStream())
                {
                    while (true)
                    { //分段加密
                        int readSize = inputStream.Read(buffer, 0, bufferSize);
                        if (readSize <= 0)
                        {
                            break;
                        }
                        var temp = new byte[readSize];
                        Array.Copy(buffer, 0, temp, 0, readSize);
                        var encryptedBytes = rsaProvider.Encrypt(temp, false);
                        outputStream.Write(encryptedBytes, 0, encryptedBytes.Length);
                    }
                    return Convert.ToBase64String(outputStream.ToArray());//转化为字节流方便传输
                }
            }
        }

        /// <summary>  
        /// RSA 私钥 解密 
        /// </summary>  
        /// <param name="privateKey">私钥</param>  
        /// <param name="decryptstring">待解密的字符串</param>  
        public static string RsaDecrypt(string privateKey, string decryptstring)
        {
            using (var rsaProvider = new RSACryptoServiceProvider())
            {
                var xmlPrivateKey = RSAPrivateKeyJava2DotNet(privateKey);
                rsaProvider.FromXmlString(xmlPrivateKey); //载入私钥  
                var encryptedBytes = Convert.FromBase64String(decryptstring); //将传入的字符串转化为字节流  
                var bufferSize = rsaProvider.KeySize / 8;
                var buffer = new byte[bufferSize];
                using (MemoryStream inputStream = new MemoryStream(encryptedBytes), outputStream = new MemoryStream())
                {
                    while (true)
                    {
                        int readSize = inputStream.Read(buffer, 0, bufferSize);
                        if (readSize <= 0)
                        {
                            break;
                        }
                        var temp = new byte[readSize];
                        Array.Copy(buffer, 0, temp, 0, readSize);
                        var decryptedBytes = rsaProvider.Decrypt(temp, false);
                        outputStream.Write(decryptedBytes, 0, decryptedBytes.Length);
                    }
                    return Encoding.UTF8.GetString(outputStream.ToArray()); //转化为字符串  
                }
            }
        }

        /// <summary>
        /// RSA私钥  分段 加密
        /// </summary>
        /// <param name="privateKey">私钥</param>
        /// <param name="encryptstring">待加密的字符串</param>
        public static string RsaPrivateEncrypt(string privateKey, string encryptstring)
        {
            var rsaProvider = new RSACryptoServiceProvider();
            var xmlPrivateKey = RSAPrivateKeyJava2DotNet(privateKey);
            rsaProvider.FromXmlString(xmlPrivateKey);//载入私钥
            //var inputBytes = Convert.FromBase64String(encryptstring);//有含义的字符串转化为字节流
            byte[] inputBytes = Encoding.UTF8.GetBytes(encryptstring);
            int bufferSize = (rsaProvider.KeySize / 8) - 11;//单块最大长度
            var buffer = new byte[bufferSize];
            using (MemoryStream inputStream = new MemoryStream(inputBytes), outputStream = new MemoryStream())
            {
                while (true)
                {
                    //分段加密
                    int readSize = inputStream.Read(buffer, 0, bufferSize);
                    if (readSize <= 0)
                    {
                        break;
                    }
                    var temp = new byte[readSize];
                    Array.Copy(buffer, 0, temp, 0, readSize);
                    var encryptedBytes = RsaPrivateEncrypt(privateKey, temp);
                    outputStream.Write(encryptedBytes, 0, encryptedBytes.Length);
                }
                return Convert.ToBase64String(outputStream.ToArray());//转化为字节流方便传输
            }
        }

        /// <summary>  
        /// RSA公钥解密
        /// </summary>  
        /// <param name="publicKey">公钥</param>  
        /// <param name="decryptstring">待解密的字符串</param>  
        public static string RsaPublicDecrypt(string publicKey, string decryptstring)
        {
            var rsaProvider = new RSACryptoServiceProvider();
            var xmlPublicKey = RSAPublicKeyJava2DotNet(publicKey);
            rsaProvider.FromXmlString(xmlPublicKey); //载入公钥  
            var encryptedBytes = Convert.FromBase64String(decryptstring); //将传入的字符串转化为字节流  
            var bufferSize = rsaProvider.KeySize / 8;
            var buffer = new byte[bufferSize];
            using (MemoryStream inputStream = new MemoryStream(encryptedBytes), outputStream = new MemoryStream())
            {
                while (true)
                {
                    int readSize = inputStream.Read(buffer, 0, bufferSize);
                    if (readSize <= 0)
                    {
                        break;
                    }
                    var temp = new byte[readSize];
                    Array.Copy(buffer, 0, temp, 0, readSize);
                    var decryptedBytes = decryptByPublicKey(publicKey, temp);
                    outputStream.Write(decryptedBytes, 0, decryptedBytes.Length);
                }
                return Encoding.UTF8.GetString(outputStream.ToArray());
                //return Convert.ToBase64String(outputStream.ToArray());
            }
        }

        /// <summary>
        /// 私钥加密
        /// 这个方法只能加密 私钥长度/8 -11 个字符，分段加密的代码要自己处理了。
        /// </summary>
        /// <param name="privateKey">密钥</param>
        /// <param name="data">要加密的数据</param>
        /// <returns></returns>
        public static byte[] RsaPrivateEncrypt(string privateKey, byte[] data)
        {
            string xmlPrivateKey = RSAPrivateKeyJava2DotNet(privateKey);
            //加载私钥  
            RSACryptoServiceProvider privateRsa = new RSACryptoServiceProvider();
            privateRsa.FromXmlString(xmlPrivateKey);
            //转换密钥  
            AsymmetricCipherKeyPair keyPair = DotNetUtilities.GetKeyPair(privateRsa);
            IBufferedCipher c = CipherUtilities.GetCipher("RSA/ECB/PKCS1Padding");// 参数与Java中加密解密的参数一致       
            //IBufferedCipher c = CipherUtilities.GetCipher("RSA");
            c.Init(true, keyPair.Private); //第一个参数为true表示加密，为false表示解密；第二个参数表示密钥 
            byte[] DataToEncrypt = data;
            byte[] outBytes = c.DoFinal(DataToEncrypt);//加密  
            return outBytes;
        }

        /// <summary>
        /// 用公钥解密
        /// 这个方法只能加密 私钥长度/8 -11 个字符，分段加密的代码要自己处理了。
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static byte[] decryptByPublicKey(string publicKey, byte[] data)
        {
            string xmlPublicKey = RSAPublicKeyJava2DotNet(publicKey);

            RSACryptoServiceProvider publicRsa = new RSACryptoServiceProvider();
            publicRsa.FromXmlString(xmlPublicKey);

            AsymmetricKeyParameter keyPair = DotNetUtilities.GetRsaPublicKey(publicRsa);
            //转换密钥  
            // AsymmetricCipherKeyPair keyPair = DotNetUtilities.GetRsaKeyPair(publicRsa);
            IBufferedCipher c = CipherUtilities.GetCipher("RSA/ECB/PKCS1Padding");// 参数与Java中加密解密的参数一致       
            //IBufferedCipher c = CipherUtilities.GetCipher("RSA");
            c.Init(false, keyPair); //第一个参数为true表示加密，为false表示解密；第二个参数表示密钥 
            byte[] DataToEncrypt = data;
            byte[] outBytes = c.DoFinal(DataToEncrypt);//解密  
            return outBytes;
        }

        #endregion

        #region 签名验签部分

        /// <summary>
        /// 私钥签名
        /// </summary>
        /// <param name="data"></param>
        /// <param name="privatekey"></param>
        /// <returns></returns>
        public static string RsaSign(string data, string privatekey)
        {
            //转换成适用于.Net的秘钥
            var netKey = RSAPrivateKeyJava2DotNet(privatekey);
            CspParameters CspParameters = new CspParameters();
            RSACryptoServiceProvider RSA = new RSACryptoServiceProvider(2048, CspParameters);
            byte[] bytes = Encoding.UTF8.GetBytes(data);
            RSA.FromXmlString(netKey);
            byte[] sign = RSA.SignData(bytes, "SHA256");

            return Convert.ToBase64String(sign);
        }

        /// <summary>
        /// 公钥 验签  2048 SHA256 
        /// </summary>
        /// <param name="contentForSign"></param>
        /// <param name="signedData"></param>
        /// <param name="publickey"></param>
        /// <returns></returns>
        public static bool RsaVerifySign(string contentForSign, string signedData, string publickey)
        {
            //转换成适用于.Net的秘钥
            var netKey = RSAPublicKeyJava2DotNet(publickey);
            CspParameters CspParameters = new CspParameters();
            RSACryptoServiceProvider RSA = new RSACryptoServiceProvider(2048, CspParameters);
            byte[] bytes = Encoding.UTF8.GetBytes(contentForSign);
            RSA.FromXmlString(netKey);
            var datas = Convert.FromBase64String(signedData);
            var res = RSA.VerifyData(bytes, "SHA256", datas);

            return res;
        }

        /// <summary>
        /// 公钥签名
        /// </summary>
        /// <param name="data"></param>
        /// <param name="pubkey"></param>
        /// <returns></returns>
        public static string RsaPubSign(string data, string pubkey)
        {
            //转换成适用于.Net的秘钥
            var netKey = RSAPublicKeyJava2DotNet(pubkey);
            CspParameters CspParameters = new CspParameters();
            RSACryptoServiceProvider RSA = new RSACryptoServiceProvider(2048, CspParameters);
            byte[] bytes = Encoding.UTF8.GetBytes(data);
            RSA.FromXmlString(netKey);
            byte[] sign = RSA.SignData(bytes, "SHA256");

            return Convert.ToBase64String(sign);
        }

        /// <summary>
        /// 私钥 验签 SHA256 2048 
        /// </summary>
        /// <param name="contentForSign"></param>
        /// <param name="signedData"></param>
        /// <param name="privatekey"></param>
        /// <returns></returns>
        public static bool RsaPubVerifySign(string contentForSign, string signedData, string privatekey)
        {
            //转换成适用于.Net的秘钥
            var netKey = RSAPrivateKeyJava2DotNet(privatekey);
            CspParameters CspParameters = new CspParameters();
            RSACryptoServiceProvider RSA = new RSACryptoServiceProvider(2048, CspParameters);
            byte[] bytes = Encoding.UTF8.GetBytes(contentForSign);
            RSA.FromXmlString(netKey);
            var datas = Convert.FromBase64String(signedData);
            var res = RSA.VerifyData(bytes, "SHA256", datas);
            return res;
        }
        #endregion

        #region java/net公私钥互转



        /// <summary>
        /// RSA私钥格式转换，java->.net
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public static string RSAPrivateKeyJava2DotNet(string privateKey)
        {
            RsaPrivateCrtKeyParameters privateKeyParam = (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(Convert.FromBase64String(privateKey));

            return string.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent><P>{2}</P><Q>{3}</Q><DP>{4}</DP><DQ>{5}</DQ><InverseQ>{6}</InverseQ><D>{7}</D></RSAKeyValue>",
                Convert.ToBase64String(privateKeyParam.Modulus.ToByteArrayUnsigned()),
                Convert.ToBase64String(privateKeyParam.PublicExponent.ToByteArrayUnsigned()),
                Convert.ToBase64String(privateKeyParam.P.ToByteArrayUnsigned()), Convert.ToBase64String(privateKeyParam.Q.ToByteArrayUnsigned()),
                Convert.ToBase64String(privateKeyParam.DP.ToByteArrayUnsigned()),
                Convert.ToBase64String(privateKeyParam.DQ.ToByteArrayUnsigned()),
                Convert.ToBase64String(privateKeyParam.QInv.ToByteArrayUnsigned()),
                Convert.ToBase64String(privateKeyParam.Exponent.ToByteArrayUnsigned()));
        }

   

        /// <summary>
        /// RSA公钥格式转换，java->.net
        /// </summary>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public static string RSAPublicKeyJava2DotNet(string publicKey)
        {
            RsaKeyParameters publicKeyParam = (RsaKeyParameters)PublicKeyFactory.CreateKey(Convert.FromBase64String(publicKey));
            return string.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent></RSAKeyValue>",
                Convert.ToBase64String(publicKeyParam.Modulus.ToByteArrayUnsigned()),
                Convert.ToBase64String(publicKeyParam.Exponent.ToByteArrayUnsigned()));
        }


        /// <summary>    
        /// RSA私钥格式转换，.net->java    
        /// </summary>    
        /// <param name="privateKey">.net生成的私钥</param>    
        /// <returns></returns>   
        public static string RsaPrivateKeyDotNet2Java(string privateKey)
        {
            XmlDocument doc = new XmlDocument();
            doc.LoadXml(privateKey);
            if (doc.DocumentElement == null)
            {
                return null;
            }
            BigInteger m = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("Modulus")[0].InnerText));
            BigInteger exp = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("Exponent")[0].InnerText));
            BigInteger d = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("D")[0].InnerText));
            BigInteger p = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("P")[0].InnerText));
            BigInteger q = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("Q")[0].InnerText));
            BigInteger dp = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("DP")[0].InnerText));
            BigInteger dq = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("DQ")[0].InnerText));
            BigInteger qinv = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("InverseQ")[0].InnerText));
            RsaPrivateCrtKeyParameters privateKeyParam = new RsaPrivateCrtKeyParameters(m, exp, d, p, q, dp, dq, qinv);
            PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKeyParam);
            byte[] serializedPrivateBytes = privateKeyInfo.ToAsn1Object().GetEncoded();
            return Convert.ToBase64String(serializedPrivateBytes);
        }

        /// <summary>    
        /// RSA公钥格式转换，.net->java    
        /// </summary>    
        /// <param name="publicKey">.net生成的公钥</param>    
        /// <returns></returns>   
        public static string RsaPublicKeyDotNet2Java(string publicKey)
        {
            XmlDocument doc = new XmlDocument();
            doc.LoadXml(publicKey);
            if (doc.DocumentElement == null)
            {
                return null;
            }
            BigInteger m = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("Modulus")[0].InnerText));
            BigInteger p = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("Exponent")[0].InnerText));
            RsaKeyParameters pub = new RsaKeyParameters(false, m, p);
            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pub);
            byte[] serializedPublicBytes = publicKeyInfo.ToAsn1Object().GetDerEncoded();
            return Convert.ToBase64String(serializedPublicBytes);
        }
        #endregion

    }
}
