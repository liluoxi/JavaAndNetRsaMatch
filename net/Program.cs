// See https://aka.ms/new-console-template for more information

using System.Reflection.Emit;
using System.Text;

Console.WriteLine("Hello, World!");
String publicKey ="";
String privateKey="";

//Console.WriteLine("----------------------------新生成 net key--------------------------------");
//RsaUtil.RsaUtil.GeneratorNet(out privateKey, out publicKey, 2048);

//Console.WriteLine("NetPrivateKey:" + privateKey);
//Console.WriteLine("NetPublicKey:" + publicKey);

//Console.WriteLine("----------------------------新生成 java key-------------------------------------");

//RsaUtil.RsaUtil.GeneratorJava(out privateKey, out publicKey, 2048);

//Console.WriteLine("privateKey:" + privateKey);
//Console.WriteLine("publicKey:" + publicKey);

Console.WriteLine("----------------------------Java Demo Test key-------------------------------------");
//与java Demo 测试数据
publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvjV6QghX03Kkz9j5fLchqqfCwRcHW/Oc4HVjbVLMPEHbkS7X3T3KmL3WoR69bUMc7duqWUlPbUwxJL60rneW+Ct2Sk5kCjda+gN9G8DRUleGc6SqYtcR+jFjlUOtGF4ZWrHo0vMsq+/qxfIwLcSpGwq0SVMW34YiPYh4W72pUudYl5f8/xz1VgJilgDFhK2fHuoPZTrIznnJ7r2cWiuMYwm8eysvFyDkwJoG6h8SsAk5foeyBih/HI7M4RmkGkGA5pfb9lX+IvZrXd7CmoLhlKaSKE3g4OgggtlaGxmBMSZB0u94HPtiDNxC//Krg6Kz83Sp4qlM5aL1IDBX8oJNnQIDAQAB";
privateKey = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC+NXpCCFfTcqTP2Pl8tyGqp8LBFwdb85zgdWNtUsw8QduRLtfdPcqYvdahHr1tQxzt26pZSU9tTDEkvrSud5b4K3ZKTmQKN1r6A30bwNFSV4ZzpKpi1xH6MWOVQ60YXhlasejS8yyr7+rF8jAtxKkbCrRJUxbfhiI9iHhbvalS51iXl/z/HPVWAmKWAMWErZ8e6g9lOsjOecnuvZxaK4xjCbx7Ky8XIOTAmgbqHxKwCTl+h7IGKH8cjszhGaQaQYDml9v2Vf4i9mtd3sKaguGUppIoTeDg6CCC2VobGYExJkHS73gc+2IM3EL/8quDorPzdKniqUzlovUgMFfygk2dAgMBAAECggEANQLAfRDIMWUdK9RDzA9Z8a7pp1jcszLVAPWWbUyLISwVnoPYo49qHGGkJKllj8MJl/0Fn/a/jS2T8LK5tnob+DRctl7coMBGubEpOAfoDrPYA/jbh8p69yi2oU4IOudW16EHy2r8gzrNSrex17+cha3ZCyp+EHPYrR+Qs7jLLRBT207xlF9lMBS2xFML5khydxpoQpaKnouZ8fc1g84HsDDM9RrCtuSmFzzypk1NJdggXVZM7G9yQY6lQY6R1ZUkgEM+mpEURGNHCZonFAE9+HKo37+yomCE4gw5Gcq4B615A+B2c5LKhy0nWSBv63X7rUcUMfGwezvCbxAaEfwofQKBgQDU5rGwOwJyHUlylGH+eZd//zHUaPbCQo6sMXOEV1GjK9Nwc33thyd0v6c71vNrTOG1Ys8PoirISWOOMziUIHkd0hQhmzdvelwx1c5cTuLKCmBHeTVtDDXy2jOYT2QiQDC7+3ANYJgKkP2xsT/nGMoaaDpJ+ctfXl0Z30t6wrNwGwKBgQDktsoA3ZlK19FpUC6Mm0NMXASKsZseCTQIrftft1cNRoK1oH7vqJEwCW1vCwrAlfjasR8ERGTjrPaIo16joX9AQk7ZET8Bn9IkYhs9BDXA+4ABLdGuUWvQpDeMT5m0var9ndf+IFiMT2bH00Nz122vSvf5jSYMLqWo3nBgTddEpwKBgQCILF4uuC+iSbU2wk3DdIZAaju2/sQGEIgs/xxB44/l7Bw7asN6791+wS74CU58rRoY6HBEMZdnr/krdPuVUwfk2P/jVuIoPX1GqthpFlPcorJeRNq1OwAuqv4hR3ZmqeQB+Jr9E3FsIL0DsLmM2MA8D7poootAHp0x9S7UAEDBTQKBgQCcvUwIddUk/mxsAOA1yf2/6dvO9NJ6LhJz1E/OE8ZbubPAJyJ2uY3uXreZfva6bszhirrX4MtHYHR/xX4JI5cigY6pofEM+us3teg205jHDVR2+mCVVwVNMg1DYhXTUJxLPI4WgTJNzeiBDx5N2Bg6JmV0py+o75rl9LMMvKvHRwKBgHYwUbhIDLoz7yeGu3yh+2ZXPVKJVgKEW5xpxULkbcCFb1mK2pKM2DvIVMW2X22Re7iM2afm8tNBbzD5zsYibql1SpRTYrS69x+hRlpQETcuiLhgtLA+3eG9uMh0yrU5em7Y3NF/TCq28SBr0N4gVm+HJ0wB2s9n3fRR0UBaCpBO";
Console.WriteLine("privateKey:" + privateKey);
Console.WriteLine("publicKey:" + publicKey);

Console.WriteLine("-----------------------------公钥加密 私钥解密--------使用分段加密----------------------------");
String encrypt = RsaUtil.RsaUtil.RsaEncrypt(publicKey, "8896");
//encrypt = "Nc42vCyaDcHsIuyzWzssDyuNUkWdh6r6495Kle9u/azy2YsR+6DmJfwoezfRiVD7t2AfWx8xi11V0zBYnv6WLxDDNS7jQNhONg+FbpvplR22Nlkamus2+ax7dNEMvtdyOy+iUjZDkIfexc9mgX3gCbaOgzkr+ABiOF4bg/lXUH4D/+XRdF9cYBeQ3RvRBli0mrky4bIHE7S4YDdkqmUipScgGNOsMU4HDN2eQPad4gHTWtShCWHSHecACwl+I1jdqhjChZQUucei0RGJTg4BWSpWIaRONBsnQBNRoeYFIV5dbN/WkBIH6fxbiTRjVg+peLugBwev7EBZqnzqhLZkLBi5srv3f0iJDNhXWCeyKMPKHcUE7AdaVssCQwEifQ1tw1E9SZXFhI+0XES77fmTu46BzhjGGie2TgfplAjLfxpYe18e2HjjTTBKoXnESIYhML6sbeOqesWG3RtZ5BEvWPxP6/UzMWoPQG/fdluXIJJLA/6kyG4S6WFTShG9ODSHk7LJJ+X396HozuIHnAAHfW6jxn5Tl+Fdln+YTqeZNpy/NZ01SpC4Dh8AZKFh1aKjUsULcfEawJMiOdbLRwjiAQiohaNxcG4s0xbno+Mx3/YhscMLj1pV/1GVhZujA1wZL+zuQjA/Lyn9PcdAkmKT726U7sSCDYB9ggd7RsIr67Y=";
Console.WriteLine("公钥密文:"+ encrypt);
string decrypt = RsaUtil.RsaUtil.RsaDecrypt(privateKey, encrypt);
Console.WriteLine("私钥明文："+decrypt);
Console.WriteLine("-----------------------------私钥加密 公钥解密---------使用分段加密---------------------------");
String encrypt1 = RsaUtil.RsaUtil.RsaPrivateEncrypt(privateKey, "8896");
Console.WriteLine("私钥密文:" + encrypt1);
string decrypt1 = RsaUtil.RsaUtil.RsaPublicDecrypt(publicKey, encrypt1);
Console.WriteLine("公钥明文：" + decrypt1);
Console.WriteLine("------------------------------签名 验签-----------------------------------");
string sign = RsaUtil.RsaUtil.RsaSign("8896", privateKey);
Console.WriteLine(sign);
bool b2 = RsaUtil.RsaUtil.RsaVerifySign("8896", sign, publicKey);
Console.WriteLine(b2);