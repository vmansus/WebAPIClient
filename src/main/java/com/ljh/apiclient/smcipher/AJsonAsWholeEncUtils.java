package com.ljh.apiclient.smcipher;

import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.serializer.SerializerFeature;
import com.ljh.apiclient.configeditor.CryptoConfigUtils;
import com.ljh.apiclient.gmhelper.SM2Util;
import com.ljh.apiclient.gmhelper.SM4Util;
import com.ljh.apiclient.gmhelper.cert.SM2X509CertMaker;
import com.ljh.apiclient.streamcipher.BCZuc;
import com.ljh.apiclient.streamcipher.RandomZucKeyGenerater;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class AJsonAsWholeEncUtils {
    static {
        Security.removeProvider("SunEC");
        Security.addProvider(new BouncyCastleProvider());
    }

//    private static final char[] TEST_P12_PASSWD="12345678".toCharArray();
//    private static final String TEST_P12_FILENAME="D:\\githuba\\apiclient\\src\\main\\resources\\clientkeystore.p12";
    private static AJsonAsWholeEncUtils instance=null;
    private Key keyEncryptKey=null;

    public AJsonAsWholeEncUtils(X509Certificate certificate) throws NoSuchProviderException, NoSuchAlgorithmException, IOException, URISyntaxException {
        keyEncryptKey=certificate.getPublicKey();
    }

    public  static AJsonAsWholeEncUtils getInstance(X509Certificate certificate) throws Exception{
        if (instance==null)return new AJsonAsWholeEncUtils(certificate);
        else return instance;
    }
    CryptoConfigUtils cryptoConfigUtils=new CryptoConfigUtils();
    int encalg=cryptoConfigUtils.getEncAlg();
    byte[] sm4key=SM4Util.generateKey();
    String zuckey=new RandomZucKeyGenerater().makeKey();

    public String stringEncrypt(String text) throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidKeyException, UnsupportedEncodingException {
        if (encalg==0){
            byte[] iv=Base64.getDecoder().decode(stringToBytes("LvbTKayS1A2NFFBjaPvkJg=="));
            byte[] srcdata=text.getBytes();
            byte[] cipherText= SM4Util.encrypt_CBC_Padding(sm4key,iv,srcdata);
            String ss=bytesToString(Base64.getEncoder().encode(cipherText));
            return ss;
        }else if(encalg==1){
            String res=new BCZuc().stringEncCipher(text,zuckey);
            return res;
        }else {
            System.out.println("请检查对称加密配置!!!");
            return null;
        }
    }

    public String stringSign(String text, String keystoretype,char[] password,String dest,String alias) throws Exception {
        KeyStore ks = KeyStore.getInstance(keystoretype, "BC");
        try (InputStream is = Files.newInputStream(Paths.get(dest),
                StandardOpenOption.READ)) {
            ks.load(is, password);
        }
        PrivateKey privateKey=(BCECPrivateKey)ks.getKey(alias,password);

        byte[] srcData = text.getBytes();
        Signature sign = Signature.getInstance(SM2X509CertMaker.SIGN_ALGO_SM3WITHSM2, "BC");
        sign.initSign(privateKey);
        sign.update(srcData);
        byte[] signatureValue = sign.sign();

        return bytesToString(Base64.getEncoder().encode(signatureValue));
    }

    public static String Sm2Enc(byte[] srcData,Key publickey) throws InvalidCipherTextException {
        byte[] ciperdata= SM2Util.encrypt((BCECPublicKey) publickey,srcData);
        String ss=bytesToString(Base64.getEncoder().encode(ciperdata));
        return ss;
    }


    public Certificate[] getCerts(String keystoretype,char[] password,String dest,String alias) throws Exception{
        KeyStore ks = KeyStore.getInstance(keystoretype, "BC");
        try (InputStream is = Files.newInputStream(Paths.get(dest),
                StandardOpenOption.READ)) {
            ks.load(is, password);
        }
        Certificate[] certificates=ks.getCertificateChain(alias);
        return certificates;

    }

    public static byte[] stringToBytes(String str) {
        try {
            // 使用指定的字符集将此字符串编码为byte序列并存到一个byte数组中
            return str.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String bytesToString(byte[] bs) {
        try {
            // 通过指定的字符集解码指定的byte数组并构造一个新的字符串
            return new String(bs, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null;
    }

    public String  jsonEncrypt(String json,String keystoretype,char[] password,String dest,String keyname,String alias) throws Exception {
        JSONObject js=JSONObject.parseObject(json);
        String jsstr=JSONObject.toJSONString(js, SerializerFeature.SortField.MapSortField);
        String encryptedJsonString=stringEncrypt(jsstr);
        String encryptkey = null;
        try {
            if (encalg == 0) {
                encryptkey = Sm2Enc(sm4key,keyEncryptKey);
            }else if(encalg==1){
                byte[] zuckeybytes=stringToBytes(zuckey);
                encryptkey=Sm2Enc(zuckeybytes,keyEncryptKey);
            }else {
                System.out.println("请检查对称加密配置!!!");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        String signValue=stringSign(jsstr,keystoretype,password,dest,alias);
        JSONObject jsonObject=new JSONObject();
        jsonObject.put("Protected",encryptedJsonString);
        jsonObject.put("Encrypted_Key",encryptkey);
        jsonObject.put("KeyName",keyname);
        jsonObject.put("Signature",signValue);

        JSONObject jsonChainCert=new JSONObject();
        for (int i=0;i<getCerts(keystoretype,password,dest,alias).length;i++){
            jsonChainCert.put(String.valueOf(i),bytesToString(Base64.getEncoder().encode(getCerts(keystoretype,password,dest,alias)[i].getEncoded())));
        }
//                    X509Certificate cert= (X509Certificate) getCerts(alias)[0];
        jsonObject.put("Certs",jsonChainCert);

        String result=JSONObject.toJSONString(jsonObject, SerializerFeature.SortField.MapSortField);
        return result;

    }

    public String  jsonEncrypt1(String json,String keyname) throws Exception {
        String encryptedJsonString=stringEncrypt(json);
        String encryptkey = null;
        try {
            if (encalg == 0) {
                encryptkey = Sm2Enc(sm4key,keyEncryptKey);
            }else if(encalg==1){
                byte[] zuckeybytes=stringToBytes(zuckey);
                encryptkey=Sm2Enc(zuckeybytes,keyEncryptKey);
            }else {
                System.out.println("请检查对称加密配置!!!");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        JSONObject jsonObject=new JSONObject();
        jsonObject.put("Protected",encryptedJsonString);
        jsonObject.put("Encrypted_Key",encryptkey);
        jsonObject.put("KeyName",keyname);

        String result=JSONObject.toJSONString(jsonObject, SerializerFeature.SortField.MapSortField);
        return result;

    }

    public String  jsonEncrypt2(String json,String keystoretype,char[] password,String dest,String alias) throws Exception {
        JSONObject js=JSONObject.parseObject(json);
        String jsstr=JSONObject.toJSONString(js, SerializerFeature.SortField.MapSortField);
        String signValue=stringSign(jsstr,keystoretype,password,dest,alias);
        JSONObject jsonObject=new JSONObject();
        jsonObject.put("Signature",signValue);
        jsonObject.put("Protected",js);
        JSONObject jsonChainCert=new JSONObject();
        for (int i=0;i<getCerts(keystoretype,password,dest,alias).length;i++){
            jsonChainCert.put(String.valueOf(i),bytesToString(Base64.getEncoder().encode(getCerts(keystoretype,password,dest,alias)[i].getEncoded())));
        }
        jsonObject.put("Certs",jsonChainCert);

        String result=JSONObject.toJSONString(jsonObject, SerializerFeature.SortField.MapSortField);
        return result;
    }



}
