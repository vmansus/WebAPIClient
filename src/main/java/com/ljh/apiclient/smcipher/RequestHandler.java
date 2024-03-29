package com.ljh.apiclient.smcipher;

import com.ljh.apiclient.configeditor.CryptoConfigUtils;
import io.swagger.models.auth.In;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Value;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Properties;


public class RequestHandler {

    static {
        Security.removeProvider("SunEC");
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final char[] TEST_P12_PASSWD="12345678".toCharArray();
    private static final String TEST_P12_FILENAME="D:\\githuba\\apiclient\\src\\main\\resources\\clientkeystore.p12";


    public String encRequest(String requestBody,String encryptCert,String signkey) throws Exception {
        //keyname即加密所用证书DN
        String keyname;
        KeyStore ks=KeyStore.getInstance("PKCS12","BC");
        try(InputStream is= Files.newInputStream(Paths.get(TEST_P12_FILENAME), StandardOpenOption.READ)){
            ks.load(is,TEST_P12_PASSWD);
        }
        X509Certificate cert= (X509Certificate) ks.getCertificate(encryptCert);
        keyname=cert.getSubjectDN().toString();


//        Properties properties=new Properties();
//        BufferedReader bufferedReader=new BufferedReader(new FileReader("D:\\githuba\\apiclient\\src\\main\\resources\\application.properties"));
//        properties.load(bufferedReader);
//        int mode= Integer.parseInt(properties.getProperty("workmode"));
//        int isWhole= Integer.parseInt(properties.getProperty("isWhole"));
        CryptoConfigUtils cryptoConfigUtils=new CryptoConfigUtils();
        int mode= cryptoConfigUtils.getWorkMode();
        int isWhole= cryptoConfigUtils.getIsWhole();

        if (isWhole==0){
            if(mode==0){
                requestBody= JsonUtils.getInstance(cert).jsonEncrypt(requestBody,keyname,signkey);
            }else if(mode==1){
                requestBody= JsonUtils.getInstance(cert).jsonEncryptmode1(requestBody,keyname,signkey);
            }else if(mode==2){
                requestBody= JsonUtils.getInstance(cert).jsonEncryptmode2(requestBody,keyname,signkey);
            }
        }else if(isWhole==1){
            if(mode==0){
                requestBody= JsonAsWholeEncUtils.getInstance(cert).jsonEncrypt(requestBody,keyname,signkey);
            }else if(mode==1){
                requestBody= JsonAsWholeEncUtils.getInstance(cert).jsonEncrypt1(requestBody,keyname,signkey);
            }else if(mode==2){
                requestBody= JsonAsWholeEncUtils.getInstance(cert).jsonEncrypt2(requestBody,keyname,signkey);
            }
        }

        return requestBody;
    }

    public String encRequest(String requestBody,String keystoretype,char[] password,String dest,String encryptCert,String signkey) throws Exception {

        //keyname即加密所用证书DN
        String keyname;
        KeyStore ks=KeyStore.getInstance(keystoretype,"BC");
        try(InputStream is= Files.newInputStream(Paths.get(dest), StandardOpenOption.READ)){
            ks.load(is,password);
        }
        X509Certificate cert= (X509Certificate) ks.getCertificate(encryptCert);
        keyname=cert.getSubjectDN().toString();


//        Properties properties=new Properties();
//        BufferedReader bufferedReader=new BufferedReader(new FileReader("D:\\githuba\\apiclient\\src\\main\\resources\\application.properties"));
//        properties.load(bufferedReader);
//        int mode= Integer.parseInt(properties.getProperty("workmode"));
//        int isWhole= Integer.parseInt(properties.getProperty("isWhole"));
        CryptoConfigUtils cryptoConfigUtils=new CryptoConfigUtils();
        int mode= cryptoConfigUtils.getWorkMode();
        int isWhole= cryptoConfigUtils.getIsWhole();

        if (isWhole==0){
            if(mode==0){
                requestBody= AJsonUtils.getInstance(cert).jsonEncrypt(requestBody,keystoretype,password,dest,keyname,signkey);
            }else if(mode==1){
                requestBody= AJsonUtils.getInstance(cert).jsonEncryptmode1(requestBody,keystoretype,password,dest,keyname);
            }else if(mode==2){
                requestBody= AJsonUtils.getInstance(cert).jsonEncryptmode2(requestBody,keystoretype,password,dest,signkey);
            }
        }else if(isWhole==1){
            if(mode==0){
                requestBody= AJsonAsWholeEncUtils.getInstance(cert).jsonEncrypt(requestBody,keystoretype,password,dest,keyname,signkey);
            }else if(mode==1){
                requestBody= AJsonAsWholeEncUtils.getInstance(cert).jsonEncrypt1(requestBody,keyname);
            }else if(mode==2){
                requestBody= AJsonAsWholeEncUtils.getInstance(cert).jsonEncrypt2(requestBody,keystoretype,password,dest,signkey);
            }
        }

        return requestBody;
    }



    public String decResponse(String responseBody) throws Exception {
//        Properties properties=new Properties();
//        BufferedReader bufferedReader=new BufferedReader(new FileReader("D:\\githuba\\apiclient\\src\\main\\resources\\application.properties"));
//        properties.load(bufferedReader);
//        int mode= Integer.parseInt(properties.getProperty("workmode"));
//        int isWhole= Integer.parseInt(properties.getProperty("isWhole"));
        CryptoConfigUtils cryptoConfigUtils=new CryptoConfigUtils();
        int mode= cryptoConfigUtils.getWorkMode();
        int isWhole= cryptoConfigUtils.getIsWhole();

        if (isWhole==0){
            if(mode==0){
                responseBody= new JsonDecryptUtils().jsonDecrypt(responseBody);
            }else if(mode==1){
                responseBody= new JsonDecryptUtils().jsonDecryptmode1(responseBody);
            }else if(mode==2){
                responseBody= new JsonDecryptUtils().jsonDecryptmode2(responseBody);
            }
        }else if(isWhole==1){
            if(mode==0){
                responseBody= new JsonAsWholeDecUtils().jsonDecrypt(responseBody);
            }else if(mode==1){
                responseBody= new JsonAsWholeDecUtils().jsonDecrypt1(responseBody);
            }else if(mode==2){
                responseBody= new JsonAsWholeDecUtils().jsonDecrypt2(responseBody);
            }
        }


        return responseBody;
    }

    public String decResponse(String responseBody,String keystoretype,char[] password,String dest) throws Exception {
//        Properties properties=new Properties();
//        BufferedReader bufferedReader=new BufferedReader(new FileReader("D:\\githuba\\apiclient\\src\\main\\resources\\application.properties"));
//        properties.load(bufferedReader);
//        int mode= Integer.parseInt(properties.getProperty("workmode"));
//        int isWhole= Integer.parseInt(properties.getProperty("isWhole"));
        CryptoConfigUtils cryptoConfigUtils=new CryptoConfigUtils();
        int mode= cryptoConfigUtils.getWorkMode();
        int isWhole= cryptoConfigUtils.getIsWhole();

        if (isWhole==0){
            if(mode==0){
                responseBody= new AJsonDecryptUtils().jsonDecrypt(responseBody,keystoretype,password,dest);
            }else if(mode==1){
                responseBody= new AJsonDecryptUtils().jsonDecryptmode1(responseBody,keystoretype,password,dest);
            }else if(mode==2){
                responseBody= new AJsonDecryptUtils().jsonDecryptmode2(responseBody);
            }
        }else if(isWhole==1){
            if(mode==0){
                responseBody= new AJsonAsWholeDecUtils().jsonDecrypt(responseBody,keystoretype,password,dest);
            }else if(mode==1){
                responseBody= new AJsonAsWholeDecUtils().jsonDecrypt1(responseBody,keystoretype,password,dest);
            }else if(mode==2){
                responseBody= new AJsonAsWholeDecUtils().jsonDecrypt2(responseBody);
            }
        }


        return responseBody;
    }


}
