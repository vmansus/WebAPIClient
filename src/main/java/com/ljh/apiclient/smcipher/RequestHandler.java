package com.ljh.apiclient.smcipher;

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


        Properties properties=new Properties();
        BufferedReader bufferedReader=new BufferedReader(new FileReader("D:\\githuba\\apiclient\\src\\main\\resources\\application.properties"));
        properties.load(bufferedReader);
        int mode= Integer.parseInt(properties.getProperty("workmode"));

        if(mode==0){
            requestBody= JsonUtils.getInstance(cert).jsonEncrypt(requestBody,keyname,signkey);
        }else if(mode==1){
            requestBody= JsonUtils.getInstance(cert).jsonEncryptmode1(requestBody,keyname,signkey);
        }else if(mode==2){
            requestBody= JsonUtils.getInstance(cert).jsonEncryptmode2(requestBody,keyname,signkey);
        }

        return requestBody;
    }



    public String decResponse(String responseBody) throws Exception {
        Properties properties=new Properties();
        BufferedReader bufferedReader=new BufferedReader(new FileReader("D:\\githuba\\apiclient\\src\\main\\resources\\application.properties"));
        properties.load(bufferedReader);
        int mode= Integer.parseInt(properties.getProperty("workmode"));
        if(mode==0){
            responseBody= new JsonDecryptUtils().jsonDecrypt(responseBody);
        }else if(mode==1){
            responseBody= new JsonDecryptUtils().jsonDecryptmode1(responseBody);
        }else if(mode==2){
            responseBody= new JsonDecryptUtils().jsonDecryptmode2(responseBody);
        }

        return responseBody;
    }



}
