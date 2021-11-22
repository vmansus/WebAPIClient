package com.ljh.apiclient.smcipher;

import io.swagger.models.auth.In;
import org.springframework.beans.factory.annotation.Value;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.Properties;


public class RequestHandler {



//    int mode=Integer.parseInt(properties)
//    @Value("${workmode}")
//    int mode;

    public String encRequest(String requestBody) throws IOException {
        Properties properties=new Properties();
        BufferedReader bufferedReader=new BufferedReader(new FileReader("D:\\githuba\\apiclient\\src\\main\\resources\\application.properties"));
        properties.load(bufferedReader);
        int mode= Integer.parseInt(properties.getProperty("workmode"));

        if(mode==0){
            requestBody= new JsonUtils().jsonEncrypt(requestBody);
        }else if(mode==1){
            requestBody= new JsonUtils().jsonEncryptmode1(requestBody);
        }else if(mode==2){
            requestBody= new JsonUtils().jsonEncryptmode2(requestBody);
        }

        return requestBody;
    }



    public String decResponse(String responseBody) throws IOException {
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
