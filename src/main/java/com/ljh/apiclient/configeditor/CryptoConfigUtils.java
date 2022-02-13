package com.ljh.apiclient.configeditor;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

public class CryptoConfigUtils {

    public static Properties getProperties() throws IOException {
        Properties properties=new Properties();
        BufferedReader bufferedReader=new BufferedReader(new FileReader("D:\\githuba\\apiclient\\src\\main\\resources\\CryptoConfig.properties"));
        properties.load(bufferedReader);
//        int mode= Integer.parseInt(properties.getProperty("workmode"));
        return properties;
    }

    public int getWorkMode() throws IOException {
        Properties properties=getProperties();
        int mode= Integer.parseInt(properties.getProperty("workmode"));
        return mode;
    }

    public int getIsWhole() throws IOException {
        Properties properties=getProperties();
        int mode= Integer.parseInt(properties.getProperty("isWhole"));
        return mode;
    }

    public int getEncAlg() throws IOException {
        Properties properties=getProperties();
        int mode= Integer.parseInt(properties.getProperty("encAlg"));
        return mode;
    }

    public List<String> getRequestEncParms() throws IOException {
        Properties properties=getProperties();
        String requestEnc=properties.getProperty("requestEnc");
        String[] strings=requestEnc.split("\\s+");
        List<String> stringList=new ArrayList<>();
        for (String s:strings){
//            String m=s.substring(0,1).toUpperCase()+s.substring(1);
            stringList.add(s);
        }
        return stringList;
    }

    public List<String> getRequestSignParms() throws IOException {
        Properties properties=getProperties();
        String requestEnc=properties.getProperty("requestSign");
        String[] strings=requestEnc.split("\\s+");
        List<String> stringList=new ArrayList<>();
        for (String s:strings){
//            String m=s.substring(0,1).toUpperCase()+s.substring(1);
            stringList.add(s);
        }
        return stringList;
    }

    public List<String> getResponseEncParms() throws IOException {
        Properties properties=getProperties();
        String requestEnc=properties.getProperty("responseEnc");
        String[] strings=requestEnc.split("\\s+");
        List<String> stringList=new ArrayList<>();
        for (String s:strings){
//            String m=s.substring(0,1).toUpperCase()+s.substring(1);
            stringList.add(s);
        }
        return stringList;
    }

    public List<String> getResponseSignParms() throws IOException {
        Properties properties=getProperties();
        String requestEnc=properties.getProperty("responseSign");
        String[] strings=requestEnc.split("\\s+");
        List<String> stringList=new ArrayList<>();
        for (String s:strings){
//            String m=s.substring(0,1).toUpperCase()+s.substring(1);
            stringList.add(s);
        }
        return stringList;
    }

}