package com.ljh.apiclient.configeditor;

import java.io.*;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

public class CryptoConfigUtils {

    public Properties getProperties() throws IOException, URISyntaxException {
        URL apiconfigurl = this.getClass().getClassLoader().getResource("ApiConfig.properties");
        File apiconfigfile = Paths.get(apiconfigurl.toURI()).toFile();
        Reader reader=new FileReader(apiconfigfile);
        Properties properties2=new Properties();
        properties2.load(reader);
        String path=properties2.getProperty("configFilePath");

        Properties properties=new Properties();
        BufferedReader bufferedReader=new BufferedReader(new FileReader(path+"\\CryptoConfig.properties"));
        properties.load(bufferedReader);
//        int mode= Integer.parseInt(properties.getProperty("workmode"));
        return properties;
    }

    public int getWorkMode() throws IOException, URISyntaxException {
        Properties properties=getProperties();
        int mode= Integer.parseInt(properties.getProperty("workmode"));
        return mode;
    }

    public int getIsWhole() throws IOException, URISyntaxException {
        Properties properties=getProperties();
        int mode= Integer.parseInt(properties.getProperty("isWhole"));
        return mode;
    }

    public int getEncAlg() throws IOException, URISyntaxException {
        Properties properties=getProperties();
        int mode= Integer.parseInt(properties.getProperty("encAlg"));
        return mode;
    }

    public List<String> getRequestEncParms() throws IOException, URISyntaxException {
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

    public List<String> getRequestSignParms() throws IOException, URISyntaxException {
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

    public List<String> getResponseEncParms() throws IOException, URISyntaxException {
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

    public List<String> getResponseSignParms() throws IOException, URISyntaxException {
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
    public String getKeyStoreType() throws Exception{
        Properties properties=getProperties();
        String keystoreType=properties.getProperty("keystoreType");
        return keystoreType;
    }

    public String getKeyStorePassword() throws Exception{
        Properties properties=getProperties();
        String keystorePassword=properties.getProperty("keystorePassword");
        return keystorePassword;
    }

    public String getKeyStoreDest() throws Exception{
        Properties properties=getProperties();
        String keystoreDest=properties.getProperty("keystoreDest");
        return keystoreDest;
    }

}