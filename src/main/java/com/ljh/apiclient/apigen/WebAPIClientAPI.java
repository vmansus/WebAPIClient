package com.ljh.apiclient.apigen;

import com.alibaba.fastjson.JSONObject;
import com.ljh.apiclient.configeditor.CryptoConfigUtils;
import com.ljh.apiclient.smcipher.RequestHandler;

public class WebAPIClientAPI {

    public JSONObject encJson(JSONObject jsonObject,String encCert,String signCert) throws Exception {
        String keyStoreType=new CryptoConfigUtils().getKeyStoreType();
        String keyStorePassword=new CryptoConfigUtils().getKeyStorePassword();
        String keyStoreDest=new CryptoConfigUtils().getKeyStoreDest();
        char[] password=keyStorePassword.toCharArray();
        String jsonstr=jsonObject.toJSONString();
        String resStr= new RequestHandler().encRequest(jsonstr,keyStoreType,password,keyStoreDest,encCert,signCert);
        JSONObject resJson=JSONObject.parseObject(resStr);
        return resJson;
    }

    public String encJsonStr(String jsonStr, String encCert, String signCert) throws Exception {
        String keyStoreType=new CryptoConfigUtils().getKeyStoreType();
        String keyStorePassword=new CryptoConfigUtils().getKeyStorePassword();
        String keyStoreDest=new CryptoConfigUtils().getKeyStoreDest();
        char[] password=keyStorePassword.toCharArray();
        String resStr= new RequestHandler().encRequest(jsonStr,keyStoreType,password,keyStoreDest,encCert,signCert);
        return resStr;
    }

    public JSONObject decJson(JSONObject jsonObject) throws Exception {
        String keyStoreType=new CryptoConfigUtils().getKeyStoreType();
        String keyStorePassword=new CryptoConfigUtils().getKeyStorePassword();
        String keyStoreDest=new CryptoConfigUtils().getKeyStoreDest();
        char[] password=keyStorePassword.toCharArray();
        String jsonstr=jsonObject.toJSONString();
        String resStr=new RequestHandler().decResponse(jsonstr,keyStoreType,password,keyStoreDest);
        JSONObject resJson=JSONObject.parseObject(resStr);
        return resJson;
    }

    public String decJsonStr(String jsonStr) throws Exception{
        String keyStoreType=new CryptoConfigUtils().getKeyStoreType();
        String keyStorePassword=new CryptoConfigUtils().getKeyStorePassword();
        String keyStoreDest=new CryptoConfigUtils().getKeyStoreDest();
        char[] password=keyStorePassword.toCharArray();
        String resStr=new RequestHandler().decResponse(jsonStr,keyStoreType,password,keyStoreDest);
        return resStr;

    }
}
