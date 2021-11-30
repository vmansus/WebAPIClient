package com.ljh.apiclient.smcipher;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.JSONValidator;
import com.alibaba.fastjson.serializer.SerializerFeature;
import com.ljh.apiclient.gmhelper.SM2Util;
import com.ljh.apiclient.gmhelper.SM4Util;
import com.ljh.apiclient.gmhelper.cert.SM2X509CertMaker;
import lombok.var;
import org.apache.commons.lang.StringEscapeUtils;
import org.apache.commons.lang.StringUtils;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Component;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

@Component
public class JsonDecryptUtils {

    static {
        Security.removeProvider("SunEC");
        Security.addProvider(new BouncyCastleProvider());
    }
    private static final char[] TEST_P12_PASSWD="12345678".toCharArray();
    private static final String TEST_P12_FILENAME="D:\\githuba\\apiclient\\src\\main\\resources\\clientkeystore.p12";






    byte[] sm4key = null;

    // 需要加密的日志节点
//    HashMap<String, List<String>> encryptNodeMap = new HashMap<String, List<String>>();
    // 需要加密的日志节点
    NodeMap nodeMap=new NodeMap();
    Map<String, List<String>> encryptNodeMap=nodeMap.encryptNodeMap();
    List<String> signNodelist=nodeMap.signNodelist();
    public Map<String, Object> signvaluemap=new HashMap<>();


    public static byte[] Sm2Dec(String text, PrivateKey privateKey) throws InvalidCipherTextException {
        byte[] aa=Base64.getDecoder().decode(stringToBytes(text));
        byte[] decryptdata= SM2Util.decrypt((BCECPrivateKey)privateKey,aa);
        return decryptdata;
    }


    public boolean validate(String text,String signaturevalue,X509Certificate cert) throws Exception {
        byte[] temp=Base64.getDecoder().decode(stringToBytes(signaturevalue));
        byte[] srcData=stringToBytes(text);
        Signature verify = Signature.getInstance(SM2X509CertMaker.SIGN_ALGO_SM3WITHSM2, "BC");
        verify.initVerify(cert);
        verify.update(srcData);
        return verify.verify(temp);
    }


    public PrivateKey getPrivateKey(String keyname) throws Exception{
        PrivateKey privateKey = null;
        KeyStore ks=KeyStore.getInstance("PKCS12","BC");
        try(InputStream is= Files.newInputStream(Paths.get(TEST_P12_FILENAME), StandardOpenOption.READ)){
            ks.load(is,TEST_P12_PASSWD);
        }
        Enumeration<String> alias=ks.aliases();
        while (alias.hasMoreElements()){
            String aliass=alias.nextElement();
            java.security.cert.Certificate cert1=ks.getCertificateChain(aliass)[0];
            X509Certificate cert= (X509Certificate) cert1;
            if(cert.getSubjectDN().toString().equals(keyname)&&ks.getKey(aliass,TEST_P12_PASSWD)!=null){
                privateKey=(PrivateKey)ks.getKey(aliass,TEST_P12_PASSWD);
                break;
            }
        }

        return privateKey;

    }



    public String jsonDecrypt(String json) throws Exception{


//        PrivateKey privateKey= (PrivateKey) ks.getKey("server cert",TEST_P12_PASSWD);

        boolean checksign=true;
        String json2 = "";
        String jsonStr="";
        try {
            if (!StringUtils.isBlank(json)) {
                JSONObject jsonObject = JSON.parseObject(json);
                String encryptkey=jsonObject.getString("encryptkey");
                String KeyName=jsonObject.getString("KeyName");

                String certString=jsonObject.getString("Cert");
                byte[] certbcytes=Base64.getDecoder().decode(stringToBytes(certString));
                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                java.security.cert.Certificate cert = certFactory.generateCertificate(new ByteArrayInputStream(certbcytes));
                X509Certificate x509Certificate= (X509Certificate) cert;

                PrivateKey privateKey=getPrivateKey(KeyName);



                Map<Object,Object>  signature= (Map<Object, Object>) jsonObject.get("Signature");
                jsonObject.remove("Signature");
                jsonObject.remove("Cert");
                String json1=jsonObject.toJSONString();
                // 使用SM2算法将随机生成的SM4key解密
                byte[] thekey = null;
                try {
                    thekey= Sm2Dec(encryptkey,privateKey);
                    this.sm4key=thekey;
                } catch (Exception e) {
                    e.printStackTrace();
                }

                for (String key :  encryptNodeMap.keySet()){
//                    System.out.println(encryptNodeMap.get(key));
                    Object output = GetAesJToken(JSON.parseObject(json1.trim()), encryptNodeMap.get(key));
                    JSONObject jsonObject1 =  (JSONObject) JSON.toJSON(output);
                    jsonObject1.remove("encryptkey");
                    jsonObject1.remove("KeyName");
                    String result=JSONObject.toJSONString(jsonObject1, SerializerFeature.SortField.MapSortField,SerializerFeature.DisableCheckSpecialChar);

                    jsonStr = StringEscapeUtils.unescapeJavaScript(result);

                    for (int i = 0; i < jsonStr.length()-1; i++) {
                        if (jsonStr.charAt(i) =='"' && jsonStr.charAt(i+1) =='{'  ) {
                            jsonStr=removeCharAt(jsonStr,i);
                        }else if(jsonStr.charAt(i) =='}' && jsonStr.charAt(i+1) =='"'){
                            jsonStr=removeCharAt(jsonStr,i+1);
                        }
                    }

                }
                GetSignvalue(JSON.parseObject(jsonStr.trim()),signNodelist);
                //1、迭代器
                Iterator<Map.Entry<String, Object>> iter = signvaluemap.entrySet().iterator();
                //判断往下还有没有数据
                while(iter.hasNext()){
                    //有的话取出下面的数据
                    Map.Entry<String, Object> entry = iter.next();
                    Object data = entry.getKey();
                    String signvalue = (String)entry.getValue();
                    String sign= (String) signature.get(data);
                    boolean b = validate(signvalue,sign,x509Certificate);
//                    System.out.println(b);
                    if (!b){
                        checksign=false;
                        System.out.println(data+"验签失败");
                    }
                }


            }
        } catch (Exception e) {
            String output = "json解密异常:" + e.getMessage() + "解密前信息：" + json;
            jsonStr=output;

        }
        System.out.println("验签结果:"+checksign+"\n");
        return jsonStr;

    }

    public String jsonDecryptmode1(String json) throws Exception {
        boolean checksign=true;
        String json2 = "";
        String jsonStr="";
        try {
            if (!StringUtils.isBlank(json)) {
                JSONObject jsonObject = JSON.parseObject(json);
                String encryptkey=jsonObject.getString("encryptkey");
                String KeyName=jsonObject.getString("KeyName");
                PrivateKey privateKey=getPrivateKey(KeyName);
                String json1=jsonObject.toJSONString();
                // 使用SM2算法将随机生成的SM4key解密
                byte[] thekey = null;
                try {
                    thekey= Sm2Dec(encryptkey,privateKey);
                    this.sm4key=thekey;
                } catch (Exception e) {
                    e.printStackTrace();
                }

                for (String key :  encryptNodeMap.keySet()){
//                    System.out.println(encryptNodeMap.get(key));
                    Object output = GetAesJToken(JSON.parseObject(json1.trim()), encryptNodeMap.get(key));
                    JSONObject jsonObject1 =  (JSONObject) JSON.toJSON(output);
                    jsonObject1.remove("encryptkey");
                    jsonObject1.remove("KeyName");
                    String result=JSONObject.toJSONString(jsonObject1, SerializerFeature.SortField.MapSortField,SerializerFeature.DisableCheckSpecialChar);

                    jsonStr = StringEscapeUtils.unescapeJavaScript(result);

                    for (int i = 0; i < jsonStr.length()-1; i++) {
                        if (jsonStr.charAt(i) =='"' && jsonStr.charAt(i+1) =='{'  ) {
                            jsonStr=removeCharAt(jsonStr,i);
                        }else if(jsonStr.charAt(i) =='}' && jsonStr.charAt(i+1) =='"'){
                            jsonStr=removeCharAt(jsonStr,i+1);
                        }
                    }
//                    System.out.println(jsonStr+"11111");

                }



            }
        } catch (Exception e) {
            String output = "json解密异常:" + e.getMessage() + "解密前信息：" + json;
            jsonStr=output;

        }
//        System.out.println(checksign);
        return jsonStr;

    }

    public String jsonDecryptmode2(String json){
        boolean checksign=true;
        String json2 = "";
        String jsonStr="";
        try {
            if (!StringUtils.isBlank(json)) {
                JSONObject jsonObject = JSON.parseObject(json);

                String certString=jsonObject.getString("Cert");
                byte[] certbcytes=Base64.getDecoder().decode(stringToBytes(certString));
                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                Certificate cert = certFactory.generateCertificate(new ByteArrayInputStream(certbcytes));
                X509Certificate x509Certificate= (X509Certificate) cert;

//                String encryptkey=jsonObject.getString("encryptkey");
                Map<Object,Object>  signature= (Map<Object, Object>) jsonObject.get("Signature");
                jsonObject.remove("Signature");
                jsonObject.remove("Cert");
//                jsonObject.remove("encryptkey");
//                jsonStr=jsonObject.toJSONString();
                // 使用SM2算法将随机生成的SM4key解密
//                String thekey = null;
//                try {
//                    thekey= SM2test.SM2Dec(privateKey,encryptkey);
//                    this.sm4key=thekey;
//                } catch (Exception e) {
//                    e.printStackTrace();
//                }

//                for (String key :  encryptNodeMap.keySet()){
//                    System.out.println(encryptNodeMap.get(key));
//                    Object output = GetAesJToken(JSON.parseObject(json1.trim()), encryptNodeMap.get(key));
//                    JSONObject jsonObject1 =  (JSONObject) JSON.toJSON(output);
//                    jsonObject1.remove("encryptkey");
                String result=JSONObject.toJSONString(jsonObject, SerializerFeature.SortField.MapSortField,SerializerFeature.DisableCheckSpecialChar);
//
                jsonStr = StringEscapeUtils.unescapeJavaScript(result);
//
                for (int i = 0; i < jsonStr.length()-1; i++) {
                    if (jsonStr.charAt(i) =='"' && jsonStr.charAt(i+1) =='{'  ) {
                        jsonStr=removeCharAt(jsonStr,i);
                    }else if(jsonStr.charAt(i) =='}' && jsonStr.charAt(i+1) =='"'){
                        jsonStr=removeCharAt(jsonStr,i+1);
                    }
                }
//                    System.out.println(jsonStr+"11111");
//
//                }
                GetSignvalue(JSON.parseObject(jsonStr.trim()),signNodelist);
                //1、迭代器
                Iterator<Map.Entry<String, Object>> iter = signvaluemap.entrySet().iterator();
                //判断往下还有没有数据
                while(iter.hasNext()){
                    //有的话取出下面的数据
                    Map.Entry<String, Object> entry = iter.next();
                    Object data = entry.getKey();
                    String signvalue = (String)entry.getValue();
                    String sign= (String) signature.get(data);
                    boolean b = validate(signvalue,sign,x509Certificate);
//                    System.out.println(b);
                    if (!b){
                        checksign=false;
                        System.out.println(data+"验签失败");
                    }
                }


            }
        } catch (Exception e) {
            String output = "json解密异常:" + e.getMessage() + "解密前信息：" + json;
            jsonStr=output;

        }
        System.out.println("验签结果:"+checksign+"\n");
        return jsonStr;

    }
    /**
     * 文本解密（忽略异常）
     *
     * @param text 入参
     * @return 解密字符串
     */
    public String stringDecrypt(String text) throws BadPaddingException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchProviderException, InvalidKeyException {
        byte[] cipherdata=stringToBytes(text);
        byte[] iv=Base64.getDecoder().decode(stringToBytes("LvbTKayS1A2NFFBjaPvkJg=="));
        byte[] decryptedData= SM4Util.decrypt_CBC_Padding(sm4key,iv,Base64.getDecoder().decode(cipherdata));
        return bytesToString(decryptedData);
    }

    public static String removeCharAt(String s, int pos) {
        return s.substring(0, pos) + s.substring(pos + 1);
    }

    /**
     * 根据节点逐一展开json对象并进行解密
     *
     * @param object   入参
     * @param nodeList 入参
     * @return 结果
     */
    private Object GetAesJToken(Object object, List<String> nodeList) throws BadPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchProviderException, InvalidKeyException {
        // 如果为空，直接返回
        if (object == null || nodeList.size() == 0) return object;
        JSONObject jsonObject = null;
        // 多层节点递归展开，单层节点直接解密
        Map<String, List<String>> deepLevelNodes = new HashMap<>();
        for (var node : nodeList) {
            var nodeArr = Arrays.asList(node.split("\\."));
            if (nodeArr.size() > 1) {
                if (deepLevelNodes.containsKey(nodeArr.get(0)))
                    deepLevelNodes.get(nodeArr.get(0)).add(com.ctrip.framework.apollo.core.utils.StringUtils.join(nodeArr.subList(1, nodeArr.size()), "."));
                else
                    deepLevelNodes.put(nodeArr.get(0), new ArrayList<>(Arrays.asList(com.ctrip.framework.apollo.core.utils.StringUtils.join(nodeArr.subList(1, nodeArr.size()), "."))));
            } else {
                object = AesNodeToJson(object, node);
            }
        }
        if (deepLevelNodes.size() > 0) {
            for (String key : deepLevelNodes.keySet()) {
                //JSONValidator validator = JSONValidator.from(x);
                if (JSONValidator.from(object.toString()).getType()==JSONValidator.Type.Object
                    //JSON.isValidObject(object.toString())
                ) {
                    var jObject = JSON.parseObject(object.toString());
                    if (jObject.get(key) != null) {
                        jObject.put(key, GetAesJToken(jObject.get(key), deepLevelNodes.get(key)));
                    }
                    object = jObject;
                }
                if (JSONValidator.from(object.toString()).getType()==JSONValidator.Type.Array
                    //JSON.isValidArray(object.toString())
                ) {
                    var jArray = JSON.parseArray(object.toString());
                    for (int i = 0; i < jArray.size(); i++) {
                        JSONObject curObject = jArray.getJSONObject(i);
                        if (curObject != null && curObject.get(key) != null) {
                            jArray.set(i, GetAesJToken(curObject.get(key), deepLevelNodes.get(key)));
                        }
                    }
                    object = jArray;
                }
            }
        }
        return object;
    }




    /**
     * 将确定节点解密
     *
     * @param object 入参
     * @param node   入参
     * @return 结果
     */
    private Object AesNodeToJson(Object object, String node) throws BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchProviderException, InvalidAlgorithmParameterException {
        if (object == null) return object;
        if (JSONValidator.from(object.toString()).getType()==JSONValidator.Type.Object
            // JSON.isValidObject(object.toString())
        ) {
            var jObject = JSON.parseObject(object.toString());
            if (jObject.get(node) != null) {
                if (
//                        JSONValidator.from(jObject.get(node).toString()).getType()==JSONValidator.Type.Array
                        JSON.isValidArray(jObject.get(node).toString())
                ) {
                    var jArray = jObject.getJSONArray(node);
                    for (int i = 0; i < jArray.size(); i++) {
                        jArray.set(i, stringDecrypt(jArray.get(i).toString()));
                    }
                    jObject.put(node, jArray);
                } else
//                    if (
////                            JSONValidator.from(jObject.get(node).toString()).getType()!=JSONValidator.Type.Object    //非
//                    !JSON.isValidObject(jObject.get(node).toString())
//                )
                {
                    String TMP=stringDecrypt(jObject.get(node).toString());
//                        String TMP=JSONObject.toJSONString(jObject.get(node), SerializerFeature.SortField.MapSortField);
//                        System.out.println(TMP+"222");

//                        JSONObject jsonObject=JSONObject.parseObject(TMP);
//                        String tmp=JSONObject.toJSONString(jsonObject);
                    jObject.put(node, TMP);
                    //System.out.println(stringDecrypt(jObject.get(node).toString()));
                }
            }
            object = jObject;
        } else if (
//                JSONValidator.from(object.toString()).getType()==JSONValidator.Type.Array
                JSON.isValidArray(object.toString())
        ) {
            var jArray = JSON.parseArray(object.toString());
            for (int i = 0; i < jArray.size(); i++) {
                Object curObject = jArray.getJSONObject(i);
                if (curObject != null) {
                    jArray.set(i, AesNodeToJson(curObject, node));
                }
            }
            object = jArray;
        } else {
            object = stringDecrypt(object.toString());
        }
        return object;
    }


    public Object  GetSignvalue(Object object, List<String> nodeList) throws Exception {
        Map<String, Object> signmap=new HashMap();
        // 如果为空，直接返回
        if (object == null || nodeList.size() == 0) return null;
        JSONObject jsonObject = null;
        // 多层节点递归展开，单层节点直接加密
        Map<String, List<String>> deepLevelNodes = new HashMap<>();
        for (var node : nodeList) {
            var nodeArr = Arrays.asList(node.split("\\."));
            if (nodeArr.size() > 1) {
                if (deepLevelNodes.containsKey(nodeArr.get(0)))
                    deepLevelNodes.get(nodeArr.get(0))
                            .add(com.ctrip.framework.apollo.core.utils.StringUtils
                                    .join(nodeArr.subList(1, nodeArr.size()), "."));
                else
                    deepLevelNodes.put(nodeArr.get(0),
                            new ArrayList<>(Arrays.asList(com.ctrip.framework.apollo.core.utils.StringUtils
                                    .join(nodeArr.subList(1, nodeArr.size()), "."))));
            } else {
                //object = JsonNodeToAes(object, node);

                object=JsonNodeSign(object, node);

            }
        }


        if (deepLevelNodes.size() > 0) {
            for (String key : deepLevelNodes.keySet()) {
                //JSONValidator validator = JSONValidator.from(x);
                if (JSONValidator.from(object.toString()).getType()==JSONValidator.Type.Object
                    //JSON.isValidObject(object.toString())
                ) {
                    var jObject = JSON.parseObject(object.toString());
                    if (jObject.get(key) != null) {
                        jObject.put(key, GetSignvalue(jObject.get(key), deepLevelNodes.get(key)));
                    }
                    object = jObject;
                }
                if (JSONValidator.from(object.toString()).getType()==JSONValidator.Type.Array
                    //JSON.isValidArray(object.toString())
                ) {
                    var jArray = JSON.parseArray(object.toString());
                    for (int i = 0; i < jArray.size(); i++) {
                        JSONObject curObject = jArray.getJSONObject(i);
                        if (curObject != null && curObject.get(key) != null) {
                            jArray.set(i, GetSignvalue(curObject.get(key), deepLevelNodes.get(key)));
                        }
                    }
                    object = jArray;
                }
            }
        }
        return object;
    }

    /**
     * 确定节点验签
     *
     * @param object 入参
     * @param node   入参
     * @return 结果
     */
    private Object JsonNodeSign(Object object, String node) throws Exception {
        if (object == null) return null;

        if (JSONValidator.from(object.toString()).getType()==JSONValidator.Type.Object
            // JSON.isValidObject(object.toString())
        ) {
            var jObject = JSON.parseObject(object.toString());
            if (jObject.get(node) != null) {
                if (JSONValidator.from(jObject.get(node).toString()).getType()==JSONValidator.Type.Array
                    //JSON.isValidArray(jObject.get(node).toString())
                ) {
                    var jArray = jObject.getJSONArray(node);
                    for (int i = 0; i < jArray.size(); i++) {
                        jArray.set(i, jArray.get(i).toString());

                        String tmp=JSONObject.toJSONString(jArray.get(i), SerializerFeature.SortField.MapSortField);
                        this.signvaluemap.put(node, tmp);
//                        this.signvaluemap.put(node, jArray.get(i).toString());
                    }
                    jObject.put(node, jArray);
                } else
//                    if (JSONValidator.from(jObject.get(node).toString()).getType()!=JSONValidator.Type.Object    //非
//                    //!JSON.isValidObject(jObject.get(node).toString())
//                )
                {
                    jObject.put(node, jObject.get(node).toString());
                    String tmp=JSONObject.toJSONString(jObject.get(node), SerializerFeature.SortField.MapSortField);
                    this.signvaluemap.put(node, tmp);
//                    this.signvaluemap.put(node,jObject.get(node).toString());
                }
            }
            object = jObject;
        } else if (
                JSONValidator.from(object.toString()).getType()==JSONValidator.Type.Array
            //JSON.isValidArray(object.toString())
        ) {
            var jArray = JSON.parseArray(object.toString());
            for (int i = 0; i < jArray.size(); i++) {
                Object curObject = jArray.getJSONObject(i);
                if (curObject != null) {
                    jArray.set(i, JsonNodeSign(curObject, node));
                }
            }
            object = jArray;
//            signmap = jArray.;
        } else {
            object = object.toString();
            String tmp=JSONObject.toJSONString(object, SerializerFeature.SortField.MapSortField);
            this.signvaluemap.put(node, tmp);
//            this.signvaluemap.put(node,object.toString());
        }


        return object;


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
}