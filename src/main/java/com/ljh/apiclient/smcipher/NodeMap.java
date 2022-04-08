package com.ljh.apiclient.smcipher;

import com.ljh.apiclient.configeditor.CryptoConfigUtils;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

//@EnableConfigurationProperties(com.ljh.apiclient.smcipher.NodesConfig.class)
//@Component
public class NodeMap {


//    @Autowired
//    private NodesConfig NodesConfig;
//    private com.ljh.apiclient.smcipher.NodesConfig nodesConfig = com.ljh.apiclient.smcipher.BeanUtils.getBean(com.ljh.apiclient.smcipher.NodesConfig.class);
    CryptoConfigUtils cryptoConfigUtils=new CryptoConfigUtils();

    public Map<String, List<String>> encryptNodeMap() throws IOException, URISyntaxException {
        List<String> lists=cryptoConfigUtils.getResponseEncParms();
        Map<String, List<String>> Map = new HashMap<String, List<String>>(){
            {
                put("defult",  lists);
            }
        };
        return Map;
    }



    public Map<String, List<String>> reencNodeMap() throws IOException, URISyntaxException {
        List<String> lists=cryptoConfigUtils.getRequestEncParms();
        Map<String, List<String>> Map = new HashMap<String, List<String>>(){
            {
                put("defult",  lists);
            }
        };
        return Map;
    }





    public Map<String, List<String>> resignNodeMap() throws IOException, URISyntaxException {
        List<String> lists=cryptoConfigUtils.getRequestSignParms();
        Map<String, List<String>> Map = new HashMap<String, List<String>>(){
            {
                put("defult",  lists);
            }
        };
        return Map;
    }



    public List<String> signNodelist() throws IOException, URISyntaxException {
        List<String> lists=cryptoConfigUtils.getResponseSignParms();
        return lists;
    }



//    public int workmodenum(){
//        int num=nodesConfig.getWorkmode();
//        return num;
//    }
}