package com.ljh.apiclient.smcipher;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@EnableConfigurationProperties(com.ljh.apiclient.smcipher.NodesConfig.class)
@Component
public class NodeMap {


//    @Autowired
//    private NodesConfig NodesConfig;
    private com.ljh.apiclient.smcipher.NodesConfig nodesConfig = com.ljh.apiclient.smcipher.BeanUtils.getBean(com.ljh.apiclient.smcipher.NodesConfig.class);

    public Map<String, List<String>> encryptNodeMap(){
        List<String> lists=nodesConfig.getEncryptlist();
        Map<String, List<String>> Map = new HashMap<String, List<String>>(){
            {
                put("defult",  lists);
            }
        };
        return Map;
    }

    public Map<String, List<String>> formencryptNodeMap(){
        List<String> lists=nodesConfig.getFormenc();
        Map<String, List<String>> Map = new HashMap<String, List<String>>(){
            {
                put("defult",  lists);
            }
        };
        return Map;
    }

    public Map<String, List<String>> reencNodeMap(){
        List<String> lists=nodesConfig.getReenc();
        Map<String, List<String>> Map = new HashMap<String, List<String>>(){
            {
                put("defult",  lists);
            }
        };
        return Map;
    }

    public Map<String, List<String>> formreencNodeMap(){
        List<String> lists=nodesConfig.getFormreenc();
        Map<String, List<String>> Map = new HashMap<String, List<String>>(){
            {
                put("defult",  lists);
            }
        };
        return Map;
    }


    public Map<String, List<String>> signNodeMap(){
        List<String> lists=nodesConfig.getSignlist();
        Map<String, List<String>> Map = new HashMap<String, List<String>>(){
            {
                put("defult",  lists);
            }
        };
        return Map;
    }

    public Map<String, List<String>> formsignNodeMap(){
        List<String> lists=nodesConfig.getFormsign();
        Map<String, List<String>> Map = new HashMap<String, List<String>>(){
            {
                put("defult",  lists);
            }
        };
        return Map;
    }

    public Map<String, List<String>> resignNodeMap(){
        List<String> lists=nodesConfig.getResign();
        Map<String, List<String>> Map = new HashMap<String, List<String>>(){
            {
                put("defult",  lists);
            }
        };
        return Map;
    }

    public Map<String, List<String>> formresignNodeMap(){
        List<String> lists=nodesConfig.getFormresign();
        Map<String, List<String>> Map = new HashMap<String, List<String>>(){
            {
                put("defult",  lists);
            }
        };
        return Map;
    }

    public List<String> signNodelist(){
        List<String> lists=nodesConfig.getSignlist();
        return lists;
    }

    public List<String> formsignNodelist(){
        List<String> lists=nodesConfig.getFormsign();
        return lists;
    }

    public List<String> resignlist(){
        List<String> lists=nodesConfig.getReenc();
        return lists;
    }

    public List<String> formresignlist(){
        List<String> lists=nodesConfig.getFormreenc();
        return lists;
    }

//    public int workmodenum(){
//        int num=nodesConfig.getWorkmode();
//        return num;
//    }
}