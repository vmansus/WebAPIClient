package com.ljh.apiclient;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.ljh.apiclient.apigen.WebAPIClientAPI;
import org.junit.Test;

public class TestAPI {
    @Test
    public void testEncJson() throws Exception {
        JSONObject obj = JSON.parseObject("{\"cardInfo\":{\"cashCardNo\":\"99989998\",\"cardID\":\"666666\"},\"customerInfo\":{\"date\":\"1111-11-1\",\"mobile\":\"42412421\"},\"name\":\"ljh\",\"sex\":\"male\"}");
        JSONObject res=new WebAPIClientAPI().encJson(obj,"server cert","clientsignkey");
        System.out.println(res.toJSONString());
    }


}
