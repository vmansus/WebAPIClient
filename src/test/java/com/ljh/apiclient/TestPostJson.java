package com.ljh.apiclient;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.ljh.apiclient.smcipher.RequestHandler;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.context.web.WebAppConfiguration;

import java.io.IOException;

@RunWith(SpringRunner.class)
@SpringBootTest
@WebAppConfiguration
public class TestPostJson {



    @Test
    public void HttpPostData() {
        try {
//            System.setProperty("http.proxyHost", "192.168.1.109");
//            System.setProperty("https.proxyHost", "192.168.1.109");
//            System.setProperty("http.proxyPort", "8888");
//            System.setProperty("https.proxyPort", "8888");
            HttpClient httpclient = new DefaultHttpClient();
            String uri = "http://ipv4.fiddler:8080/test/testapi";
            HttpPost httppost = new HttpPost(uri);
//            HttpHost proxy = new HttpHost("http://ipv4.fiddler", 8888, "http");
//            RequestConfig config = RequestConfig.custom().setProxy(proxy).build();

            //添加http头信息
            httppost.addHeader("Content-Type", "application/json");
            httppost.addHeader("yye", "yye");
//            httppost.setConfig(config);

            JSONObject obj = JSON.parseObject("{\"cardInfo\":{\"cashCardNo\":\"99989998\",\"cardID\":\"666666\"},\"customerInfo\":{\"date\":\"1111-11-1\",\"mobile\":\"42412421\"},\"name\":\"ljh\",\"sex\":\"male\"}");

            System.out.println("原始请求为:\n\n"+obj.toString()+"\n\n");

            String request=new RequestHandler().encRequest(obj.toString());
            System.out.println("修改请求为:\n\n"+request+"\n\n");
            httppost.setEntity(new StringEntity(request));

            HttpResponse response;
            response = httpclient.execute(httppost);


            //检验状态码，如果成功接收数据
            int code = response.getStatusLine().getStatusCode();

//            System.out.println(response.getEntity().getContent().toString());
            System.out.println(code+"code");
            if (code == 200) {
                String rev = EntityUtils.toString(response.getEntity());//返回json格式： {"id": "","name": ""}

                System.out.println("收到响应为:\n\n"+rev+"\n\n");
                String decResponse=new RequestHandler().decResponse(rev);
                System.out.println("原始响应为:\n\n"+decResponse+"\n\n");
            }
        } catch (ClientProtocolException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
