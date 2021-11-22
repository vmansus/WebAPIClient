package com.ljh.apiclient.smcipher;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.PropertySource;
import org.springframework.stereotype.Component;

import java.util.List;

//@Component
//@PropertySource(value = {"classpath:application-crypto.yml"}, factory = YamlPropertySourceFactory.class)
//@ConfigurationProperties(prefix = "nodeinfo.my")
//@Configuration
//@PropertySource(value = "classpath:application.yml", encoding = "UTF-8", factory = YamlPropertyLoaderFactory.class)
//@ConfigurationProperties(prefix = "node")
//@Data

@Component
@PropertySource("classpath:application.properties")
@ConfigurationProperties(prefix = "node.info")
@Data
@Primary
public class NodesConfig {
    private List<String> encryptlist ;
    private List<String> signlist ;
    private List<String> reenc ;
    private List<String> resign ;
    private List<String> formenc;
    private List<String> formsign;
    private List<String> formreenc;
    private List<String> formresign;
//    private int workmode;
}
