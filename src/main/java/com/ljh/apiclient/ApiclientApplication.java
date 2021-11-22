package com.ljh.apiclient;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.ServletComponentScan;

@SpringBootApplication
@ServletComponentScan
public class ApiclientApplication {

    public static void main(String[] args) {
        SpringApplication.run(ApiclientApplication.class, args);
    }

}
