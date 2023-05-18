package com.tencent.kona.demo;

import com.tencent.kona.KonaProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Security;

@SpringBootApplication
public class KonaServer {

    static {
        // It looks the framework just selects the first provider for each algorithm.
        Security.insertProviderAt(new KonaProvider(), 1);
    }

    public static void main(String[] args) {
//        System.setProperty("com.tencent.kona.ssl.debug", "all");
        SpringApplication.run(KonaServer.class, args);
    }

    @RestController
    public static class ResponseController {

        @GetMapping("/")
        public String response() {
            return "This is a testing server on Tencent Kona SM Suite";
        }
    }
}
