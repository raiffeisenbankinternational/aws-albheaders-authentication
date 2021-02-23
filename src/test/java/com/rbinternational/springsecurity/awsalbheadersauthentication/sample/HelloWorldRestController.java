package com.rbinternational.springsecurity.awsalbheadersauthentication.sample;

import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloWorldRestController {

    @GetMapping("/helloauthuser")
    @Secured("ROLE_AUTH_USER")
    public String sayHelloAuthUser() {
        return "Hello auth user!";
    }

    @GetMapping("/helloadminuser")
    @Secured("ROLE_ADMIN")
    public String sayHelloAdminUser() {
        return "Hello mighty admin user!";
    }

    @GetMapping("/hello")
    public String sayHello() {
        return "Hello to everyone!";
    }
}
