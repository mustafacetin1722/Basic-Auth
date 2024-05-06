package com.mustafa.basicauth.controller;

import com.mustafa.basicauth.service.UserService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/public")
public class PublicController {

    @GetMapping
    public String helloWorldPublic() {
        return "Hello World! from public endpoint.";
    }
}
