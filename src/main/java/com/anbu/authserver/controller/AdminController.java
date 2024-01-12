package com.anbu.authserver.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class AdminController {

    @RequestMapping("/")
    public String index(){
        return "index";
    }

    @GetMapping("/hello")
    public String greet(){ return  "Hello World!!!";}

}
