package kubernetes.security_framework;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
public class SimpleappApplication {
    public static void main(String[] args) {
        SpringApplication.run(SimpleappApplication.class, args);
    }
}

//Another attempt

@RestController
class HelloController {
    @GetMapping("/hello")
    public String hello() {
        return "Hello,! Welcome to update 3!!";
    }
}