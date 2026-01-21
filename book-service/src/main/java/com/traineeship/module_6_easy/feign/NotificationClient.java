package com.traineeship.module_6_easy.feign;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;

@FeignClient(name = "NOTIFICATION-SERVICE")
public interface NotificationClient {

    @GetMapping("/api/notify")
    String notifyService();
}
