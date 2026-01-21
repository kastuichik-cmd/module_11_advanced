package com.traineeship.notification_service.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class NotificationController {
    @GetMapping("/api/notify")
    public String notifyEndpoint() {
        System.err.println("Получен запрос на уведомление от BookService!");
        return "Уведомление получено";
    }
}
