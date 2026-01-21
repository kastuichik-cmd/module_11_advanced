package com.traineeship.module_6_easy.controller;

import com.traineeship.module_6_easy.service.AsyncTaskService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AsyncController {

    private final AsyncTaskService asyncTaskService;

    public AsyncController(AsyncTaskService asyncTaskService) {
        this.asyncTaskService = asyncTaskService;
    }

    @GetMapping("/run-async")
    public ResponseEntity<String> runAsyncTask() {
        asyncTaskService.runLongTask();
        return ResponseEntity.ok("Асинхронная задача запущена!");
    }
}
