package com.traineeship.module_6_easy.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class AsyncTaskService {

    @Async
    public void runLongTask() {
        try {
            log.info("Асинхронная задача началась...");
            Thread.sleep(5000);
            log.info("Асинхронная задача завершена!");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("Ошибка в асинхронной задаче", e);
        }
    }
}
