package com.traineeship.module_6_easy.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class ScheduledTaskService {

    @Scheduled(cron = "0 * * * * ?")
    public void runTask() {
        log.info("Running scheduled task...");
    }
}
