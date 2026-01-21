package com.traineeship.module_6_easy.controller;

import com.traineeship.module_6_easy.model.dto.BitcoinPrice;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import tools.jackson.databind.JsonNode;


@RestController
public class ExternalApiController {

    private final WebClient webClient;

    public ExternalApiController(WebClient webClient) {
        this.webClient = webClient;
    }

    // https://api.coindesk.com/v1/bpi/currentprice.json не работает, использова альтернативный
    @GetMapping("/bitcoin-price")
    public Mono<BitcoinPrice> getPrice() {
        String url = "https://blockchain.info/ticker";

        return webClient.get()
                .uri(url)
                .retrieve()
                .bodyToMono(JsonNode.class)
                .map(root -> {
                    BitcoinPrice dto = new BitcoinPrice();
                    dto.symbol = "USD";
                    dto.lastPrice = root.at("/USD/last").asText();
                    return dto;
                });
    }
}
