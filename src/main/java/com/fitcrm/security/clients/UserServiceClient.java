package com.fitcrm.security.clients;

import com.fitcrm.security.model.dto.LoginRequestDto;
import com.fitcrm.security.model.dto.UserDto;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.*;

@FeignClient(
        name = "user-service",
        url = "${user-service.url}"
)
public interface UserServiceClient {

    @PostMapping("/internal/users/verify-credentials")
    UserDto verifyCredentials(@RequestBody LoginRequestDto request);

    @GetMapping("/api/users/{id}")
    UserDto getUserById(@PathVariable("id") Long id);
}