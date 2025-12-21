package com.flightapp.apigateway.DTO;

import lombok.Data;

@Data
public class PasswordChange {
    private String username;
    private String newPassword;
}
