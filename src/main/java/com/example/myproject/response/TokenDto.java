package com.example.myproject.response;


import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class TokenDto {

    private String userId;
    private String accessToken;
    private String refreshToken;


}
