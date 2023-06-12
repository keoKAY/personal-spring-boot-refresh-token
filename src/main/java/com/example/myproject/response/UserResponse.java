package com.example.myproject.response;


import com.example.myproject.document.User;
import lombok.Builder;
import lombok.Data;

@Builder
@Data
public class UserResponse {

    private String id ;
    private String username;

    public static UserResponse from (User user ){
        return builder()
                .id(user.getId())
                .username(user.getUsername())
                .build();
    }
}
