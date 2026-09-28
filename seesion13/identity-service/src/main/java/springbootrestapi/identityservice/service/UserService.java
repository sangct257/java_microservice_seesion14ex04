package springbootrestapi.identityservice.service;

import springbootrestapi.identityservice.dto.request.LoginRequest;
import springbootrestapi.identityservice.dto.request.LogoutRequest;
import springbootrestapi.identityservice.dto.request.UserRegistrationRequest;
import springbootrestapi.identityservice.dto.respose.JWTResponse;
import springbootrestapi.identityservice.dto.respose.UserResponse;
import springbootrestapi.identityservice.entity.User;

public interface UserService {
    UserResponse register(UserRegistrationRequest request);
    String generateTokenByUsername(String username);
    JWTResponse login(LoginRequest request);
    void logout(LogoutRequest token);
}
