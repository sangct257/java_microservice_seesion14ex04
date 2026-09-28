package springbootrestapi.identityservice.service;

import springbootrestapi.identityservice.dto.respose.JWTResponse;
import springbootrestapi.identityservice.entity.RefreshToken;

public interface RefreshTokenService {
    RefreshToken createRefreshToken(String userId);
    RefreshToken verifyExpiration(RefreshToken token);
    JWTResponse refreshToken(String requestToken);
}
