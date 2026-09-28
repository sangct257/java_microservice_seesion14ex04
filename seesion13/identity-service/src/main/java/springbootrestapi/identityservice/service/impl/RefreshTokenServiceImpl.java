package springbootrestapi.identityservice.service.impl;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import springbootrestapi.identityservice.dto.respose.JWTResponse;
import springbootrestapi.identityservice.entity.RefreshToken;
import springbootrestapi.identityservice.entity.User;
import springbootrestapi.identityservice.repository.RefreshTokenRepository;
import springbootrestapi.identityservice.repository.UserRepository;
import springbootrestapi.identityservice.security.jwt.JwtUtil;
import springbootrestapi.identityservice.security.principal.CustomUserDetails;
import springbootrestapi.identityservice.service.RefreshTokenService;

import java.time.Instant;
import java.util.NoSuchElementException;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenServiceImpl implements RefreshTokenService {
    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtUtil jwtUtil;

    @Value("${jwt-refresh-expiration}")
    private long refreshExpiration;

    @Override
    public RefreshToken createRefreshToken(String userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Không tìm thấy uesr với id: " + userId));

        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .username(user.getUsername())
                .refreshToken(UUID.randomUUID().toString())
                .expiryDate(Instant.now().plusMillis(refreshExpiration))
                .invoke(false)
                .build();

        return refreshTokenRepository.save(refreshToken);
    }

    @Override
    public RefreshToken verifyExpiration(RefreshToken token) {
        // 1. Kiểm tra xem Token đã bị thu hồi (invoke = true) chưa
        if (Boolean.TRUE.equals(token.getInvoke())) {
            refreshTokenRepository.delete(token); // Xóa token đã bị thu hồi
            throw new RuntimeException("Refresh token đã bị thu hồi. Vui lòng đăng nhập lại.");
        }
        // 2. Kiểm tra xem Token đã hết hạn chưa
        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(token); // Xóa token đã hết hạn
            throw new RuntimeException("Refresh token đã hết hạn. Vui lòng đăng nhập lại.");
        }
        return token;
    }

    @Override
    @Transactional
    public JWTResponse refreshToken(String requestToken) {
        // 1. Tìm RefreshToken trong DB bằng chuỗi requestToken.
        RefreshToken refreshToken = refreshTokenRepository.findByRefreshToken(requestToken)
                .orElseThrow(() -> new NoSuchElementException("Refresh token không tồn tại"));
        // 2. Nếu không tìm thấy hoặc token đã hết hạn (expiryDate < Instant.now()) -> Ném Exception.
        if (refreshToken.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(refreshToken); // Xóa token đã hết hạn
            throw new RuntimeException("Refresh token đã hết hạn. Vui lòng đăng nhập lại.");
        }

        // Lấy thông tin User sở hữu Token này
        User user = refreshToken.getUser();
        // 3. (QUAN TRỌNG - Rotation): Xóa bản ghi Refresh Token cũ khỏi DB.
        refreshTokenRepository.delete(refreshToken);

        // 4. Lấy User từ token cũ, gọi JwtUtils để tạo Access Token mới.
        CustomUserDetails customUserDetails = CustomUserDetails.builder()
                .id(user.getUserId())
                .username(user.getUsername())
                .password(user.getPassword())
                .enabled(user.getEnabled())
                .authorities(user.getRoles().stream()
                        .map(role -> new SimpleGrantedAuthority(role.getRoleName().toString()))
                        .toList()
                )
                .build();
        String newAccessToken = jwtUtil.generateToken(customUserDetails);
        // 5. Gọi hàm createRefreshToken (đã viết ở Bài 1) để tạo Refresh Token hoàn toàn mới.
        RefreshToken newRefreshToken = createRefreshToken(user.getUserId());
        // 6. Trả về cặp Token mới cho Client.


        return JWTResponse.builder()
                .username(customUserDetails.getUsername())
                .enabled(customUserDetails.getEnabled())
                .authorities(customUserDetails.getAuthorities())
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken.getRefreshToken())
                .build();
    }
}
