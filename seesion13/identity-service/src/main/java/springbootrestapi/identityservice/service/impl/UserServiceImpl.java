package springbootrestapi.identityservice.service.impl;

import io.jsonwebtoken.Claims;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import springbootrestapi.identityservice.dto.request.LoginRequest;
import springbootrestapi.identityservice.dto.request.LogoutRequest;
import springbootrestapi.identityservice.dto.request.UserRegistrationRequest;
import springbootrestapi.identityservice.dto.respose.JWTResponse;
import springbootrestapi.identityservice.dto.respose.UserResponse;
import springbootrestapi.identityservice.entity.RefreshToken;
import springbootrestapi.identityservice.entity.User;
import springbootrestapi.identityservice.repository.RefreshTokenRepository;
import springbootrestapi.identityservice.repository.UserRepository;
import springbootrestapi.identityservice.security.jwt.JwtUtil;
import springbootrestapi.identityservice.security.principal.CustomUserDetails;
import springbootrestapi.identityservice.security.principal.CustomUserDetailsService;
import springbootrestapi.identityservice.service.RefreshTokenService;
import springbootrestapi.identityservice.service.UserService;

import java.util.Date;

@Slf4j
@Service
@AllArgsConstructor
public class UserServiceImpl implements UserService {
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final CustomUserDetailsService customUserDetailsService;
    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenService refreshTokenService;
    private final StringRedisTemplate redisTemplate;
    private final RefreshTokenRepository refreshTokenRepository;

    @Override
    public UserResponse register(UserRegistrationRequest request) {
        // 1. Kiểm tra username đã tồn tại chưa
        userRepository.findByUsername(request.getUsername())
                .ifPresent(existingUser -> {
                    throw new RuntimeException("Tài khoản đã tồn tại");
                });


        // 3. Tạo User
        User user = User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .roles(request.getRoles())
                .enabled(true)
                .build();

        User savedUser = userRepository.save(user);

        // 4. Trả về DTO
        return UserResponse.builder()
                .id(savedUser.getUserId())
                .username(savedUser.getUsername())
                .roles(savedUser.getRoles())
                .enabled(savedUser.getEnabled())
                .build();
    }

    @Override
    public String generateTokenByUsername(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Tài khoản không tồn tại: " + username));
        CustomUserDetails customUserDetails = (CustomUserDetails) customUserDetailsService.loadUserByUsername(user.getUsername());
        return jwtUtil.generateToken(customUserDetails);
    }

    @Override
    public JWTResponse login(LoginRequest request) {
        try {
            // 1. Xác thực thông tin username/password
            Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));

            CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();
            // 2. Tạo Access Token từ JWT
            String accessToken = jwtUtil.generateToken(customUserDetails);
            // 3. Tạo Refresh Token lưu vào Database
            RefreshToken refreshToken = refreshTokenService.createRefreshToken(customUserDetails.getId());
            return JWTResponse.builder()
                    .username(customUserDetails.getUsername())
                    .enabled(customUserDetails.getEnabled())
                    .authorities(customUserDetails.getAuthorities())
                    .accessToken(accessToken)
                    .refreshToken(refreshToken.getRefreshToken())
                    .build();
        } catch (Exception e) {
            log.error("Username hoặc password không đúng ", e.getMessage());
            throw new UsernameNotFoundException("Username hoặc password không đúng "+ e.getMessage());
        }
    }

    @Override
    @Transactional
    public void logout(LogoutRequest request) {
        if (request == null || request.getToken() == null || request.getToken().isBlank()) {
            throw new IllegalArgumentException("Token không được để rỗng!");
        }

        // 💡 BƯỚC QUAN TRỌNG NHẤT: Xóa sạch toàn bộ khoảng trắng, xuống dòng (\n, \r, space)
        String cleanToken = request.getToken().replaceAll("\\s+", "");

        // 1. Giải mã token đã làm sạch
        Claims claims = jwtUtil.extractAllClaims(cleanToken);
        String jti = claims.getId();
        Date expiration = claims.getExpiration();

        // 2. Tính toán TTL
        long currentTimeMillis = System.currentTimeMillis();
        long ttlInMillis = expiration.getTime() - currentTimeMillis;

        if (ttlInMillis > 0) {
            // 3 & 4. Lưu key "blacklist:{jti}" vào Redis với TTL
            String redisKey = "blacklist:" + jti;
            redisTemplate.opsForValue().set(redisKey, "revoked", ttlInMillis, java.util.concurrent.TimeUnit.MILLISECONDS);
            log.info("Đã đưa Token (JTI: {}) vào Blacklist Redis với TTL: {} ms", jti, ttlInMillis);
        }

        // 5. Xóa Refresh Token tương ứng trong PostgreSQL
        String username = claims.getSubject();
        refreshTokenRepository.deleteByUsername(username);
    }

}
