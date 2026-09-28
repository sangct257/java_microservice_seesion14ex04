package springbootrestapi.identityservice.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;
import springbootrestapi.identityservice.security.principal.CustomUserDetails;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Component // Đánh dấu lớp này là một Spring Component để có thể Dependency Injection vào Service/Controller
public class JwtUtil {

    // Tiêm (Inject) chuỗi khóa bí mật từ file application.yml (Yêu cầu chuỗi đủ dài >= 256-bit / 32 ký tự)
    @Value("${jwt-scecret}")
    private String jwtSecret;

    // Tiêm thời gian hết hạn của Access Token (đơn vị: mili-giây)
    @Value("${jwt-expiration}")
    private long jwtExpiration;

    // Tiêm thời gian hết hạn của Refresh Token (đơn vị: mili-giây)
    @Value("${jwt-refresh-expiration}")
    private long jwtRefreshExpiration;

    /**
     * Hàm sinh (generate) ra chuỗi JWT Token từ thông tin người dùng.
     * @param customUserDetails Chứa thông tin chi tiết của User đã xác thực thành công.
     * @return Chuỗi JWT Token chuẩn mã hóa dạng Header.Payload.Signature
     */
    public String generateToken(CustomUserDetails customUserDetails) {
        Date now = new Date(); // Lấy thời điểm tạo Token
        Date expirationDate = new Date(now.getTime() + jwtExpiration); // Tính thời điểm Token hết hạn

        // Chuyển đổi chuỗi Secret Key dạng văn bản sang đối tượng SecretKey chuẩn mã hóa HMAC-SHA
        SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));

        // Tạo Map chứa các Custom Claims (Thông tin bổ sung muốn lưu trữ bên trong Payload của JWT)
        Map<String, Object> claims = new HashMap<>();
        claims.put("username", customUserDetails.getUsername()); // Đưa thông tin tên tài khoản
        // Trích xuất danh sách quyền (Roles/Authorities) từ UserDetails và chuyển thành dạng Danh sách chuỗi (List<String>)
        claims.put("roles", customUserDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList());

        // Thực hiện đóng gói và ký (sign) Token
        return Jwts.builder()
                .setClaims(claims) // Thiết lập các custom claims (Payload)
                .setId(UUID.randomUUID().toString()) // THÊM JTI (JWT ID) VÀO PAYLOAD
                .subject(customUserDetails.getUsername()) // Thiết lập Claim chuẩn 'sub' (chủ thể của token)
                .setIssuedAt(now) // Thiết lập thời gian khởi tạo ('iat')
                .setExpiration(expirationDate) // Thiết lập thời gian hết hạn ('exp')
                .signWith(key) // Ký chữ ký số bằng SecretKey và thuật toán mặc định (HS256)
                .compact(); // Chuẩn hóa chuỗi Token hoàn chỉnh dạng String
    }

    // Bổ sung hàm phụ trợ giải mã Claims phục vụ hàm Logout
    public Claims extractAllClaims(String token) {
        SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
        return Jwts.parser()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}