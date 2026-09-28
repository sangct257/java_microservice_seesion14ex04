package ra.demo.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.function.Function;

@Component // Đánh dấu class là một Spring Bean để có thể @Autowired sử dụng ở các nơi khác (ví dụ: GlobalFilter)
public class JwtUtils {

    // Bơm giá trị Secret Key từ file cấu hình application.yml (mã khóa bí mật dùng để xác thực chữ ký JWT)
    @Value("${jwt-scecret}")
    private String jwtSecret;

    /**
     * Trích xuất Username (Subject) từ JWT Token
     * @param token Chuỗi JWT Token
     * @return Username của người dùng
     */
    public String extractUsername(String token) {
        // Claims::getSubject tương đương với gọi hàm claims.getSubject() để lấy thông tin 'sub' trong Payload
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Trích xuất Thời gian hết hạn (Expiration Date) từ JWT Token
     * @param token Chuỗi JWT Token
     * @return Thời gian token hết hạn (kiểu Date)
     */
    public Date extractExpiration(String token){
        // Claims::getExpiration tương đương với gọi hàm claims.getExpiration() để lấy thông tin 'exp' trong Payload
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Trích xuất danh sách Vai trò (Roles) của người dùng từ JWT Token
     * @param token Chuỗi JWT Token
     * @return Danh sách các Role dạng List<String> (ví dụ: ["ROLE_ADMIN", "ROLE_USER"])
     */
    @SuppressWarnings("unchecked") // Bỏ qua cảnh báo ép kiểu không an toàn (Unchecked cast) khi chuyển Object sang List.class
    public List<String> extractRoles(String token) {
        Claims claims = extractAllClaim(token);      // 1. Lấy toàn bộ thông tin Claims từ Token
        return claims.get("roles", List.class);      // 2. Lấy giá trị tương ứng với key "roles" và ép kiểu về List
    }

    /**
     * Hàm Generic hỗ trợ trích xuất một trường (Claim) cụ thể ra khỏi Token
     * @param token Chuỗi JWT Token
     * @param claimsResolver Hàm xử lý để lấy đúng Claim mong muốn
     */
    private <T> T extractClaim(String token, Function<Claims,T> claimsResolver) {
        final Claims claims = extractAllClaim(token); // 1. Lấy toàn bộ danh sách Claims từ Token
        return claimsResolver.apply(claims);        // 2. Áp dụng hàm truyền vào để lấy riêng claim cần dùng
    }

    /**
     * Trích xuất TOÀN BỘ thông tin (Claims/Payload) bên trong JWT Token
     * Đây là hàm cốt lõi để giải mã và xác thực token
     * @param token Chuỗi JWT Token
     * @return Đối tượng Claims chứa thông tin Payload của token
     */
    private Claims extractAllClaim(String token) {
        // Chuyển chuỗi mã bí mật (jwtSecret) thành đối tượng SecretKey theo chuẩn thuật toán HMAC-SHA
        SecretKey secretKey = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));

        return Jwts.parser()             // 1. Khởi tạo đối tượng JwtParser
                .verifyWith(secretKey)   // 2. Đưa SecretKey vào để kiểm tra tính hợp lệ của chữ ký
                .build()                 // 3. Tiến hành build Parser
                .parseSignedClaims(token) // 4. Phân tích token (Nếu sai mã bí mật hoặc token biến dạng sẽ ném Exception ngay)
                .getPayload();           // 5. Lấy phần thông tin chính (Payload/Body) của Token
    }

    /**
     * Kiểm tra xem Token đã hết hạn hay chưa
     * @param token Chuỗi JWT Token
     * @return true nếu đã hết hạn, false nếu vẫn còn hạn sử dụng
     */
    private Boolean isTokenExpired(String token) {
        try {
            // So sánh ngày hết hạn của token với ngày giờ hiện tại
            return extractExpiration(token).before(new Date());
        } catch (Exception e) {
            // Nếu có lỗi khi lấy ngày (ví dụ token lỗi định dạng), mặc định coi như token đã hết hạn
            return true;
        }
    }

    /**
     * Kiểm tra tính hợp lệ toàn diện của JWT Token
     * @param token Chuỗi JWT Token gửi từ Client
     * @return true nếu token hợp lệ (đúng chữ ký + chưa hết hạn), false nếu token không hợp lệ
     */
    public Boolean validateToken(String token) {
        try {
            // Chuyển đổi Secret Key
            SecretKey secretKey = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));

            // Thực hiện phân tích token để kiểm tra chữ ký (Signature)
            Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token);

            // Nếu không bị nhảy vào catch (chữ ký chuẩn), tiếp tục kiểm tra xem token còn hạn không
            return !isTokenExpired(token);
        } catch (Exception e) {
            // Catch tất cả các lỗi: Sai chữ ký, token bị chỉnh sửa, thiếu thông tin,... -> Trả về false
            return false;
        }
    }
}