package ra.demo.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;


/**
 * Filter này kế thừa OncePerRequestFilter để đảm bảo chỉ chạy DUY NHẤT 1 LẦN cho mỗi HTTP Request đi vào Product-Service.
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    // Lấy Secret Key từ file cấu hình application.yml / application.properties.
    // Lưu ý: Secret Key này BẮT BUỘC phải giống hệt Secret Key bên Identity-Service.
    @Value("${jwt-scecret}")
    private String jwtSecret;

    /**
     * Phương thức xử lý chính của Filter, can thiệp vào luồng xử lý của từng Request.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // BƯỚC 1: Bóc tách chuỗi JWT ra khỏi Header "Authorization" của HTTP Request.
        String token = getJwtFromRequest(request);

        // Kiểm tra xem Request có gửi kèm Token hợp lệ (không null và không rỗng) hay không.
        if (StringUtils.hasText(token)) {
            try {
                // BƯỚC 2: Tạo SecretKey mã hóa HMAC-SHA bằng chuẩn UTF-8 đồng bộ với Identity-Service.
                SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));

                // Thực hiện GIẢI MÃ (Parse) và XÁC THỰC (Verify) chữ ký của Token.
                // Nếu Token bị hết hạn, bị chỉnh sửa trái phép hoặc sai chữ ký, dòng code này sẽ ném ra Exception.
                Claims claims = Jwts.parser()
                        .setSigningKey(key)
                        .build()
                        .parseClaimsJws(token)
                        .getBody();

                // BƯỚC 3: Trích xuất thông tin người dùng từ Payload (Claims) của Token.
                String username = claims.getSubject(); // Lấy 'sub' (tên tài khoản)

                @SuppressWarnings("unchecked")
                List<String> roles = (List<String>) claims.get("roles"); // Lấy danh sách 'roles' dạng List<String>

                // BƯỚC 4: Nếu trích xuất dữ liệu thành công
                if (roles != null && username != null) {

                    // Chuyển đổi danh sách chuỗi Role (VD: ["ROLE_ADMIN"]) thành danh sách các SimpleGrantedAuthority mà Spring Security hiểu.
                    List<SimpleGrantedAuthority> authorities = roles.stream()
                            .map(SimpleGrantedAuthority::new)
                            .toList();

                    // BƯỚC 5: Khởi tạo đối tượng Authentication đại diện cho phiên làm việc hiện tại của người dùng.
                    // Tham số 1: Principal (username), Tham số 2: Credentials (null vì đã authen bằng JWT), Tham số 3: Authorities (Danh sách quyền)
                    UsernamePasswordAuthenticationToken authenticationToken =
                            new UsernamePasswordAuthenticationToken(username, null, authorities);

                    // Gắn thêm các chi tiết phụ trợ của HTTP Request (IP, Session ID...) vào đối tượng Authentication.
                    authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    // NẠP ĐỐI TƯỢNG AUTHENTICATION VÀO SECURITY CONTEXT:
                    // Dòng lệnh quan trọng nhất! Báo cho Spring Security biết Request này ĐÃ ĐƯỢC XÁC THỰC THÀNH CÔNG,
                    // giúp các annotation như @PreAuthorize("hasRole('ADMIN')") ở Controller hoạt động được.
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                }
            } catch (Exception e) {
                // Nếu Token không hợp lệ (sai mã, hết hạn, xáo trộn chữ ký...), log ra thông báo lỗi và không set Authentication.
                logger.error("Không thể xác thực JWT Token: {}", e);
            }

            // BƯỚC 6: Cho phép Request tiếp tục đi qua các Filter tiếp theo trong chuỗi FilterChain để vào Controller.
            filterChain.doFilter(request, response);
        }
    }

    /**
     * Hàm phụ trợ (Helper method): Rút trích chuỗi Token thô bằng cách cắt bỏ tiền tố "Bearer " khỏi Header Authorization.
     */
    private String getJwtFromRequest(HttpServletRequest request) {
        String authorizationHeader = request.getHeader("Authorization");

        // Kiểm tra Header có chứa chữ "Bearer " ở đầu hay không
        if (StringUtils.hasText(authorizationHeader) && authorizationHeader.startsWith("Bearer ")) {
            return authorizationHeader.substring(7); // Cắt bỏ 7 ký tự "Bearer " để lấy nguyên chuỗi Token phía sau
        }
        return null;
    }
}