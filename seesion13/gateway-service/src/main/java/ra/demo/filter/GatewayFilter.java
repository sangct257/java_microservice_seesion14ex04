package ra.demo.filter;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import ra.demo.config.RouteValidator;
import ra.demo.jwt.JwtUtils;
import reactor.core.publisher.Mono;

import java.util.List;

@Component // Đánh dấu đây là một Spring Bean
@RequiredArgsConstructor // Lombok tự động tạo Constructor để tiêm (Inject) các biến final (routeValidator, jwtUtils)
@Slf4j // Lombok hỗ trợ ghi log (sử dụng biến 'log')
public class GatewayFilter implements GlobalFilter, Ordered {

    private final RouteValidator routeValidator;
    private final JwtUtils jwtUtils;

    /**
     * Phương thức xử lý chính của Filter cho mọi Request đi qua Gateway
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();

        // BƯỚC 1: Kiểm tra xem Request này có thuộc nhóm API CẦN BẢO MẬT hay không
        if (routeValidator.isSecured.test(request)) {

            // 1.1 Trích xuất Header 'Authorization' từ Request gửi lên
            String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

            // 1.2 Kiểm tra sự tồn tại của Header Authorization
            if (authHeader == null || authHeader.isEmpty()) {
                log.error("Missing Authorization Header for secure path: {}", request.getURI().getPath());
                return onError(exchange, HttpStatus.UNAUTHORIZED, "Missing authorization header"); // Trả về 401 Unauthorized
            }

            // 1.3 Kiểm tra định dạng chuẩn của Token (Bắt buộc phải bắt đầu bằng "Bearer ")
            if (!authHeader.startsWith("Bearer ")) {
                log.error("Không đúng định dạng chuỗi jwt token: {}", authHeader);
                return onError(exchange, HttpStatus.UNAUTHORIZED, "Invalid authorization header format"); // Trả về 401 Unauthorized
            }

            // 1.4 Lấy ra chuỗi JWT Token nguyên bản bằng cách cắt bỏ 7 ký tự đầu ("Bearer ")
            String token = authHeader.substring(7);

            // BƯỚC 2: XÁC THỰC TOKEN (Authentication)
            // Sử dụng JwtUtils để kiểm tra tính hợp lệ (chữ ký, hạn sử dụng, định dạng...)
            if (!jwtUtils.validateToken(token)) {
                log.error("Invalid/Expired JWT token");
                return onError(exchange, HttpStatus.UNAUTHORIZED, "Invalid or expired token"); // Trả về 401 Unauthorized
            }

            // BƯỚC 3: TRÍCH XUẤT THÔNG TIN TỪ TOKEN
            List<String> roles = jwtUtils.extractRoles(token);      // Lấy danh sách Roles (quyền)
            String username = jwtUtils.extractUsername(token);    // Lấy Username người dùng
            log.info("Request by user: {}, roles: {}", username, roles);

            // BƯỚC 4: PHÂN QUYỀN TRUY CẬP (Authorization)
            String path = request.getURI().getPath();             // Lấy URI Path của request
            String method = request.getMethod().name();           // Lấy HTTP Method (GET, POST, PUT, DELETE...)

            // Kiểm tra xem User với các 'roles' hiện tại có đủ quyền gọi API (path + method) này không
            if (!routeValidator.isAuthorized(path, method, roles)) {
                log.warn("User {} unauthorized to call API {} {}", username, method, path);
                return onError(exchange, HttpStatus.FORBIDDEN, "Access denied: Unauthorized access"); // Trả về 403 Forbidden
            }

            // BƯỚC 5: ĐÁNH DẤU & CHUYỂN TIẾP (Header Enrichment)
            // Bổ sung thêm thông tin User (Username, Roles) vào Header của Request
            // để các Microservice phía sau có thể sử dụng trực tiếp mà không cần giải mã lại JWT
            ServerHttpRequest mutatedRequest = request.mutate()
                    .header("X-User-Id", username)
                    .header("X-User-Role", (roles != null && !roles.isEmpty()) ? String.join(",", roles) : "")
                    .build();

            // Cho phép Request đi tiếp xuống Microservice đích với Header đã được bổ sung
            return chain.filter(exchange.mutate().request(mutatedRequest).build());
        }

        // Nếu API KHÔNG CẦN BẢO MẬT (nằm trong danh sách Open API như /login, /register...) -> Cho qua thẳng
        return chain.filter(exchange);
    }

    /**
     * Hàm hỗ trợ ngắt luồng và trả về Response lỗi cho Client (401 hoặc 403)
     */
    private Mono<Void> onError(ServerWebExchange exchange, HttpStatus httpStatus, String err) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus); // Thiết lập HTTP Status Code (401 Unauthorized / 403 Forbidden)
        return response.setComplete();     // Hoàn tất và gửi phản hồi về ngay lập tức
    }

    /**
     * Thiết lập thứ tự ưu tiên của Filter
     * Trả về -1 để đảm bảo Filter này chạy ĐẦU TIÊN trong chuỗi Global Filters của Spring Cloud Gateway
     */
    @Override
    public int getOrder() {
        return -1;
    }
}