package ra.demo.config;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.function.Predicate;

@Component // Đánh dấu là Spring Bean để có thể @Autowired sử dụng ở các lớp Filter
public class RouteValidator {

    /**
     * Danh sách các endpoint CÔNG KHAI (Open APIs), không cần kiểm tra JWT Token hay Phân quyền.
     * Bất kỳ ai cũng có thể truy cập các đường dẫn này mà không bị chặn.
     */
    public static final List<String> openApiEndpoints = List.of(
            "/identity-service/api/auth/",
            "/eureka"
    );

    /**
     * Predicate kiểm tra xem một Request gửi lên CÓ CẦN BẢO MẬT (Secured) hay không.
     *
     * Cách hoạt động:
     * 1. Duyệt qua danh sách 'openApiEndpoints'.
     * 2. 'noneMatch': Trả về true nếu KHÔNG CÓ url nào trong danh sách nằm trong path của Request.
     *
     * -> Nếu path nằm trong 'openApiEndpoints' -> isSecured = false (Không bảo mật, cho qua luôn).
     * -> Nếu path KHÔNG nằm trong 'openApiEndpoints' -> isSecured = true (Cần bảo mật, chuyển qua kiểm tra Token & Quyền).
     */
    public Predicate<ServerHttpRequest> isSecured = request -> openApiEndpoints
            .stream()
            .noneMatch(url -> request.getURI().getPath().contains(url));

    /**
     * Kiểm tra người dùng có đủ thẩm quyền (Roles) để truy cập API dựa trên quy tắc đã định nghĩa.
     *
     * @param path   Đường dẫn URI của request gửi lên (ví dụ: /product-service/api/v1/products)
     * @param method Phương thức HTTP (GET, POST, PUT, DELETE,...)
     * @param roles  Danh sách Role trích xuất từ JWT Token của người dùng
     * @return true nếu hợp lệ (được phép truy cập), false nếu không đủ quyền (bị từ chối - 403 Forbidden)
     */
    public boolean isAuthorized(String path, String method, List<String> roles) {
        // Duyệt qua từng quy tắc phân quyền trong danh sách AUTHORIZATION_RULES
        for (RouteRule rule : AUTHORIZATION_RULES) {
            // Nếu Request khớp với quy tắc này (cả Path lẫn HTTP Method)
            if (rule.matches(path, method)) {
                // Kiểm tra xem User có đủ Role yêu cầu hay không
                if (!rule.isAuthorized(roles)) {
                    return false; // Trả về false ngay nếu không đủ quyền
                }
            }
        }
        return true; // Nếu duyệt qua hết các luật hoặc không dính luật nào cấm -> Được phép truy cập
    }

    /**
     * Danh sách các quy tắc phân quyền (RBAC) áp dụng cho toàn bộ dự án.
     */
    private static final List<RouteRule> AUTHORIZATION_RULES = List.of(
            // Quy tắc 1: Các thao tác thay đổi dữ liệu (POST, PUT, PATH, DELETE) vào API sản phẩm -> Bắt buộc phải có ROLE_ADMIN
            // Lưu ý: "PATH" có thể là gõ nhầm của "PATCH"
            new RouteRule("/product-service/api/products/**", List.of("POST", "PUT", "PATH", "DELETE"), List.of("ROLE_ADMIN")),

            // Quy tắc 2: Thao tác xem (GET) sản phẩm -> Danh sách requiredRoles rỗng (List.of())
            // có nghĩa là chỉ cần Đăng nhập thành công (bất kỳ role nào) là có thể xem.
            new RouteRule("/product-service/api/products/**", List.of("GET"), List.of())
    );
}