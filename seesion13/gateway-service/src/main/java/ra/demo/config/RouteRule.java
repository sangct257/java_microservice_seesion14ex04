package ra.demo.config;

import org.springframework.util.AntPathMatcher;

import java.util.List;

/**
 * Class định nghĩa quy tắc phân quyền (Authorization Rule) cho một route hoặc API cụ thể.
 * Class này quyết định:
 * 1. Request nào sẽ bị áp dụng luật này (dựa vào URL và HTTP Method).
 * 2. User có những Role gì thì mới được phép truy cập (RBAC - Role-Based Access Control).
 */
public class RouteRule {
    // Đường dẫn (Pattern) cần áp dụng luật (ví dụ: "/identity/api/admin/**")
    private final String pathPattern;

    // Danh sách các HTTP Method áp dụng (POST, GET, PUT, DELETE...).
    // Nếu danh sách rỗng -> Áp dụng cho mọi HTTP Method.
    private final List<String> methods;

    // Danh sách các Role được phép truy cập (ví dụ: ["ADMIN", "MANAGER"]).
    // Nếu danh sách rỗng -> Bất kỳ ai đăng nhập thành công cũng truy cập được.
    private final List<String> requiredRoles;

    /**
     * Khởi tạo một quy tắc phân quyền cho route.
     *
     * @param pathPattern   Chuỗi ký tự hoặc pattern của đường dẫn cần kiểm tra (ví dụ: "/api/v1/categories")
     * @param methods       Danh sách các phương thức HTTP áp dụng quy tắc này (ví dụ: POST, PUT, DELETE).
     *                      Nếu rỗng nghĩa là áp dụng cho tất cả các phương thức.
     * @param requiredRoles Danh sách các vai trò (roles) yêu cầu để truy cập.
     *                      Nếu rỗng nghĩa là không yêu cầu vai trò cụ thể nào.
     */
    public RouteRule(String pathPattern, List<String> methods, List<String> requiredRoles) {
        this.pathPattern = pathPattern;
        this.methods = methods;
        this.requiredRoles = requiredRoles;
    }

    // Công cụ hỗ trợ so sánh đường dẫn URL theo chuẩn Ant Pattern (ví dụ: /api/** khớp với /api/users/1)
    private static final AntPathMatcher pathMatcher = new AntPathMatcher();

    /**
     * Kiểm tra xem request hiện tại từ client gửi lên có thuộc phạm vi quản lý của Rule này không.
     *
     * @param path   Đường dẫn (URI Path) thực tế từ request (ví dụ: "/identity/api/admin/users")
     * @param method Phương thức HTTP thực tế từ request (GET, POST, PUT, DELETE,...)
     * @return true nếu request hiện tại khớp với cả Path Pattern và HTTP Method của Rule này.
     */
    public boolean matches(String path, String method) {
        // 1. Kiểm tra URL: Khớp nếu path chứa chuỗi pattern HOẶC khớp với cấu trúc wildcard AntPathMatcher
        boolean pathMatch = path.contains(this.pathPattern) || pathMatcher.match(this.pathPattern, path);

        // 2. Kiểm tra HTTP Method: Khớp nếu luật không quy định method cụ thể (rỗng) HOẶC method gửi lên nằm trong danh sách
        boolean methodMatch = this.methods.isEmpty() || this.methods.contains(method);

        // Trả về true nếu CẢ TÍNH NĂNG PATH VÀ METHOD ĐỀU KHỚP
        return pathMatch && methodMatch;
    }

    /**
     * Xác thực xem danh sách vai trò (Roles) lấy từ JWT Token của người dùng có đủ quyền truy cập hay không.
     *
     * @param userRoles Danh sách vai trò (Roles) của người dùng trích xuất từ JWT Token
     * @return true nếu người dùng hợp lệ, ngược lại trả về false (không đủ quyền -> 403 Forbidden).
     */
    public boolean isAuthorized(List<String> userRoles) {
        // 1. Trường hợp Route không yêu cầu Role cụ thể nào -> Cho phép truy cập luôn
        if (requiredRoles.isEmpty()) {
            return true;
        }

        // 2. Trường hợp Route có yêu cầu Role nhưng User lại không có Role nào trong Token -> Tuối chối (Forbidden)
        if (userRoles.isEmpty()) {
            return false;
        }

        // 3. Kiểm tra xem User có sở hữu ÍT NHẤT 1 ROLE nằm trong danh sách Role yêu cầu (requiredRoles) hay không
        return userRoles.stream().anyMatch(requiredRoles::contains);
    }
}