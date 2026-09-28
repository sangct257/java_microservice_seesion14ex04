package ra.demo.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;


@RestController
@RequestMapping("/api/products")
public class ProductController {

    // Danh sách sản phẩm giả/tĩnh
    private final List<Map<String, Object>> products = new ArrayList<>(List.of(
            Map.of("id", 1, "name", "Laptop Dell XPS"),
            Map.of("id", 2, "name", "iPhone 15 Pro"),
            Map.of("id", 3, "name", "Samsung Galaxy S24")
    ));

    // GET /api/products: Cho phép mọi user đã đăng nhập (USER hoặc ADMIN)
    @GetMapping
    public ResponseEntity<?> getAllProducts() {
        return ResponseEntity.ok(products);
    }

    // DELETE /api/products/{id}: Chỉ cho phép User có Role ADMIN
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')") // Hoặc hasAuthority('ROLE_ADMIN')
    public ResponseEntity<?> deleteProduct(@PathVariable Long id) {
        return ResponseEntity.ok("Xóa thành công sản phẩm có ID: " + id);
    }
}
