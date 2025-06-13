<?php
// Tệp debug.php - Đặt ở cùng thư mục với website.php
session_start();
error_reporting(E_ALL);
ini_set('display_errors', 1);

echo "<h2>🔍 DEBUG THÔNG TIN ĐĂNG NHẬP/ĐĂNG KÝ</h2>";

// 1. Kiểm tra cấu hình PHP
echo "<h3>1. Cấu hình PHP:</h3>";
echo "PHP Version: " . phpversion() . "<br>";
echo "Session ID: " . session_id() . "<br>";
echo "POST Max Size: " . ini_get('post_max_size') . "<br>";
echo "Upload Max Size: " . ini_get('upload_max_filesize') . "<br>";

// 2. Kiểm tra kết nối database
echo "<h3>2. Kết nối Database:</h3>";
$db_host = 'localhost';
$db_user = 'root';
$db_pass = '';
$db_name = 'sunflower_shop';

try {
    $pdo = new PDO("mysql:host=$db_host;dbname=$db_name;charset=utf8mb4", $db_user, $db_pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    echo "✅ Kết nối database thành công<br>";
    
    // Kiểm tra bảng
    $tables = ['danhmuc', 'sanpham', 'khachhang', 'donhang'];
    foreach($tables as $table) {
        $stmt = $pdo->query("SHOW TABLES LIKE '$table'");
        if($stmt->rowCount() > 0) {
            echo "✅ Bảng $table tồn tại<br>";
        } else {
            echo "❌ Bảng $table không tồn tại<br>";
        }
    }
    
} catch(PDOException $e) {
    echo "❌ Lỗi database: " . $e->getMessage() . "<br>";
    echo "<strong>Hướng dẫn sửa lỗi database:</strong><br>";
    echo "1. Kiểm tra XAMPP/WAMP đã khởi động<br>";
    echo "2. Mở phpMyAdmin tại http://localhost/phpmyadmin<br>";
    echo "3. Tạo database 'sunflower_shop'<br>";
    echo "4. Import SQL hoặc chạy script tạo bảng<br>";
}

// 3. Kiểm tra dữ liệu POST
echo "<h3>3. Dữ liệu POST (nếu có):</h3>";
if($_SERVER['REQUEST_METHOD'] == 'POST') {
    echo "<pre>";
    print_r($_POST);
    echo "</pre>";
} else {
    echo "Không có dữ liệu POST<br>";
}

// 4. Kiểm tra Session
echo "<h3>4. Thông tin Session:</h3>";
echo "<pre>";
print_r($_SESSION);
echo "</pre>";

// 5. Test CSRF Token
echo "<h3>5. Test CSRF Token:</h3>";
function generateCSRFToken() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

$token = generateCSRFToken();
echo "CSRF Token: " . $token . "<br>";

// 6. Test form đăng ký đơn giản
echo "<h3>6. Test Form Đăng Ký:</h3>";

if(isset($_POST['test_register'])) {
    echo "<h4>Xử lý đăng ký test:</h4>";
    
    $tendn = $_POST['tendn'] ?? '';
    $matkhau = $_POST['matkhau'] ?? '';
    $hoten = $_POST['hoten'] ?? '';
    $email = $_POST['email'] ?? '';
    $sodt = $_POST['sodt'] ?? '';
    
    echo "Tên đăng nhập: $tendn<br>";
    echo "Mật khẩu: " . (empty($matkhau) ? 'Trống' : 'Có dữ liệu') . "<br>";
    echo "Họ tên: $hoten<br>";
    echo "Email: $email<br>";
    echo "SĐT: $sodt<br>";
    
    // Validation đơn giản
    $errors = [];
    if(empty($tendn)) $errors[] = "Tên đăng nhập trống";
    if(empty($matkhau)) $errors[] = "Mật khẩu trống";
    if(empty($hoten)) $errors[] = "Họ tên trống";
    if(empty($email)) $errors[] = "Email trống";
    if(empty($sodt)) $errors[] = "SĐT trống";
    
    if(empty($errors)) {
        echo "✅ Validation thành công<br>";
        
        // Test insert database
        if(isset($pdo)) {
            try {
                $hashed_password = password_hash($matkhau, PASSWORD_DEFAULT);
                $stmt = $pdo->prepare("INSERT INTO khachhang (TenDN, MatKhau, HoTen, SoDT, Email) VALUES (?, ?, ?, ?, ?)");
                if($stmt->execute([$tendn, $hashed_password, $hoten, $sodt, $email])) {
                    echo "✅ Thêm tài khoản thành công!<br>";
                } else {
                    echo "❌ Lỗi thêm tài khoản<br>";
                }
            } catch(PDOException $e) {
                echo "❌ Lỗi SQL: " . $e->getMessage() . "<br>";
            }
        }
    } else {
        echo "❌ Lỗi validation:<br>";
        foreach($errors as $error) {
            echo "- $error<br>";
        }
    }
}

// 7. Test form đăng nhập đơn giản
if(isset($_POST['test_login'])) {
    echo "<h4>Xử lý đăng nhập test:</h4>";
    
    $tendn = $_POST['login_tendn'] ?? '';
    $matkhau = $_POST['login_matkhau'] ?? '';
    
    if(isset($pdo)) {
        try {
            $stmt = $pdo->prepare("SELECT MaKH, TenDN, MatKhau, HoTen FROM khachhang WHERE TenDN = ?");
            $stmt->execute([$tendn]);
            $user = $stmt->fetch();
            
            if(!$user) {
                echo "❌ Tài khoản không tồn tại<br>";
            } elseif(!password_verify($matkhau, $user['MatKhau'])) {
                echo "❌ Mật khẩu không đúng<br>";
            } else {
                echo "✅ Đăng nhập thành công!<br>";
                $_SESSION['user_id'] = $user['MaKH'];
                $_SESSION['username'] = $user['TenDN'];
                $_SESSION['fullname'] = $user['HoTen'];
            }
        } catch(PDOException $e) {
            echo "❌ Lỗi SQL: " . $e->getMessage() . "<br>";
        }
    }
}
?>

<style>
body { font-family: Arial, sans-serif; margin: 20px; }
h2, h3, h4 { color: #333; }
form { background: #f9f9f9; padding: 15px; margin: 10px 0; border-radius: 5px; }
input { margin: 5px 0; padding: 8px; width: 200px; }
button { padding: 10px 15px; background: #007bff; color: white; border: none; border-radius: 3px; cursor: pointer; }
button:hover { background: #0056b3; }
pre { background: #f8f8f8; padding: 10px; border-radius: 3px; overflow-x: auto; }
</style>

<!-- Form test đăng ký -->
<form method="POST">
    <h4>Test Đăng Ký:</h4>
    <input type="text" name="tendn" placeholder="Tên đăng nhập" required><br>
    <input type="password" name="matkhau" placeholder="Mật khẩu" required><br>
    <input type="text" name="hoten" placeholder="Họ tên" required><br>
    <input type="email" name="email" placeholder="Email" required><br>
    <input type="text" name="sodt" placeholder="Số điện thoại" required><br>
    <button type="submit" name="test_register">Test Đăng Ký</button>
</form>

<!-- Form test đăng nhập -->
<form method="POST">
    <h4>Test Đăng Nhập:</h4>
    <input type="text" name="login_tendn" placeholder="Tên đăng nhập" required><br>
    <input type="password" name="login_matkhau" placeholder="Mật khẩu" required><br>
    <button type="submit" name="test_login">Test Đăng Nhập</button>
</form>

<hr>
<h3>8. Danh sách tài khoản hiện có:</h3>
<?php
if(isset($pdo)) {
    try {
        $stmt = $pdo->query("SELECT MaKH, TenDN, HoTen, Email, NgayDK FROM khachhang ORDER BY NgayDK DESC LIMIT 10");
        $users = $stmt->fetchAll();
        
        if($users) {
            echo "<table border='1' cellpadding='5' cellspacing='0'>";
            echo "<tr><th>ID</th><th>Tên ĐN</th><th>Họ tên</th><th>Email</th><th>Ngày ĐK</th></tr>";
            foreach($users as $user) {
                echo "<tr>";
                echo "<td>{$user['MaKH']}</td>";
                echo "<td>{$user['TenDN']}</td>";
                echo "<td>{$user['HoTen']}</td>";
                echo "<td>{$user['Email']}</td>";
                echo "<td>{$user['NgayDK']}</td>";
                echo "</tr>";
            }
            echo "</table>";
        } else {
            echo "Chưa có tài khoản nào";
        }
    } catch(PDOException $e) {
        echo "Lỗi truy vấn: " . $e->getMessage();
    }
}
?>

<hr>
<h3>9. Hướng dẫn sửa lỗi:</h3>
<ol>
    <li><strong>Nếu lỗi database:</strong> Kiểm tra XAMPP/WAMP, tạo database 'sunflower_shop'</li>
    <li><strong>Nếu form không gửi được:</strong> Kiểm tra JavaScript console (F12)</li>
    <li><strong>Nếu CSRF lỗi:</strong> Xóa cookie và session</li>
    <li><strong>Nếu validation lỗi:</strong> Kiểm tra dữ liệu POST</li>
    <li><strong>Nếu password lỗi:</strong> Thử đăng ký tài khoản mới</li>
</ol>

<p><a href="website.php">← Quay lại trang chính</a></p>