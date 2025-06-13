<?php
session_start();

error_reporting(E_ERROR | E_PARSE);

// ===================== CAU HINH DATABASE =====================
$db_host = 'localhost';
$db_user = 'root';
$db_pass = '';
$db_name = 'sunflower_shop';

// Khoi tao bien PDO
$pdo = null;

try {
    $pdo = new PDO("mysql:host=$db_host;dbname=$db_name;charset=utf8mb4", $db_user, $db_pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch(PDOException $e) {
    // Se xu ly sau
}

// ===================== KHOI TAO BIEN TOAN CUC =====================
$page = isset($_GET['page']) ? $_GET['page'] : 'home';
$action = isset($_GET['action']) ? $_GET['action'] : '';
$message = '';
$error = '';

// Khoi tao bien admin
$total_products = 0;
$total_customers = 0; 
$total_orders = 0;
$customers = [];
$products = [];
$categories = [];

// Khoi tao bien filter
$category_filter = isset($_GET['dm']) ? (int)$_GET['dm'] : 0;
$type_filter = isset($_GET['type']) ? $_GET['type'] : '';
$search = isset($_GET['search']) ? $_GET['search'] : '';

// ===================== SECURITY FUNCTIONS =====================
function generateCSRFToken() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validateCSRFToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

function checkRateLimit($action, $max_attempts = 5, $time_window = 300) {
    $key = $action . '_' . $_SERVER['REMOTE_ADDR'];
    
    if (!isset($_SESSION['rate_limit'][$key])) {
        $_SESSION['rate_limit'][$key] = ['count' => 0, 'first_attempt' => time()];
    }
    
    $rate_data = $_SESSION['rate_limit'][$key];
    
    // Reset neu da qua time window
    if (time() - $rate_data['first_attempt'] > $time_window) {
        $_SESSION['rate_limit'][$key] = ['count' => 1, 'first_attempt' => time()];
        return true;
    }
    
    // Kiem tra so lan thu
    if ($rate_data['count'] >= $max_attempts) {
        return false;
    }
    
    $_SESSION['rate_limit'][$key]['count']++;
    return true;
}

// ===================== HELPER FUNCTIONS =====================
function formatCurrency($amount) {
    return number_format($amount, 0, ',', '.') . ' VND';
}

function sanitizeInput($data) {
    return htmlspecialchars(trim(stripslashes($data)));
}

function checkLogin() {
    return isset($_SESSION['user_id']);
}

function redirect($url) {
    header("Location: $url");
    exit();
}

function safeGetPost($key, $default = '') {
    return isset($_POST[$key]) ? sanitizeInput($_POST[$key]) : $default;
}

function safeGetGet($key, $default = '') {
    return isset($_GET[$key]) ? sanitizeInput($_GET[$key]) : $default;
}

function validateEmail($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

function validatePhone($phone) {
    // Kiem tra ma vung so dien thoai
    return preg_match('/^[0-9]{10,11}$/', $phone);
}

function validatePassword($password) {
    // It nhat tren 8 chu so
    return strlen($password) >= 8 && 
           preg_match('/[A-Z]/', $password) && 
           preg_match('/[a-z]/', $password) && 
           preg_match('/[0-9]/', $password);
}

// ===================== TAO DATABASE TU DONG (NEU CHUA CO) =====================
function createDatabase() {
    global $db_host, $db_user, $db_pass, $db_name;
    
    try {
        // Ket noi khong chi dinh database
        $pdo = new PDO("mysql:host=$db_host;charset=utf8mb4", $db_user, $db_pass);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        // Tao database
        $pdo->exec("CREATE DATABASE IF NOT EXISTS $db_name CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
        $pdo->exec("USE $db_name");
        
        // Tao bang
        $sql = "
        CREATE TABLE IF NOT EXISTS danhmuc (
            MaDM INT AUTO_INCREMENT PRIMARY KEY,
            TenDM VARCHAR(100) NOT NULL,
            MoTa TEXT
        );

        CREATE TABLE IF NOT EXISTS sanpham (
            MaSP INT AUTO_INCREMENT PRIMARY KEY,
            TenSP VARCHAR(200) NOT NULL,
            Gia DECIMAL(15,0) NOT NULL,
            TrongLuong VARCHAR(50),
            MoTa TEXT,
            Hinh VARCHAR(255),
            MaDM INT,
            SoLuong INT DEFAULT 0,
            NgayTao TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (MaDM) REFERENCES danhmuc(MaDM)
        );

        CREATE TABLE IF NOT EXISTS khachhang (
            MaKH INT AUTO_INCREMENT PRIMARY KEY,
            TenDN VARCHAR(50) UNIQUE NOT NULL,
            MatKhau VARCHAR(255) NOT NULL,
            HoTen VARCHAR(100) NOT NULL,
            SoDT VARCHAR(15) NOT NULL,
            Email VARCHAR(100) NOT NULL,
            DiaChi TEXT,
            NgayDK TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            TrangThai ENUM('active', 'inactive', 'banned') DEFAULT 'active',
            EmailVerified BOOLEAN DEFAULT FALSE,
            LastLogin TIMESTAMP NULL,
            LoginAttempts INT DEFAULT 0,
            LockedUntil TIMESTAMP NULL
        );

        CREATE TABLE IF NOT EXISTS donhang (
            MaDH INT AUTO_INCREMENT PRIMARY KEY,
            MaKH INT,
            NgayDat TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            TongTien DECIMAL(15,0) NOT NULL,
            TrangThai ENUM('Cho xu ly', 'Dang giao', 'Da giao', 'Da huy') DEFAULT 'Cho xu ly',
            FOREIGN KEY (MaKH) REFERENCES khachhang(MaKH)
        );
        ";
        
        $pdo->exec($sql);
        
        // Insert du lieu mau neu chua co
        $stmt = $pdo->query("SELECT COUNT(*) as count FROM danhmuc");
        if ($stmt->fetch()['count'] == 0) {
            $pdo->exec("
                INSERT INTO danhmuc (TenDM, MoTa) VALUES 
                ('Sua chua', 'Cac loai sua chua tuoi ngon'),
                ('Dien thoai', 'Cac loai smartphone cao cap'),
                ('Laptop', 'May tinh xach tay cac hang');

                INSERT INTO sanpham (TenSP, Gia, TrongLuong, MoTa, MaDM, Hinh) VALUES 
                ('Sua chua Ba Vi', 9000, '450 gram', 'Sua chua tuoi ngon tu Ba Vi', 1, 'suachuabavi.jpg'),
                ('Sua chua Vinamilk', 10000, '490 gram', 'Sua chua Vinamilk chat luong cao', 1, 'suachuavinamilk.jpg'),
                ('Sua chua TH', 11000, '480 gram', 'Sua chua TH organic', 1, 'suachuath.jpg'),
                ('iPhone', 32000000, '550g', 'iPhone cao cap', 2, 'iphone.jpg'),
                ('Samsung', 28000000, '600g', 'Samsung Galaxy series', 2, 'samsung.jpg'),
                ('Bphone', 6000000, '480g', 'Dien thoai Bphone Viet Nam', 2, 'bphone.jpg'),
                ('Laptop Asus VivoBook X507MA N4000', 12000000, '2.1kg', 'CPU: Intel Celeron, N4000, 1.10 GHz', 3, 'asus.jpg'),
                ('Laptop Dell Inspiron 5593 i5 1035G1', 17500000, '2.3kg', 'CPU: Intel Core i5 Ice Lake, 1035G1, 1.00 GHz', 3, 'dell.jpg');
            ");
        }
        
        return true;
    } catch(PDOException $e) {
        return false;
    }
}

// ===================== KIEM TRA VA TAO DATABASE =====================
if (!$pdo) {
    if (createDatabase()) {
        try {
            $pdo = new PDO("mysql:host=$db_host;dbname=$db_name;charset=utf8mb4", $db_user, $db_pass);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        } catch(PDOException $e) {
            die("Khong the ket noi database sau khi tao: " . $e->getMessage());
        }
    } else {
        die("Khong the tao database. Vui long kiem tra cau hinh MySQL.");
    }
}

// ===================== XU LY ACTIONS =====================

// Xu ly dang ky
if ($action == 'register' && $_SERVER['REQUEST_METHOD'] == 'POST') {
    // Kiểm tra CSRF token
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $error = 'Yêu cầu không hợp lệ. Vui lòng thử lại!';
    }
    // Kiem tra rate limiting
    elseif (!checkRateLimit('register', 3, 600)) {
        $error = 'Bạn đã thử đăng ký quá nhiều lần. Vui lòng thử lại sau 10 phút!';
    }
    else {
        $tendn = safeGetPost('tendn');
        $matkhau = isset($_POST['matkhau']) ? $_POST['matkhau'] : '';
        $nhaplai_matkhau = isset($_POST['nhaplai_matkhau']) ? $_POST['nhaplai_matkhau'] : '';
        $hoten = safeGetPost('hoten');
        $sodt = safeGetPost('sodt');
        $email = safeGetPost('email');
        
        // Validation nang cao
        if (empty($tendn)) {
            $error = 'Tên đăng nhập không được để trống!';
        } elseif (strlen($tendn) < 3 || strlen($tendn) > 50) {
            $error = 'Tên đăng nhập phải từ 3-50 ký tự!';
        } elseif (!preg_match('/^[a-zA-Z0-9_]+$/', $tendn)) {
            $error = 'Tên đăng nhập chỉ được chứa chữ cái, số và dấu gạch dưới!';
        } elseif (empty($matkhau)) {
            $error = 'Mật khẩu không được để trống!';
        } elseif (!validatePassword($matkhau)) {
            $error = 'Mật khẩu phải có ít nhất 8 ký tự, bao gồm chữ hoa, chữ thường và số!';
        } elseif ($matkhau !== $nhaplai_matkhau) {
            $error = 'Mật khẩu xác nhận không khớp!';
        } elseif (empty($hoten)) {
            $error = 'Họ tên không được để trống!';
        } elseif (strlen($hoten) < 2 || strlen($hoten) > 100) {
            $error = 'Họ tên phải từ 2-100 ký tự!';
        } elseif (!preg_match('/^[a-zA-ZÀ-ỹ\s]+$/', $hoten)) {
            $error = 'Họ tên chỉ được chứa chữ cái và khoảng trắng!';
        } elseif (empty($sodt)) {
            $error = 'Số điện thoại không được để trống!';
        } elseif (!validatePhone($sodt)) {
            $error = 'Số điện thoại không hợp lệ!';
        } elseif (empty($email)) {
            $error = 'Email không được để trống!';
        } elseif (!validateEmail($email)) {
            $error = 'Email không hợp lệ!';
        } else {
            try {
                // Kiem tra ten dang nhap da ton tai
                $stmt = $pdo->prepare("SELECT MaKH FROM khachhang WHERE TenDN = ?");
                $stmt->execute([$tendn]);
                if ($stmt->fetch()) {
                    $error = 'Tên đăng nhập đã được sử dụng!';
                } else {
                    // Kiem tra email da ton tai 
                    $stmt = $pdo->prepare("SELECT MaKH FROM khachhang WHERE Email = ?");
                    $stmt->execute([$email]);
                    if ($stmt->fetch()) {
                        $error = 'Email đã được sử dụng!';
                    } else {
                        // Kiem tra so diem thoai da ton tai
                        $stmt = $pdo->prepare("SELECT MaKH FROM khachhang WHERE SoDT = ?");
                        $stmt->execute([$sodt]);
                        if ($stmt->fetch()) {
                            $error = 'Số điện thoại đã được sử dụng!';
                        } else {
                            // Them nguoi dung moi
                            $hashed_password = password_hash($matkhau, PASSWORD_DEFAULT);
                            $stmt = $pdo->prepare("INSERT INTO khachhang (TenDN, MatKhau, HoTen, SoDT, Email) VALUES (?, ?, ?, ?, ?)");
                            if ($stmt->execute([$tendn, $hashed_password, $hoten, $sodt, $email])) {
                                $_SESSION['register_success'] = 'Đăng ký thành công! Bạn có thể đăng nhập ngay với tài khoản: ' . $tendn;
                                header('Location: ?page=login');
                                exit();
                            } else {
                                $error = 'Có lỗi xảy ra khi đăng ký! Vui lòng thử lại.';
                            }
                        }
                    }
                }
            } catch(PDOException $e) {
                $error = 'Lỗi hệ thống: ' . $e->getMessage();
            }
        }
    }
}

// Xu ly dang nhap
if ($action == 'login' && $_SERVER['REQUEST_METHOD'] == 'POST') {
    // Kiem tra CSRF token
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $error = 'Yêu cầu không hợp lệ. Vui lòng thử lại!';
    }
    // Kiem tra rate limiting
    elseif (!checkRateLimit('login', 5, 300)) {
        $error = 'Bạn đã thử đăng nhập quá nhiều lần. Vui lòng thử lại sau 5 phút!';
    }
    else {
        $tendn = safeGetPost('tendn');
        $matkhau = isset($_POST['matkhau']) ? $_POST['matkhau'] : '';
        $remember = isset($_POST['remember']) ? true : false;
        
        if (empty($tendn)) {
            $error = 'Vui lòng nhập tên đăng nhập!';
        } elseif (empty($matkhau)) {
            $error = 'Vui lòng nhập mật khẩu!';
        } else {
            try {
                $stmt = $pdo->prepare("SELECT MaKH, TenDN, MatKhau, HoTen, TrangThai, LoginAttempts, LockedUntil FROM khachhang WHERE TenDN = ?");
                $stmt->execute([$tendn]);
                $user = $stmt->fetch();
                
                if (!$user) {
                    $error = 'Tên đăng nhập không tồn tại!';
                } elseif ($user['TrangThai'] == 'banned') {
                    $error = 'Tài khoản của bạn đã bị khóa!';
                } elseif ($user['LockedUntil'] && strtotime($user['LockedUntil']) > time()) {
                    $error = 'Tài khoản tạm thời bị khóa do đăng nhập sai quá nhiều lần!';
                } elseif (!password_verify($matkhau, $user['MatKhau'])) {
                    // Tang so lan dang nhap sai
                    $loginAttempts = $user['LoginAttempts'] + 1;
                    $lockedUntil = null;
                    
                    if ($loginAttempts >= 5) {
                        $lockedUntil = date('Y-m-d H:i:s', time() + 1800); // Khóa 30 phút
                    }
                    
                    $stmt = $pdo->prepare("UPDATE khachhang SET LoginAttempts = ?, LockedUntil = ? WHERE MaKH = ?");
                    $stmt->execute([$loginAttempts, $lockedUntil, $user['MaKH']]);
                    
                    if ($loginAttempts >= 5) {
                        $error = 'Tài khoản đã bị khóa 30 phút do đăng nhập sai quá nhiều lần!';
                    } else {
                        $error = 'Mật khẩu không đúng! Còn ' . (5 - $loginAttempts) . ' lần thử.';
                    }
                } else {
                    // Dang nhap thanh cong
                    $_SESSION['user_id'] = $user['MaKH'];
                    $_SESSION['username'] = $user['TenDN'];
                    $_SESSION['fullname'] = $user['HoTen'];
                    
                    // Reset login attempts
                    $stmt = $pdo->prepare("UPDATE khachhang SET LoginAttempts = 0, LockedUntil = NULL, LastLogin = NOW() WHERE MaKH = ?");
                    $stmt->execute([$user['MaKH']]);
                    
                    // Xu ly remember me
                    if ($remember) {
                        $token = bin2hex(random_bytes(32));
                        setcookie('remember_token', $token, time() + (30 * 24 * 3600), '/', '', false, true);
                        // Luu token vào database (can tao bang remember_tokens)
                    }
                    
                    header('Location: ?page=home');
                    exit();
                }
            } catch(PDOException $e) {
                $error = 'Lỗi hệ thống: ' . $e->getMessage();
            }
        }
    }
}

// Xu ly dang xuat
if ($action == 'logout') {
    session_destroy();
    setcookie('remember_token', '', time() - 3600, '/');
    redirect('?page=home');
}

// Xu ly admin login
if ($action == 'admin_login' && $_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = isset($_POST['username']) ? $_POST['username'] : '';
    $password = isset($_POST['password']) ? $_POST['password'] : '';
    
    if ($username === 'admin' && $password === 'admin123') {
        $_SESSION['admin'] = true;
        redirect('?page=admin');
    } else {
        $error = 'Tên đăng nhập hoặc mật khẩu admin không đúng!';
    }
}

// Xu ly them vao gio hang
if ($action == 'add_to_cart' && $_SERVER['REQUEST_METHOD'] == 'POST') {
    header('Content-Type: application/json');
    
    if (!checkLogin()) {
        echo json_encode(['success' => false, 'message' => 'Vui lòng đăng nhập']);
        exit;
    }
    
    $product_id = isset($_POST['product_id']) ? (int)$_POST['product_id'] : 0;
    $quantity = isset($_POST['quantity']) ? (int)$_POST['quantity'] : 1;
    
    if ($product_id > 0 && $pdo) {
        try {
            // Lay thong tin san pham
            $stmt = $pdo->prepare("SELECT MaSP, TenSP, Gia FROM sanpham WHERE MaSP = ?");
            $stmt->execute([$product_id]);
            $product = $stmt->fetch();
            
            if ($product) {
                if (!isset($_SESSION['cart'])) {
                    $_SESSION['cart'] = [];
                }
                
                if (isset($_SESSION['cart'][$product_id])) {
                    $_SESSION['cart'][$product_id]['quantity'] += $quantity;
                } else {
                    $_SESSION['cart'][$product_id] = [
                        'id' => $product_id,
                        'name' => $product['TenSP'],
                        'price' => $product['Gia'],
                        'quantity' => $quantity
                    ];
                }
                
                echo json_encode(['success' => true, 'message' => 'Đã thêm vào giỏ hàng']);
            } else {
                echo json_encode(['success' => false, 'message' => 'Sản phẩm không tồn tại']);
            }
        } catch(PDOException $e) {
            echo json_encode(['success' => false, 'message' => 'Lỗi database']);
        }
    } else {
        echo json_encode(['success' => false, 'message' => 'Dữ liệu không hợp lệ']);
    }
    exit;
}

// Xu ly admin them san pham
if ($action == 'add_product' && $_SERVER['REQUEST_METHOD'] == 'POST' && isset($_SESSION['admin'])) {
    $tensp = safeGetPost('tensp');
    $gia = isset($_POST['gia']) ? (int)$_POST['gia'] : 0;
    $trong_luong = safeGetPost('trong_luong');
    $mota = safeGetPost('mota');
    $madm = isset($_POST['madm']) ? (int)$_POST['madm'] : 0;
    $hinh = safeGetPost('hinh');
    
    if (!empty($tensp) && $gia > 0 && $madm > 0) {
        try {
            $stmt = $pdo->prepare("INSERT INTO sanpham (TenSP, Gia, TrongLuong, MoTa, MaDM, Hinh) VALUES (?, ?, ?, ?, ?, ?)");
            if ($stmt->execute([$tensp, $gia, $trong_luong, $mota, $madm, $hinh])) {
                $message = 'Đã thêm sản phẩm thành công!';
            } else {
                $error = 'Có lỗi khi thêm sản phẩm!';
            }
        } catch(PDOException $e) {
            $error = 'Lỗi database: ' . $e->getMessage();
        }
    } else {
        $error = 'Vui lòng điền đầy đủ thông tin sản phẩm!';
    }
}

// Xu ly admin xoa san pham
if ($action == 'delete_product' && $_SERVER['REQUEST_METHOD'] == 'POST' && isset($_SESSION['admin'])) {
    $id = isset($_POST['product_id']) ? (int)$_POST['product_id'] : 0;
    if ($id > 0) {
        try {
            $stmt = $pdo->prepare("DELETE FROM sanpham WHERE MaSP = ?");
            if ($stmt->execute([$id])) {
                $message = 'Đã xóa sản phẩm thành công!';
            } else {
                $error = 'Có lỗi khi xóa sản phẩm!';
            }
        } catch(PDOException $e) {
            $error = 'Lỗi database: ' . $e->getMessage();
        }
    }
}

// Kiểm tra thông báo đăng ký thành công
if (isset($_SESSION['register_success'])) {
    $message = $_SESSION['register_success'];
    unset($_SESSION['register_success']);
}

// ===================== LAY DU LIEU AN TOAN =====================
try {
    if ($pdo) {
        // Lay danh muc
        $stmt = $pdo->query("SELECT * FROM danhmuc");
        $categories = $stmt ? $stmt->fetchAll() : [];
        
        // Lay san pham (co filter)
        $where_conditions = [];
        $params = [];

        if ($category_filter > 0) {
            $where_conditions[] = "sp.MaDM = ?";
            $params[] = $category_filter;
        }

        if ($type_filter) {
            switch($type_filter) {
                case 'sua_chua':
                    $where_conditions[] = "sp.TenSP LIKE ?";
                    $params[] = '%sua chua%';
                    break;
                case 'sua_tuoi':
                    $where_conditions[] = "sp.TenSP LIKE ?";
                    $params[] = '%sua tuoi%';
                    break;
            }
        }

        if ($search) {
            $where_conditions[] = "sp.TenSP LIKE ?";
            $params[] = "%$search%";
        }

        $where_clause = !empty($where_conditions) ? 'WHERE ' . implode(' AND ', $where_conditions) : '';

        $stmt = $pdo->prepare("SELECT sp.*, dm.TenDM FROM sanpham sp 
                               LEFT JOIN danhmuc dm ON sp.MaDM = dm.MaDM 
                               $where_clause
                               ORDER BY sp.NgayTao DESC");
        $stmt->execute($params);
        $products = $stmt ? $stmt->fetchAll() : [];

        // Thong ke cho admin
        if (isset($_SESSION['admin']) && $_SESSION['admin'] === true) {
            $stmt = $pdo->query("SELECT COUNT(*) as total FROM sanpham");
            $total_products = $stmt ? $stmt->fetch()['total'] : 0;
            
            $stmt = $pdo->query("SELECT COUNT(*) as total FROM khachhang");
            $total_customers = $stmt ? $stmt->fetch()['total'] : 0;
            
            $stmt = $pdo->query("SELECT COUNT(*) as total FROM donhang");
            $total_orders = $stmt ? $stmt->fetch()['total'] : 0;
            
            // Lay danh sach khach hang
            $stmt = $pdo->query("SELECT * FROM khachhang ORDER BY NgayDK DESC");
            $customers = $stmt ? $stmt->fetchAll() : [];
        }
    }
} catch(PDOException $e) {
    $error = "Lỗi truy vấn database: " . $e->getMessage();
    // Khoi tao gia tri mac dinh
    $categories = [];
    $products = [];
    $customers = [];
}

// Script tao database tu dong (chay mot lan)
if ($action == 'create_database') {
    if (createDatabase()) {
        echo json_encode(['success' => true]);
    } else {
        echo json_encode(['success' => false]);
    }
    exit;
}
?>

<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php 
        switch($page) {
            case 'login': echo 'Đăng nhập - '; break;
            case 'register': echo 'Đăng ký - '; break;
            case 'products': echo 'Sản phẩm - '; break;
            case 'admin': echo 'Quản trị - '; break;
            default: echo 'Trang chủ - '; break;
        }
    ?>Cửa hàng Hướng dương</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f8f9fa;
        }

        .header-banner {
            background: linear-gradient(135deg, #4a5d23, #8fbc8f);
            color: white;
            text-align: center;
            padding: 10px 0;
            font-size: 14px;
        }

        .sunflower-banner {
            background: linear-gradient(45deg, #f4e155, #ff8c00), url('images/banner.jpg');
            background-size: cover;
            background-position: center;
            background-blend-mode: multiply;
            height: 200px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.5);
            position: relative;
            overflow: hidden;
        }

        @keyframes float {
            0%, 100% { transform: translateY(0px); }
            50% { transform: translateY(-20px); }
        }

        .banner-content h1 {
            font-size: 3em;
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 2px;
            z-index: 1;
            position: relative;
        }

        .banner-content p {
            font-size: 1.2em;
            max-width: 800px;
            margin: 0 auto;
            z-index: 1;
            position: relative;
        }

        .contact-buttons {
            margin-top: 20px;
            z-index: 1;
            position: relative;
        }

        .btn {
            display: inline-block;
            padding: 12px 25px;
            margin: 0 10px;
            background: #ff6b35;
            color: white;
            text-decoration: none;
            border-radius: 25px;
            font-weight: bold;
            transition: all 0.3s ease;
            border: none;
            cursor: pointer;
            font-size: 14px;
        }

        .btn:hover {
            background: #e55a2b;
            transform: translateY(-2px);
        }

        .btn-primary {
            background: #007bff;
        }

        .btn-primary:hover {
            background: #0056b3;
        }

        .btn-success {
            background: #28a745;
        }

        .btn-success:hover {
            background: #218838;
        }

        .btn-danger {
            background: #dc3545;
        }

        .btn-danger:hover {
            background: #c82333;
        }

        .navbar {
            background: #ff6b35;
            padding: 0;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }

        .nav-container {
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            align-items: center;
        }

        .nav-menu {
            display: flex;
            list-style: none;
            margin: 0;
            width: 100%;
        }

        .nav-item {
            flex: 1;
        }

        .nav-link {
            display: block;
            color: white;
            text-decoration: none;
            padding: 15px 20px;
            text-align: center;
            font-weight: bold;
            text-transform: uppercase;
            transition: background 0.3s ease;
            border-right: 1px solid rgba(255,255,255,0.2);
        }

        .nav-link:hover, .nav-link.active {
            background: rgba(255,255,255,0.2);
        }

        .user-menu {
            display: flex;
            align-items: center;
            gap: 15px;
            padding: 0 20px;
            color: white;
        }

        .sidebar {
            width: 250px;
            background: #ff6b35;
            padding: 20px;
            color: white;
            float: left;
            min-height: 500px;
        }

        .sidebar h3 {
            color: white;
            margin-bottom: 15px;
            font-size: 18px;
            text-transform: uppercase;
            border-bottom: 2px solid rgba(255,255,255,0.3);
            padding-bottom: 10px;
        }

        .sidebar ul {
            list-style: none;
        }

        .sidebar li {
            margin-bottom: 8px;
        }

        .sidebar a {
            color: white;
            text-decoration: none;
            display: block;
            padding: 8px 15px;
            border-radius: 5px;
            transition: background 0.3s ease;
        }

        .sidebar a:hover, .sidebar a.active {
            background: rgba(255,255,255,0.2);
        }

        .main-content {
            margin-left: 270px;
            padding: 20px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }

        .student-form {
            background: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }

        .student-form h2 {
            color: #0066cc;
            margin-bottom: 20px;
            font-size: 24px;
        }

        .form-row {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 20px;
            margin-bottom: 20px;
        }

        .form-row label {
            font-weight: bold;
            color: #333;
        }

        .form-row input {
            padding: 8px 12px;
            border: 1px solid #ddd;
            border-radius: 5px;
            min-width: 200px;
        }

        .search-form {
            margin-bottom: 20px;
            text-align: center;
        }

        .search-form input {
            padding: 10px;
            width: 300px;
            border: 1px solid #ddd;
            border-radius: 5px 0 0 5px;
            border-right: none;
        }

        .search-form button {
            padding: 10px 20px;
            background: #007bff;
            color: white;
            border: 1px solid #007bff;
            border-radius: 0 5px 5px 0;
            cursor: pointer;
        }

        .products-section h2 {
            color: #0066cc;
            text-align: center;
            margin-bottom: 30px;
            font-size: 28px;
            text-transform: uppercase;
        }

        .products-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .product-card {
            background: white;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            overflow: hidden;
            transition: transform 0.3s ease;
        }

        .product-card:hover {
            transform: translateY(-5px);
        }

        .product-image {
            width: 100%;
            height: 200px;
            background: #f8f9fa;
            display: flex;
            align-items: center;
            justify-content: center;
            overflow: hidden;
            position: relative;
        }

        .product-image img {
            width: 100%;
            height: 100%;
            object-fit: cover;
            transition: transform 0.3s ease;
        }

        .product-image:hover img {
            transform: scale(1.05);
        }

        .product-image.no-image {
            background: linear-gradient(45deg, #f0f0f0, #e0e0e0);
            font-size: 14px;
            color: #666;
        }

        .product-info {
            padding: 20px;
        }

        .product-info h3 {
            color: #0066cc;
            margin-bottom: 10px;
            font-size: 18px;
        }

        .product-price {
            font-size: 20px;
            font-weight: bold;
            color: #e74c3c;
            margin-bottom: 10px;
        }

        .product-weight {
            color: #666;
            margin-bottom: 15px;
        }

        .add-to-cart {
            background: #28a745;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
            width: 100%;
            transition: background 0.3s ease;
        }

        .add-to-cart:hover {
            background: #218838;
        }

        /* ==============================================
           IMPROVED LOGIN & REGISTER STYLES
           ============================================== */

        .auth-container {
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            position: relative;
            padding: 20px;
        }

        .auth-container::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><defs><pattern id="grain" width="100" height="100" patternUnits="userSpaceOnUse"><circle cx="50" cy="50" r="0.5" fill="rgba(255,255,255,0.1)"/></pattern></defs><rect width="100" height="100" fill="url(%23grain)"/></svg>') repeat;
            opacity: 0.3;
        }

        .auth-card {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            box-shadow: 0 25px 50px rgba(0, 0, 0, 0.25);
            padding: 40px;
            width: 100%;
            max-width: 450px;
            position: relative;
            z-index: 1;
            animation: slideUp 0.8s ease-out;
        }

        @keyframes slideUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .auth-header {
            text-align: center;
            margin-bottom: 30px;
        }

        .auth-header .logo {
            width: 80px;
            height: 80px;
            background: linear-gradient(135deg, #ff6b35, #f7931e);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 20px;
            font-size: 32px;
            color: white;
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.05); }
        }

        .auth-header h2 {
            color: #2c3e50;
            font-size: 28px;
            font-weight: 700;
            margin-bottom: 10px;
        }

        .auth-header p {
            color: #7f8c8d;
            font-size: 16px;
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #2c3e50;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .form-group .input-wrapper {
            position: relative;
        }

        .form-group input {
            width: 100%;
            padding: 15px 20px;
            border: 2px solid #e9ecef;
            border-radius: 10px;
            font-size: 16px;
            transition: all 0.3s ease;
            background: #f8f9fa;
        }

        .form-group input:focus {
            outline: none;
            border-color: #007bff;
            background: white;
            box-shadow: 0 0 0 3px rgba(0, 123, 255, 0.1);
        }

        .form-group input.error {
            border-color: #dc3545;
            background: #fff5f5;
        }

        .form-group input.success {
            border-color: #28a745;
            background: #f8fff8;
        }

        .form-group .icon {
            position: absolute;
            right: 15px;
            top: 50%;
            transform: translateY(-50%);
            color: #6c757d;
            font-size: 18px;
        }

        .form-group .toggle-password {
            cursor: pointer;
            transition: color 0.3s ease;
        }

        .form-group .toggle-password:hover {
            color: #007bff;
        }

        .form-group .error-message {
            color: #dc3545;
            font-size: 12px;
            margin-top: 5px;
            animation: shake 0.5s ease-in-out;
        }

        .form-group .success-message {
            color: #28a745;
            font-size: 12px;
            margin-top: 5px;
        }

        @keyframes shake {
            0%, 100% { transform: translateX(0); }
            25% { transform: translateX(-5px); }
            75% { transform: translateX(5px); }
        }

        .password-strength {
            margin-top: 8px;
        }

        .password-strength-bar {
            height: 4px;
            background: #e9ecef;
            border-radius: 2px;
            overflow: hidden;
            margin-bottom: 5px;
        }

        .password-strength-fill {
            height: 100%;
            transition: all 0.3s ease;
            border-radius: 2px;
        }

        .password-strength-fill.weak {
            width: 33%;
            background: #dc3545;
        }

        .password-strength-fill.medium {
            width: 66%;
            background: #ffc107;
        }

        .password-strength-fill.strong {
            width: 100%;
            background: #28a745;
        }

        .password-strength-text {
            font-size: 12px;
            color: #6c757d;
        }

        .checkbox-group {
            display: flex;
            align-items: center;
            gap: 10px;
            margin: 20px 0;
        }

        .checkbox-group input[type="checkbox"] {
            width: 18px;
            height: 18px;
            cursor: pointer;
        }

        .checkbox-group label {
            margin: 0;
            font-weight: normal;
            color: #6c757d;
            cursor: pointer;
            text-transform: none;
            letter-spacing: normal;
            font-size: 14px;
        }

        .auth-btn {
            width: 100%;
            padding: 15px;
            background: linear-gradient(135deg, #007bff, #0056b3);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            text-transform: uppercase;
            letter-spacing: 1px;
            position: relative;
            overflow: hidden;
        }

        .auth-btn::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
            transition: left 0.5s ease;
        }

        .auth-btn:hover::before {
            left: 100%;
        }

        .auth-btn:hover {
            background: linear-gradient(135deg, #0056b3, #004085);
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(0, 123, 255, 0.3);
        }

        .auth-btn:active {
            transform: translateY(0);
        }

        .auth-btn.loading {
            pointer-events: none;
            opacity: 0.7;
        }

        .auth-btn.loading::after {
            content: '';
            position: absolute;
            top: 50%;
            left: 50%;
            width: 20px;
            height: 20px;
            margin: -10px 0 0 -10px;
            border: 2px solid transparent;
            border-top: 2px solid white;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .auth-footer {
            text-align: center;
            margin-top: 25px;
            padding-top: 25px;
            border-top: 1px solid #e9ecef;
        }

        .auth-footer p {
            color: #6c757d;
            font-size: 14px;
            margin-bottom: 10px;
        }

        .auth-footer a {
            color: #007bff;
            text-decoration: none;
            font-weight: 600;
            transition: color 0.3s ease;
        }

        .auth-footer a:hover {
            color: #0056b3;
            text-decoration: underline;
        }

        .alert {
            padding: 15px 20px;
            margin-bottom: 20px;
            border-radius: 10px;
            font-weight: 500;
            animation: fadeIn 0.5s ease-out;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .alert-success {
            background: linear-gradient(135deg, #d4edda, #c3e6cb);
            color: #155724;
            border: 1px solid #c3e6cb;
        }

        .alert-danger {
            background: linear-gradient(135deg, #f8d7da, #f5c6cb);
            color: #721c24;
            border: 1px solid #f5c6cb;
        }

        .alert-info {
            background: linear-gradient(135deg, #d1ecf1, #bee5eb);
            color: #0c5460;
            border: 1px solid #bee5eb;
        }

        .security-tips {
            background: linear-gradient(135deg, #fff3cd, #ffeaa7);
            border: 1px solid #ffeaa7;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
        }

        .security-tips h4 {
            color: #856404;
            margin-bottom: 15px;
            font-size: 16px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .security-tips ul {
            margin-left: 20px;
            color: #856404;
        }

        .security-tips li {
            margin-bottom: 8px;
            font-size: 14px;
        }

        .loading-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 9999;
            opacity: 0;
            visibility: hidden;
            transition: all 0.3s ease;
        }

        .loading-overlay.show {
            opacity: 1;
            visibility: visible;
        }

        .loading-spinner {
            width: 60px;
            height: 60px;
            border: 4px solid rgba(255, 255, 255, 0.3);
            border-top: 4px solid white;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }

        .debug-info {
            background: #fff3cd;
            color: #856404;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 20px;
            font-size: 12px;
        }

        .table {
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }

        .table th, .table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }

        .table th {
            background: #f8f9fa;
            font-weight: bold;
        }

        .dashboard-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }

        .stat-card h3 {
            color: #666;
            font-size: 14px;
            text-transform: uppercase;
            margin-bottom: 10px;
        }

        .stat-card .number {
            font-size: 36px;
            font-weight: bold;
            color: #2c3e50;
        }

        .tabs {
            display: flex;
            background: white;
            border-radius: 10px 10px 0 0;
            overflow: hidden;
        }

        .tab {
            padding: 15px 25px;
            cursor: pointer;
            background: #f8f9fa;
            border-right: 1px solid #dee2e6;
            transition: background 0.3s ease;
        }

        .tab:hover, .tab.active {
            background: #007bff;
            color: white;
        }

        .tab-content {
            display: none;
            background: white;
            padding: 20px;
            border-radius: 0 0 10px 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }

        .tab-content.active {
            display: block;
        }

        .clearfix::after {
            content: "";
            display: table;
            clear: both;
        }

        .footer-banner {
            background: linear-gradient(rgba(44, 85, 48, 0.8), rgba(44, 85, 48, 0.8)), url('images/banner.jpg');
            background-size: cover;
            background-position: center;
            background-attachment: fixed;
            color: white;
            text-align: center;
            padding: 50px 20px;
            margin-top: 50px;
            position: relative;
        }

        .footer-banner h3 {
            color: #ffd700;
            font-size: 24px;
            margin-bottom: 15px;
        }

        .footer-contact {
            margin-top: 30px;
        }

        .contact-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .contact-item {
            display: flex;
            align-items: center;
            gap: 15px;
            background: rgba(255, 255, 255, 0.1);
            padding: 20px;
            border-radius: 10px;
            backdrop-filter: blur(5px);
        }

        .contact-icon {
            font-size: 24px;
            background: rgba(255, 255, 255, 0.2);
            padding: 10px;
            border-radius: 50%;
            width: 50px;
            height: 50px;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .contact-details strong {
            display: block;
            font-size: 12px;
            color: #ffd700;
            margin-bottom: 5px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .phone-number, .chat-link, .email-link {
            color: white;
            text-decoration: none;
            font-size: 16px;
            font-weight: bold;
            transition: all 0.3s ease;
        }

        .phone-number:hover, .chat-link:hover, .email-link:hover {
            color: #ffd700;
            text-shadow: 0 0 10px rgba(255, 215, 0, 0.5);
        }

        .footer-buttons {
            display: flex;
            justify-content: center;
            gap: 20px;
            flex-wrap: wrap;
        }

        .footer-btn {
            display: inline-block;
            padding: 15px 30px;
            border-radius: 30px;
            text-decoration: none;
            font-weight: bold;
            font-size: 16px;
            text-transform: uppercase;
            letter-spacing: 1px;
            transition: all 0.3s ease;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
        }

        .footer-btn.primary {
            background: linear-gradient(45deg, #ff6b35, #f7931e);
            color: white;
            animation: pulse 2s infinite;
        }

        .footer-btn.secondary {
            background: linear-gradient(45deg, #28a745, #20c997);
            color: white;
        }

        .footer-btn:hover {
            transform: translateY(-3px);
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.3);
        }

        @media (max-width: 768px) {
            .sidebar {
                width: 100%;
                float: none;
                min-height: auto;
            }
            
            .main-content {
                margin-left: 0;
            }
            
            .nav-menu {
                flex-direction: column;
            }
            
            .banner-content h1 {
                font-size: 2em;
            }
            
            .search-form input {
                width: 200px;
            }

            .contact-info {
                grid-template-columns: 1fr;
            }
            
            .footer-buttons {
                flex-direction: column;
                align-items: center;
            }
            
            .footer-btn {
                width: 250px;
                text-align: center;
            }

            .auth-card {
                margin: 20px;
                padding: 30px 20px;
            }
        }
    </style>
</head>
<body>
    <!-- Loading Overlay -->
    <div class="loading-overlay" id="loadingOverlay">
        <div class="loading-spinner"></div>
    </div>

    <!-- Header Banner -->
    <div class="header-banner">
        <p>📞 Hotline: 098.111.6066 | ✉️ Email: contact@sunflowershop.vn | 🚚 Miễn phí giao hàng toàn quốc</p>
    </div>

    <?php if ($page != 'admin' && $page != 'login' && $page != 'register'): ?>
    <!-- Sunflower Banner -->
    <div class="sunflower-banner">
        <div class="banner-content">
            <h1>Cửa hàng Hướng dương</h1>
            <?php if ($page == 'home'): ?>
            <p>Chào mừng bạn đến với cửa hàng Hướng dương - nơi cung cấp sản phẩm chất lượng cao!</p>
            <?php endif; ?>
        </div>
    </div>

    <!-- Navigation -->
    <nav class="navbar">
        <div class="nav-container">
            <ul class="nav-menu">
                <li class="nav-item"><a href="?page=home" class="nav-link <?php echo $page == 'home' ? 'active' : ''; ?>">TRANG CHỦ</a></li>
                <li class="nav-item"><a href="?page=products" class="nav-link <?php echo $page == 'products' ? 'active' : ''; ?>">CỬA HÀNG</a></li>
                <li class="nav-item"><a href="?page=news" class="nav-link">TIN TỨC</a></li>
                <li class="nav-item"><a href="?page=jobs" class="nav-link">TUYỂN DỤNG</a></li>
                <li class="nav-item"><a href="?page=contact" class="nav-link">LIÊN HỆ</a></li>
            </ul>
            <div class="user-menu">
                <?php if (checkLogin()): ?>
                    <span>Xin chào, <?php echo isset($_SESSION['fullname']) ? $_SESSION['fullname'] : ''; ?>!</span>
                    <a href="?page=cart" class="btn btn-primary">Giỏ hàng (<?php echo isset($_SESSION['cart']) ? count($_SESSION['cart']) : 0; ?>)</a>
                    <a href="?action=logout" class="btn btn-danger">Đăng xuất</a>
                <?php else: ?>
                    <a href="?page=login" class="btn btn-primary">Đăng nhập</a>
                    <a href="?page=register" class="btn btn-success">Đăng ký</a>
                <?php endif; ?>
                <a href="?page=admin" class="btn" style="background: #6c757d;">Admin</a>
            </div>
        </div>
    </nav>
    <?php endif; ?>

    <!-- CONTENT PAGES -->
    <?php if ($page == 'login'): ?>
    <!-- TRANG ĐĂNG NHẬP -->
    <div class="auth-container">
        <div class="auth-card">
            <div class="auth-header">
                <div class="logo">🌻</div>
                <h2>Đăng nhập</h2>
                <p>Chào mừng bạn quay trở lại!</p>
            </div>

            <?php if (!empty($message)): ?>
                <div class="alert alert-success"><?php echo $message; ?></div>
            <?php endif; ?>

            <?php if (!empty($error)): ?>
                <div class="alert alert-danger"><?php echo $error; ?></div>
            <?php endif; ?>

            <form method="POST" action="?page=login" id="loginForm">
                <input type="hidden" name="action" value="login">
                <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                
                <div class="form-group">
                    <label>👤 Tên đăng nhập</label>
                    <div class="input-wrapper">
                        <input type="text" name="tendn" id="username" 
                               value="<?php echo isset($_POST['tendn']) ? htmlspecialchars($_POST['tendn']) : ''; ?>" 
                               required autocomplete="username">
                        <span class="icon">👤</span>
                    </div>
                    <div class="error-message" id="usernameError"></div>
                </div>

                <div class="form-group">
                    <label>🔒 Mật khẩu</label>
                    <div class="input-wrapper">
                        <input type="password" name="matkhau" id="password" required autocomplete="current-password">
                        <span class="icon toggle-password" onclick="togglePassword('password')">👁️</span>
                    </div>
                    <div class="error-message" id="passwordError"></div>
                </div>

                <div class="checkbox-group">
                    <input type="checkbox" name="remember" id="remember">
                    <label for="remember">Ghi nhớ đăng nhập</label>
                </div>

                <button type="submit" class="auth-btn" id="loginBtn">
                    Đăng nhập
                </button>
            </form>

            <div class="auth-footer">
                <p>Chưa có tài khoản? <a href="?page=register">Đăng ký ngay</a></p>
                <p><a href="#" onclick="alert('Tính năng sẽ được phát triển!')">Quên mật khẩu?</a></p>
            </div>
        </div>
    </div>

    <?php elseif ($page == 'register'): ?>
    <!-- TRANG ĐĂNG KÝ -->
    <div class="auth-container">
        <div class="auth-card">
            <div class="auth-header">
                <div class="logo">📝</div>
                <h2>Đăng ký thành viên</h2>
                <p>Tạo tài khoản mới để bắt đầu mua sắm</p>
            </div>

            <?php if (!empty($message)): ?>
                <div class="alert alert-success"><?php echo $message; ?></div>
            <?php endif; ?>

            <?php if (!empty($error)): ?>
                <div class="alert alert-danger"><?php echo $error; ?></div>
            <?php endif; ?>

            <div class="security-tips">
                <h4>🔒 Lưu ý bảo mật:</h4>
                <ul>
                    <li>Mật khẩu phải có ít nhất 8 ký tự</li>
                    <li>Bao gồm chữ hoa, chữ thường và số</li>
                    <li>Tên đăng nhập chỉ chứa chữ cái, số và dấu gạch dưới</li>
                    <li>Email phải có định dạng hợp lệ</li>
                    <li>Số điện thoại phải là số Việt Nam (10-11 số)</li>
                </ul>
            </div>

            <form method="POST" action="?page=register" id="registerForm">
                <input type="hidden" name="action" value="register">
                <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                
                <div class="form-group">
                    <label>Tên đăng nhập <span style="color: red;">(*)</span></label>
                    <div class="input-wrapper">
                        <input type="text" name="tendn" id="reg_username" 
                               value="<?php echo isset($_POST['tendn']) ? htmlspecialchars($_POST['tendn']) : ''; ?>" 
                               required autocomplete="username">
                        <span class="icon">👤</span>
                    </div>
                    <div class="error-message" id="regUsernameError"></div>
                    <div class="success-message" id="regUsernameSuccess"></div>
                </div>

                <div class="form-group">
                    <label>Mật khẩu <span style="color: red;">(*)</span></label>
                    <div class="input-wrapper">
                        <input type="password" name="matkhau" id="reg_password" required autocomplete="new-password">
                        <span class="icon toggle-password" onclick="togglePassword('reg_password')">👁️</span>
                    </div>
                    <div class="password-strength" id="passwordStrength">
                        <div class="password-strength-bar">
                            <div class="password-strength-fill" id="passwordStrengthFill"></div>
                        </div>
                        <div class="password-strength-text" id="passwordStrengthText">Độ mạnh mật khẩu</div>
                    </div>
                    <div class="error-message" id="regPasswordError"></div>
                </div>

                <div class="form-group">
                    <label>Nhập lại mật khẩu <span style="color: red;">(*)</span></label>
                    <div class="input-wrapper">
                        <input type="password" name="nhaplai_matkhau" id="reg_confirm_password" required autocomplete="new-password">
                        <span class="icon toggle-password" onclick="togglePassword('reg_confirm_password')">👁️</span>
                    </div>
                    <div class="error-message" id="regConfirmPasswordError"></div>
                    <div class="success-message" id="regConfirmPasswordSuccess"></div>
                </div>

                <div class="form-group">
                    <label>Họ và tên <span style="color: red;">(*)</span></label>
                    <div class="input-wrapper">
                        <input type="text" name="hoten" id="reg_fullname" 
                               value="<?php echo isset($_POST['hoten']) ? htmlspecialchars($_POST['hoten']) : ''; ?>" 
                               required autocomplete="name">
                        <span class="icon">👨‍👩‍👧‍👦</span>
                    </div>
                    <div class="error-message" id="regFullnameError"></div>
                    <div class="success-message" id="regFullnameSuccess"></div>
                </div>

                <div class="form-group">
                    <label>Số điện thoại <span style="color: red;">(*)</span></label>
                    <div class="input-wrapper">
                        <input type="tel" name="sodt" id="reg_phone" 
                               value="<?php echo isset($_POST['sodt']) ? htmlspecialchars($_POST['sodt']) : ''; ?>" 
                               required autocomplete="tel">
                        <span class="icon">📱</span>
                    </div>
                    <div class="error-message" id="regPhoneError"></div>
                    <div class="success-message" id="regPhoneSuccess"></div>
                </div>

                <div class="form-group">
                    <label>Email <span style="color: red;">(*)</span></label>
                    <div class="input-wrapper">
                        <input type="email" name="email" id="reg_email" 
                               value="<?php echo isset($_POST['email']) ? htmlspecialchars($_POST['email']) : ''; ?>" 
                               required autocomplete="email">
                        <span class="icon">✉️</span>
                    </div>
                    <div class="error-message" id="regEmailError"></div>
                    <div class="success-message" id="regEmailSuccess"></div>
                </div>

                <div class="checkbox-group">
                    <input type="checkbox" name="agree_terms" id="agree_terms" required>
                    <label for="agree_terms">Tôi đồng ý với <a href="#" onclick="alert('Điều khoản sử dụng')">Điều khoản sử dụng</a> và <a href="#" onclick="alert('Chính sách bảo mật')">Chính sách bảo mật</a></label>
                </div>

                <button type="submit" class="auth-btn" id="registerBtn">
                    Đăng ký tài khoản
                </button>
            </form>

            <div class="auth-footer">
                <p>Đã có tài khoản? <a href="?page=login">Đăng nhập ngay</a></p>
            </div>
        </div>
    </div>

    <?php elseif ($page == 'home'): ?>
    <!-- TRANG CHỦ -->
    <div class="clearfix">
        <div class="sidebar">
            <h3>Khuyến mãi</h3>
            <ul>
                <li><a href="?page=products" class="<?php echo $page == 'products' && !$category_filter ? 'active' : ''; ?>">SẢN PHẨM</a></li>
                <li><a href="?page=products&type=sua_tuoi">SỮA TƯƠI</a></li>
                <li><a href="?page=products&type=sua_dac">SỮA ĐẶC</a></li>
                <li><a href="?page=products&type=sua_chua" class="<?php echo $type_filter == 'sua_chua' ? 'active' : ''; ?>">SỮA CHUA</a></li>
            </ul>
        </div>

        <div class="main-content">
            <!-- Student Information Form -->
            <div class="student-form">
                <h2>Thong Tin Sinh Vien </h2>
                <div class="form-row">
                    <label>Họ và tên sinh viên: </label>
                    <input type="text" placeholder="Dinh Nam" />
                </div>
                <div class="form-row">
                    <label>Lớp:</label>
                    <input type="text" placeholder="CDK17 CNTTA" />
                </div>
            </div>

            <!-- Search Form -->
            <div class="search-form">
                <form method="GET">
                    <input type="hidden" name="page" value="products">
                    <input type="text" name="search" placeholder="Nhập tên sản phẩm cần tìm..." value="<?php echo htmlspecialchars($search); ?>">
                    <button type="submit">Tìm kiếm</button>
                </form>
            </div>

            <!-- Products Section -->
            <div class="products-section">
                <h2>Danh sách sản phẩm</h2>
                <div class="products-grid">
                    <?php if (is_array($products) && count($products) > 0): ?>
                        <?php foreach(array_slice($products, 0, 6) as $product): ?>
                        <div class="product-card">
                            <div class="product-image">
                                <?php if (!empty($product['Hinh']) && file_exists('images/products/' . $product['Hinh'])): ?>
                                    <img src="images/products/<?php echo htmlspecialchars($product['Hinh']); ?>" 
                                         alt="<?php echo htmlspecialchars($product['TenSP']); ?>"
                                         onerror="this.parentElement.innerHTML='<span>📦 <?php echo htmlspecialchars($product['TenSP']); ?></span>'; this.parentElement.classList.add('no-image');">
                                <?php else: ?>
                                    <span>📦 <?php echo htmlspecialchars($product['TenSP']); ?></span>
                                <?php endif; ?>
                            </div>
                            <div class="product-info">
                                <h3><?php echo htmlspecialchars($product['TenSP']); ?></h3>
                                <div class="product-price"><?php echo formatCurrency($product['Gia']); ?></div>
                                <?php if(!empty($product['TrongLuong'])): ?>
                                    <div class="product-weight">Trọng lượng: <?php echo $product['TrongLuong']; ?></div>
                                <?php endif; ?>
                                <button class="add-to-cart" onclick="addToCart(<?php echo $product['MaSP']; ?>)">
                                    Thêm vào giỏ hàng
                                </button>
                            </div>
                        </div>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <div style="text-align: center; padding: 50px; background: white; border-radius: 10px; grid-column: 1 / -1;">
                            <h3>📦 Chưa có sản phẩm</h3>
                            <p>Hiện tại chưa có sản phẩm nào trong hệ thống.</p>
                        </div>
                    <?php endif; ?>
                </div>
                <div style="text-align: center;">
                    <a href="?page=products" class="btn btn-primary">Xem tất cả sản phẩm</a>
                </div>
            </div>
        </div>
    </div>

    <?php elseif ($page == 'products'): ?>
    <!-- TRANG SẢN PHẨM -->
    <div class="clearfix">
        <div class="sidebar">
            <h3>Danh mục sản phẩm</h3>
            <ul>
                <li><a href="?page=products" class="<?php echo !$category_filter && !$type_filter ? 'active' : ''; ?>">TẤT CẢ SẢN PHẨM</a></li>
                <?php if (is_array($categories)): ?>
                    <?php foreach($categories as $cat): ?>
                    <li><a href="?page=products&dm=<?php echo $cat['MaDM']; ?>" class="<?php echo $category_filter == $cat['MaDM'] ? 'active' : ''; ?>"><?php echo strtoupper($cat['TenDM']); ?></a></li>
                    <?php endforeach; ?>
                <?php endif; ?>
            </ul>
            
            <h3>Sản phẩm nổi bật</h3>
            <ul>
                <li><a href="?page=products&type=sua_tuoi" class="<?php echo $type_filter == 'sua_tuoi' ? 'active' : ''; ?>">SỮA TƯƠI</a></li>
                <li><a href="?page=products&type=sua_dac" class="<?php echo $type_filter == 'sua_dac' ? 'active' : ''; ?>">SỮA ĐẶC</a></li>
                <li><a href="?page=products&type=sua_chua" class="<?php echo $type_filter == 'sua_chua' ? 'active' : ''; ?>">SỮA CHUA</a></li>
            </ul>
        </div>

        <div class="main-content">
            <div class="student-form">
                <h2>DANH SÁCH SẢN PHẨM</h2>
                <div class="search-form">
                    <form method="GET">
                        <input type="hidden" name="page" value="products">
                        <input type="text" name="search" placeholder="Nhập tên sản phẩm cần tìm..." value="<?php echo htmlspecialchars($search); ?>">
                        <button type="submit">Tìm kiếm</button>
                    </form>
                </div>
            </div>

            <?php if(is_array($products) && count($products) > 0): ?>
            <div class="products-grid">
                <?php foreach($products as $product): ?>
                <div class="product-card">
                    <div class="product-image">
                        <?php if (!empty($product['Hinh']) && file_exists('images/products/' . $product['Hinh'])): ?>
                            <img src="images/products/<?php echo htmlspecialchars($product['Hinh']); ?>" 
                                 alt="<?php echo htmlspecialchars($product['TenSP']); ?>"
                                 onerror="this.parentElement.innerHTML='<span>📦 Hình ảnh sản phẩm</span>'; this.parentElement.classList.add('no-image');">
                        <?php else: ?>
                            <span>📦 Hình ảnh sản phẩm</span>
                        <?php endif; ?>
                    </div>
                    <div class="product-info">
                        <h3><?php echo htmlspecialchars($product['TenSP']); ?></h3>
                        <div class="product-price"><?php echo formatCurrency($product['Gia']); ?></div>
                        <?php if(!empty($product['TrongLuong'])): ?>
                            <div class="product-weight">📏 <?php echo $product['TrongLuong']; ?></div>
                        <?php endif; ?>
                        <button class="add-to-cart" onclick="addToCart(<?php echo $product['MaSP']; ?>)">
                            🛒 Thêm vào giỏ
                        </button>
                    </div>
                </div>
                <?php endforeach; ?>
            </div>
            <?php else: ?>
            <div style="text-align: center; padding: 50px; background: white; border-radius: 10px;">
                <h3>😔 Không tìm thấy sản phẩm</h3>
                <p>Hiện tại chúng tôi chưa có sản phẩm nào phù hợp với tìm kiếm của bạn.</p>
                <br>
                <a href="?page=products" class="btn btn-primary">Xem tất cả sản phẩm</a>
            </div>
            <?php endif; ?>
        </div>
    </div>

    <?php elseif ($page == 'cart'): ?>
    <!-- TRANG GIỎ HÀNG -->
    <div class="container">
        <h2 style="text-align: center; margin-bottom: 30px;">🛒 Giỏ hàng của bạn</h2>
        
        <?php if (isset($_SESSION['cart']) && !empty($_SESSION['cart'])): ?>
        <div style="background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
            <table class="table">
                <thead>
                    <tr>
                        <th>Sản phẩm</th>
                        <th>Giá</th>
                        <th>Số lượng</th>
                        <th>Thành tiền</th>
                    </tr>
                </thead>
                <tbody>
                    <?php 
                    $total = 0;
                    foreach($_SESSION['cart'] as $item): 
                        $subtotal = $item['price'] * $item['quantity'];
                        $total += $subtotal;
                    ?>
                    <tr>
                        <td><?php echo htmlspecialchars($item['name']); ?></td>
                        <td><?php echo formatCurrency($item['price']); ?></td>
                        <td><?php echo $item['quantity']; ?></td>
                        <td><?php echo formatCurrency($subtotal); ?></td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
                <tfoot>
                    <tr style="font-weight: bold; background: #f8f9fa;">
                        <td colspan="3">Tổng cộng:</td>
                        <td><?php echo formatCurrency($total); ?></td>
                    </tr>
                </tfoot>
            </table>
            
            <div style="text-align: center; margin-top: 20px;">
                <a href="?page=products" class="btn" style="background: #6c757d;">Tiếp tục mua hàng</a>
                <button class="btn btn-success" onclick="alert('Chức năng thanh toán sẽ được phát triển!')">Thanh toán</button>
            </div>
        </div>
        <?php else: ?>
        <div style="text-align: center; padding: 50px; background: white; border-radius: 10px;">
            <h3>🛒 Giỏ hàng trống</h3>
            <p>Bạn chưa có sản phẩm nào trong giỏ hàng.</p>
            <br>
            <a href="?page=products" class="btn btn-primary">Mua sắm ngay</a>
        </div>
        <?php endif; ?>
    </div>

    <?php elseif ($page == 'admin'): ?>
    <!-- TRANG QUẢN TRỊ -->
    <?php if (!isset($_SESSION['admin']) || $_SESSION['admin'] !== true): ?>
    <!-- Admin Login -->
    <div style="min-height: 100vh; display: flex; align-items: center; justify-content: center; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);">
        <div style="background: white; padding: 40px; border-radius: 15px; box-shadow: 0 15px 35px rgba(0,0,0,0.1); max-width: 400px; width: 100%;">
            <h2 style="text-align: center; margin-bottom: 30px;">🔐 Đăng nhập quản trị</h2>
            
            <?php if (!empty($error)): ?>
                <div class="alert alert-danger"><?php echo $error; ?></div>
            <?php endif; ?>
            
            <form method="POST" action="?page=admin">
                <input type="hidden" name="action" value="admin_login">
                <div class="form-group">
                    <label>👤 Tên đăng nhập</label>
                    <input type="text" name="username" required>
                </div>
                
                <div class="form-group">
                    <label>🔒 Mật khẩu</label>
                    <input type="password" name="password" required>
                </div>
                
                <button type="submit" class="btn btn-primary" style="width: 100%;">Đăng nhập</button>
            </form>
            
            <div style="text-align: center; margin-top: 20px; color: #666; font-size: 12px;">
                <p>Demo: admin / admin123</p>
            </div>
        </div>
    </div>
    <?php else: ?>
    <!-- Admin Dashboard -->
    <div style="background: linear-gradient(135deg, #2c3e50, #3498db); color: white; padding: 20px 0;">
        <div style="max-width: 1200px; margin: 0 auto; display: flex; justify-content: space-between; align-items: center; padding: 0 20px;">
            <h1>🌻 Quản trị Cửa hàng Hướng dương</h1>
            <div style="display: flex; align-items: center; gap: 15px;">
                <span>Chào mừng, Admin</span>
                <a href="?action=logout" class="btn" style="background: #6c757d;">Đăng xuất</a>
            </div>
        </div>
    </div>

    <div class="container">
        <!-- Dashboard Stats -->
        <div class="dashboard-stats">
            <div class="stat-card">
                <h3>📦 Tổng sản phẩm</h3>
                <div class="number"><?php echo $total_products; ?></div>
            </div>
            <div class="stat-card">
                <h3>👥 Khách hàng</h3>
                <div class="number"><?php echo $total_customers; ?></div>
            </div>
            <div class="stat-card">
                <h3>🛒 Đơn hàng</h3>
                <div class="number"><?php echo $total_orders; ?></div>
            </div>
            <div class="stat-card">
                <h3>💰 Doanh thu</h3>
                <div class="number">0đ</div>
            </div>
        </div>

        <!-- Tabs -->
        <div class="tabs">
            <div class="tab active" onclick="showTab('products')">📦 Quản lý sản phẩm</div>
            <div class="tab" onclick="showTab('add-product')">➕ Thêm sản phẩm</div>
            <div class="tab" onclick="showTab('customers')">👥 Khách hàng</div>
        </div>

        <!-- Products Tab -->
        <div id="products" class="tab-content active">
            <h3>Danh sách sản phẩm</h3>
            <?php if (is_array($products) && count($products) > 0): ?>
            <table class="table">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Hình ảnh</th>
                        <th>Tên sản phẩm</th>
                        <th>Giá</th>
                        <th>Trọng lượng</th>
                        <th>Danh mục</th>
                        <th>Thao tác</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach($products as $product): ?>
                    <tr>
                        <td><?php echo $product['MaSP']; ?></td>
                        <td>
                            <?php if (!empty($product['Hinh']) && file_exists('images/products/' . $product['Hinh'])): ?>
                                <img src="images/products/<?php echo htmlspecialchars($product['Hinh']); ?>" 
                                     alt="<?php echo htmlspecialchars($product['TenSP']); ?>"
                                     style="width: 50px; height: 50px; object-fit: cover; border-radius: 5px;">
                            <?php else: ?>
                                <span style="color: #999; font-size: 12px;">No image</span>
                            <?php endif; ?>
                        </td>
                        <td><?php echo htmlspecialchars($product['TenSP']); ?></td>
                        <td><?php echo formatCurrency($product['Gia']); ?></td>
                        <td><?php echo isset($product['TrongLuong']) ? $product['TrongLuong'] : ''; ?></td>
                        <td><?php echo isset($product['TenDM']) ? $product['TenDM'] : ''; ?></td>
                        <td>
                            <form method="POST" style="display: inline;" onsubmit="return confirm('Bạn có chắc muốn xóa?')">
                                <input type="hidden" name="action" value="delete_product">
                                <input type="hidden" name="product_id" value="<?php echo $product['MaSP']; ?>">
                                <button type="submit" class="btn btn-danger">Xóa</button>
                            </form>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            <?php else: ?>
            <div style="text-align: center; padding: 50px;">
                <p>Chưa có sản phẩm nào.</p>
            </div>
            <?php endif; ?>
        </div>

        <!-- Add Product Tab -->
        <div id="add-product" class="tab-content">
            <h3>Thêm sản phẩm mới</h3>
            <form method="POST">
                <input type="hidden" name="action" value="add_product">
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                    <div class="form-group">
                        <label>Tên sản phẩm</label>
                        <input type="text" name="tensp" required>
                    </div>
                    <div class="form-group">
                        <label>Giá (VND)</label>
                        <input type="number" name="gia" required>
                    </div>
                </div>
                
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                    <div class="form-group">
                        <label>Trọng lượng</label>
                        <input type="text" name="trong_luong" placeholder="VD: 450 gram">
                    </div>
                    <div class="form-group">
                        <label>Danh mục</label>
                        <select name="madm" required>
                            <option value="">Chọn danh mục</option>
                            <?php if (is_array($categories)): ?>
                                <?php foreach($categories as $cat): ?>
                                <option value="<?php echo $cat['MaDM']; ?>"><?php echo $cat['TenDM']; ?></option>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </select>
                    </div>
                </div>
                
                <div class="form-group">
                    <label>Hình ảnh</label>
                    <input type="text" name="hinh" placeholder="VD: iphone.jpg (tên file trong thư mục images/products/)">
                    <small style="color: #666; font-size: 12px;">
                        Các file hình có sẵn: asus.jpg, bphone.jpg, dell.jpg, iphone.jpg, samsung.jpg, suachuabavi.jpg, suachuath.jpg, suachuavinamilk.jpg
                    </small>
                </div>
                
                <div class="form-group">
                    <label>Mô tả</label>
                    <textarea name="mota" placeholder="Mô tả chi tiết về sản phẩm..."></textarea>
                </div>
                
                <button type="submit" class="btn btn-success">➕ Thêm sản phẩm</button>
            </form>
        </div>

        <!-- Customers Tab -->
        <div id="customers" class="tab-content">
            <h3>Danh sách khách hàng</h3>
            <?php if (is_array($customers) && count($customers) > 0): ?>
            <table class="table">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Tên đăng nhập</th>
                        <th>Họ tên</th>
                        <th>Email</th>
                        <th>Số điện thoại</th>
                        <th>Ngày đăng ký</th>
                        <th>Trạng thái</th>
                        <th>Lần đăng nhập cuối</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach($customers as $customer): ?>
                    <tr>
                        <td><?php echo $customer['MaKH']; ?></td>
                        <td><?php echo htmlspecialchars($customer['TenDN']); ?></td>
                        <td><?php echo htmlspecialchars($customer['HoTen']); ?></td>
                        <td><?php echo htmlspecialchars($customer['Email']); ?></td>
                        <td><?php echo htmlspecialchars($customer['SoDT']); ?></td>
                        <td><?php echo date('d/m/Y', strtotime($customer['NgayDK'])); ?></td>
                        <td>
                            <span style="background: <?php echo $customer['TrangThai'] == 'active' ? '#28a745' : '#dc3545'; ?>; color: white; padding: 3px 8px; border-radius: 3px; font-size: 12px;">
                                <?php echo $customer['TrangThai']; ?>
                            </span>
                        </td>
                        <td><?php echo $customer['LastLogin'] ? date('d/m/Y H:i', strtotime($customer['LastLogin'])) : 'Chưa đăng nhập'; ?></td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            <?php else: ?>
            <div style="text-align: center; padding: 50px;">
                <p>Chưa có khách hàng nào.</p>
            </div>
            <?php endif; ?>
        </div>
    </div>
    <?php endif; ?>

    <?php else: ?>
    <!-- TRANG KHÁC -->
    <div class="container">
        <div style="text-align: center; padding: 100px; background: white; border-radius: 10px; margin-top: 50px;">
            <h2>🚧 Trang đang phát triển</h2>
            <p>Tính năng này sẽ được cập nhật trong phiên bản tiếp theo.</p>
            <br>
            <a href="?page=home" class="btn btn-primary">Về trang chủ</a>
        </div>
    </div>
    <?php endif; ?>

    <?php if ($page != 'admin' && $page != 'login' && $page != 'register'): ?>
    <!-- Footer Banner -->
    <div class="footer-banner">
        <h3>🌻 Bạn muốn trở thành đại lý phân phối?</h3>
        <p>Nếu bạn có năng khiếu kinh doanh, đã bán hàng và muốn phân phối sản phẩm của chúng tôi hãy liên hệ để nắm bắt và trao đổi các chính sách ưu đãi hấp dẫn mới nhất nhé!</p>
        
        <!-- Thêm phần liên hệ -->
        <div class="footer-contact">
            <div class="contact-info">
                <div class="contact-item">
                    <span class="contact-icon">📞</span>
                    <div class="contact-details">
                        <strong>Build By</strong>
                        <a href="Admin : Le Quang Phat" class="phone-number">Le Quang Phat</a>
                    </div>
                </div>
                
                <div class="contact-item">
                    <span class="contact-icon">💬</span>
                    <div class="contact-details">
                        <strong>CHAT TRỰC TIẾP</strong>
                        <a href="#" class="chat-link">Nhắn tin ngay</a>
                    </div>
                </div>
                
                <div class="contact-item">
                    <span class="contact-icon">✉️</span>
                    <div class="contact-details">
                        <strong>EMAIL</strong>
                        <a href="mailto:lequangphat2006@gmail.com" class="email-link">lequangphat2006@gmail.com</a>
                    </div>
                </div>
            </div>
            
            <!-- Nút hành động -->
            <div class="footer-buttons">
                <a href="tel:091.358.8865" class="footer-btn primary">📞 GỌI NGAY</a>
                <a href="#" class="footer-btn secondary">💬 CHAT NGAY</a>
            </div>
        </div>
    </div>
    <?php endif; ?>

    <script>
        // ===================== IMPROVED AUTH SCRIPTS =====================
        
        // Toggle password visibility
        function togglePassword(inputId) {
            const input = document.getElementById(inputId);
            const icon = input.nextElementSibling;
            
            if (input.type === 'password') {
                input.type = 'text';
                icon.textContent = '🙈';
            } else {
                input.type = 'password';
                icon.textContent = '👁️';
            }
        }

        // Password strength checker
        function checkPasswordStrength(password) {
            let score = 0;
            let feedback = '';
            
            if (password.length >= 8) score++;
            if (password.match(/[a-z]/)) score++;
            if (password.match(/[A-Z]/)) score++;
            if (password.match(/[0-9]/)) score++;
            if (password.match(/[^a-zA-Z0-9]/)) score++;
            
            switch (score) {
                case 0:
                case 1:
                case 2:
                    return { strength: 'weak', text: 'Mật khẩu yếu' };
                case 3:
                case 4:
                    return { strength: 'medium', text: 'Mật khẩu trung bình' };
                case 5:
                    return { strength: 'strong', text: 'Mật khẩu mạnh' };
                default:
                    return { strength: 'weak', text: 'Mật khẩu yếu' };
            }
        }

        // Real-time validation functions
        function validateUsername(username) {
            if (username.length < 3) {
                return { valid: false, message: 'Tên đăng nhập phải có ít nhất 3 ký tự' };
            }
            if (username.length > 50) {
                return { valid: false, message: 'Tên đăng nhập không được quá 50 ký tự' };
            }
            if (!/^[a-zA-Z0-9_]+$/.test(username)) {
                return { valid: false, message: 'Chỉ được chứa chữ cái, số và dấu gạch dưới' };
            }
            return { valid: true, message: 'Tên đăng nhập hợp lệ' };
        }

        function validateEmail(email) {
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) {
                return { valid: false, message: 'Email không hợp lệ' };
            }
            return { valid: true, message: 'Email hợp lệ' };
        }

        function validatePhone(phone) {
            if (!/^[0-9]{10,11}$/.test(phone)) {
                return { valid: false, message: 'Số điện thoại phải có 10-11 chữ số' };
            }
            return { valid: true, message: 'Số điện thoại hợp lệ' };
        }

        function validateFullname(name) {
            if (name.length < 2) {
                return { valid: false, message: 'Họ tên phải có ít nhất 2 ký tự' };
            }
            if (name.length > 100) {
                return { valid: false, message: 'Họ tên không được quá 100 ký tự' };
            }
            if (!/^[a-zA-ZÀ-ỹ\s]+$/.test(name)) {
                return { valid: false, message: 'Họ tên chỉ được chứa chữ cái và khoảng trắng' };
            }
            return { valid: true, message: 'Họ tên hợp lệ' };
        }

        function showFieldValidation(fieldId, validation) {
            const field = document.getElementById(fieldId);
            const errorElement = document.getElementById(fieldId + 'Error');
            const successElement = document.getElementById(fieldId + 'Success');
            
            if (!field || !errorElement) return;
            
            if (validation.valid) {
                field.classList.remove('error');
                field.classList.add('success');
                errorElement.textContent = '';
                if (successElement) {
                    successElement.textContent = validation.message;
                }
            } else {
                field.classList.remove('success');
                field.classList.add('error');
                errorElement.textContent = validation.message;
                if (successElement) {
                    successElement.textContent = '';
                }
            }
        }

        function showLoading(show) {
            const overlay = document.getElementById('loadingOverlay');
            if (overlay) {
                if (show) {
                    overlay.classList.add('show');
                } else {
                    overlay.classList.remove('show');
                }
            }
        }

        // Document ready
        document.addEventListener('DOMContentLoaded', function() {
            // Register form validation
            const registerForm = document.getElementById('registerForm');
            if (registerForm) {
                // Username validation
                const usernameField = document.getElementById('reg_username');
                if (usernameField) {
                    usernameField.addEventListener('input', function() {
                        const validation = validateUsername(this.value);
                        showFieldValidation('reg_username', validation);
                    });
                }

                // Email validation
                const emailField = document.getElementById('reg_email');
                if (emailField) {
                    emailField.addEventListener('input', function() {
                        const validation = validateEmail(this.value);
                        showFieldValidation('reg_email', validation);
                    });
                }

                // Phone validation
                const phoneField = document.getElementById('reg_phone');
                if (phoneField) {
                    phoneField.addEventListener('input', function() {
                        const validation = validatePhone(this.value);
                        showFieldValidation('reg_phone', validation);
                    });
                }

                // Fullname validation
                const fullnameField = document.getElementById('reg_fullname');
                if (fullnameField) {
                    fullnameField.addEventListener('input', function() {
                        const validation = validateFullname(this.value);
                        showFieldValidation('reg_fullname', validation);
                    });
                }

                // Password strength
                const passwordField = document.getElementById('reg_password');
                if (passwordField) {
                    passwordField.addEventListener('input', function() {
                        const strength = checkPasswordStrength(this.value);
                        const strengthFill = document.getElementById('passwordStrengthFill');
                        const strengthText = document.getElementById('passwordStrengthText');
                        
                        if (strengthFill && strengthText) {
                            strengthFill.className = 'password-strength-fill ' + strength.strength;
                            strengthText.textContent = strength.text;
                        }
                    });
                }

                // Confirm password validation
                const confirmPasswordField = document.getElementById('reg_confirm_password');
                if (confirmPasswordField && passwordField) {
                    confirmPasswordField.addEventListener('input', function() {
                        const password = passwordField.value;
                        const confirmPassword = this.value;
                        
                        if (password !== confirmPassword) {
                            showFieldValidation('reg_confirm_password', {
                                valid: false,
                                message: 'Mật khẩu xác nhận không khớp'
                            });
                        } else if (confirmPassword.length > 0) {
                            showFieldValidation('reg_confirm_password', {
                                valid: true,
                                message: 'Mật khẩu xác nhận khớp'
                            });
                        }
                    });
                }

                // Form submission
                registerForm.addEventListener('submit', function(e) {
                    const submitBtn = document.getElementById('registerBtn');
                    if (submitBtn) {
                        submitBtn.classList.add('loading');
                        submitBtn.textContent = 'Đang xử lý...';
                    }
                    showLoading(true);
                });
            }

            // Login form
            const loginForm = document.getElementById('loginForm');
            if (loginForm) {
                loginForm.addEventListener('submit', function(e) {
                    const submitBtn = document.getElementById('loginBtn');
                    if (submitBtn) {
                        submitBtn.classList.add('loading');
                        submitBtn.textContent = 'Đang đăng nhập...';
                    }
                    showLoading(true);
                });
            }
        });

        // Cart functionality
        function addToCart(productId) {
            <?php if(!checkLogin()): ?>
                alert('Vui lòng đăng nhập để thêm sản phẩm vào giỏ hàng!');
                window.location.href = '?page=login';
                return;
            <?php endif; ?>
            
            showLoading(true);
            
            fetch('', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'action=add_to_cart&product_id=' + productId + '&quantity=1'
            })
            .then(response => response.json())
            .then(data => {
                showLoading(false);
                if(data.success) {
                    // Show success notification
                    showNotification('✅ ' + data.message, 'success');
                    // Reload page to update cart count
                    setTimeout(() => {
                        location.reload();
                    }, 1000);
                } else {
                    showNotification('❌ ' + data.message, 'error');
                }
            })
            .catch(error => {
                showLoading(false);
                console.error('Error:', error);
                showNotification('❌ Có lỗi xảy ra khi thêm sản phẩm vào giỏ hàng!', 'error');
            });
        }

        // Show notification
        function showNotification(message, type) {
            // Create notification element
            const notification = document.createElement('div');
            notification.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                background: ${type === 'success' ? '#28a745' : '#dc3545'};
                color: white;
                padding: 15px 20px;
                border-radius: 10px;
                z-index: 10000;
                animation: slideInRight 0.5s ease-out;
                box-shadow: 0 5px 15px rgba(0,0,0,0.3);
            `;
            notification.textContent = message;
            
            // Add animation styles
            const style = document.createElement('style');
            style.textContent = `
                @keyframes slideInRight {
                    from { transform: translateX(100%); opacity: 0; }
                    to { transform: translateX(0); opacity: 1; }
                }
                @keyframes slideOutRight {
                    from { transform: translateX(0); opacity: 1; }
                    to { transform: translateX(100%); opacity: 0; }
                }
            `;
            document.head.appendChild(style);
            
            document.body.appendChild(notification);
            
            // Remove after 3 seconds
            setTimeout(() => {
                notification.style.animation = 'slideOutRight 0.5s ease-in';
                setTimeout(() => {
                    document.body.removeChild(notification);
                }, 500);
            }, 3000);
        }

        // Admin tab functionality
        function showTab(tabName) {
            // Hide all tab contents
            const tabContents = document.querySelectorAll('.tab-content');
            tabContents.forEach(content => {
                content.classList.remove('active');
            });
            
            // Remove active class from all tabs
            const tabs = document.querySelectorAll('.tab');
            tabs.forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Show selected tab content
            const selectedTab = document.getElementById(tabName);
            if (selectedTab) {
                selectedTab.classList.add('active');
            }
            
            // Add active class to clicked tab
            event.target.classList.add('active');
        }

        // Auto-create database if not exists
        <?php
        // Kiểm tra và tạo database tự động nếu cần
        if (!$pdo) {
            echo "
            fetch('', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'action=create_database'
            }).then(() => location.reload());
            ";
        }
        ?>
    </script>
</body>
</html>

<?php
// ===================== SQL TẠO DATABASE (BACKUP) =====================
/*
-- Copy đoạn SQL này vào phpMyAdmin nếu muốn tạo database thủ công:

CREATE DATABASE IF NOT EXISTS sunflower_shop CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE sunflower_shop;

CREATE TABLE IF NOT EXISTS danhmuc (
    MaDM INT AUTO_INCREMENT PRIMARY KEY,
    TenDM VARCHAR(100) NOT NULL,
    MoTa TEXT
);

CREATE TABLE IF NOT EXISTS sanpham (
    MaSP INT AUTO_INCREMENT PRIMARY KEY,
    TenSP VARCHAR(200) NOT NULL,
    Gia DECIMAL(15,0) NOT NULL,
    TrongLuong VARCHAR(50),
    MoTa TEXT,
    Hinh VARCHAR(255),
    MaDM INT,
    SoLuong INT DEFAULT 0,
    NgayTao TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (MaDM) REFERENCES danhmuc(MaDM)
);

CREATE TABLE IF NOT EXISTS khachhang (
    MaKH INT AUTO_INCREMENT PRIMARY KEY,
    TenDN VARCHAR(50) UNIQUE NOT NULL,
    MatKhau VARCHAR(255) NOT NULL,
    HoTen VARCHAR(100) NOT NULL,
    SoDT VARCHAR(15) NOT NULL,
    Email VARCHAR(100) NOT NULL,
    DiaChi TEXT,
    NgayDK TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    TrangThai ENUM('active', 'inactive', 'banned') DEFAULT 'active',
    EmailVerified BOOLEAN DEFAULT FALSE,
    LastLogin TIMESTAMP NULL,
    LoginAttempts INT DEFAULT 0,
    LockedUntil TIMESTAMP NULL
);

CREATE TABLE IF NOT EXISTS nhasanxuat (
    MaNSX INT AUTO_INCREMENT PRIMARY KEY,
    TenNSX VARCHAR(100) NOT NULL,
    DiaChi TEXT,
    SoDT VARCHAR(15),
    Email VARCHAR(100)
);

CREATE TABLE IF NOT EXISTS donhang (
    MaDH INT AUTO_INCREMENT PRIMARY KEY,
    MaKH INT,
    NgayDat TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    TongTien DECIMAL(15,0) NOT NULL,
    TrangThai ENUM('Cho xu ly', 'Dang giao', 'Da giao', 'Da huy') DEFAULT 'Cho xu ly',
    FOREIGN KEY (MaKH) REFERENCES khachhang(MaKH)
);

CREATE TABLE IF NOT EXISTS chitietdonhang (
    MaDH INT,
    MaSP INT,
    SoLuong INT NOT NULL,
    DonGia DECIMAL(15,0) NOT NULL,
    PRIMARY KEY (MaDH, MaSP),
    FOREIGN KEY (MaDH) REFERENCES donhang(MaDH),
    FOREIGN KEY (MaSP) REFERENCES sanpham(MaSP)
);

-- Dữ liệu mẫu
INSERT INTO danhmuc (TenDM, MoTa) VALUES 
('Sua chua', 'Cac loai sua chua tuoi ngon'),
('Dien thoai', 'Cac loai smartphone cao cap'),
('Laptop', 'May tinh xach tay cac hang');

INSERT INTO nhasanxuat (TenNSX, DiaChi, SoDT, Email) VALUES 
('Ba Vi', 'Ha Noi', '0123456789', 'bavi@example.com'),
('Vinamilk', 'TP.HCM', '0987654321', 'vinamilk@example.com'),
('TH True Milk', 'Nghe An', '0369852147', 'thmilk@example.com');

INSERT INTO sanpham (TenSP, Gia, TrongLuong, MoTa, MaDM, Hinh) VALUES 
('Sua chua Ba Vi', 9000, '450 gram', 'Sua chua tuoi ngon tu Ba Vi', 1, 'suachuabavi.jpg'),
('Sua chua Vinamilk', 10000, '490 gram', 'Sua chua Vinamilk chat luong cao', 1, 'suachuavinamilk.jpg'),
('Sua chua TH', 11000, '480 gram', 'Sua chua TH organic', 1, 'suachuath.jpg'),
('iPhone', 32000000, '550g', 'iPhone cao cap', 2, 'iphone.jpg'),
('Samsung', 28000000, '600g', 'Samsung Galaxy series', 2, 'samsung.jpg'),
('Bphone', 6000000, '480g', 'Dien thoai Bphone Viet Nam', 2, 'bphone.jpg'),
('Laptop Asus VivoBook X507MA N4000', 12000000, '2.1kg', 'CPU: Intel Celeron, N4000, 1.10 GHz Card man hinh: Card do hoa tich hop, Intel UHD Graphics 600', 3, 'asus.jpg'),
('Laptop Dell Inspiron 5593 i5 1035G1', 17500000, '2.3kg', 'CPU: Intel Core i5 Ice Lake, 1035G1, 1.00 GHz', 3, 'dell.jpg');
*/
?>