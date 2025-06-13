<?php
// simple_auth.php - Phiên bản đơn giản hóa
session_start();
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Cấu hình database
$db_host = 'localhost';
$db_user = 'root';
$db_pass = '';
$db_name = 'sunflower_shop';

$pdo = null;
$message = '';
$error = '';

// Kết nối database
try {
    $pdo = new PDO("mysql:host=$db_host;dbname=$db_name;charset=utf8mb4", $db_user, $db_pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch(PDOException $e) {
    $error = "Lỗi kết nối database: " . $e->getMessage();
}

// Tạo bảng nếu chưa có
if($pdo) {
    try {
        $pdo->exec("CREATE TABLE IF NOT EXISTS khachhang (
            MaKH INT AUTO_INCREMENT PRIMARY KEY,
            TenDN VARCHAR(50) UNIQUE NOT NULL,
            MatKhau VARCHAR(255) NOT NULL,
            HoTen VARCHAR(100) NOT NULL,
            SoDT VARCHAR(15) NOT NULL,
            Email VARCHAR(100) NOT NULL,
            NgayDK TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )");
    } catch(PDOException $e) {
        $error = "Lỗi tạo bảng: " . $e->getMessage();
    }
}

$action = $_GET['action'] ?? '';

// Xử lý đăng ký
if($action == 'register' && $_POST) {
    $tendn = trim($_POST['tendn'] ?? '');
    $matkhau = $_POST['matkhau'] ?? '';
    $hoten = trim($_POST['hoten'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $sodt = trim($_POST['sodt'] ?? '');
    
    // Validation đơn giản
    if(empty($tendn) || empty($matkhau) || empty($hoten) || empty($email) || empty($sodt)) {
        $error = 'Vui lòng điền đầy đủ thông tin!';
    } elseif(strlen($matkhau) < 6) {
        $error = 'Mật khẩu phải có ít nhất 6 ký tự!';
    } else {
        try {
            // Kiểm tra tên đăng nhập đã tồn tại
            $stmt = $pdo->prepare("SELECT MaKH FROM khachhang WHERE TenDN = ?");
            $stmt->execute([$tendn]);
            if($stmt->fetch()) {
                $error = 'Tên đăng nhập đã được sử dụng!';
            } else {
                // Thêm tài khoản mới
                $hashed_password = password_hash($matkhau, PASSWORD_DEFAULT);
                $stmt = $pdo->prepare("INSERT INTO khachhang (TenDN, MatKhau, HoTen, SoDT, Email) VALUES (?, ?, ?, ?, ?)");
                if($stmt->execute([$tendn, $hashed_password, $hoten, $sodt, $email])) {
                    $message = 'Đăng ký thành công! Bạn có thể đăng nhập ngay.';
                } else {
                    $error = 'Có lỗi xảy ra khi đăng ký!';
                }
            }
        } catch(PDOException $e) {
            $error = 'Lỗi database: ' . $e->getMessage();
        }
    }
}

// Xử lý đăng nhập
if($action == 'login' && $_POST) {
    $tendn = trim($_POST['tendn'] ?? '');
    $matkhau = $_POST['matkhau'] ?? '';
    
    if(empty($tendn) || empty($matkhau)) {
        $error = 'Vui lòng nhập đầy đủ thông tin!';
    } else {
        try {
            $stmt = $pdo->prepare("SELECT MaKH, TenDN, MatKhau, HoTen FROM khachhang WHERE TenDN = ?");
            $stmt->execute([$tendn]);
            $user = $stmt->fetch();
            
            if(!$user) {
                $error = 'Tên đăng nhập không tồn tại!';
            } elseif(!password_verify($matkhau, $user['MatKhau'])) {
                $error = 'Mật khẩu không đúng!';
            } else {
                // Đăng nhập thành công
                $_SESSION['user_id'] = $user['MaKH'];
                $_SESSION['username'] = $user['TenDN'];
                $_SESSION['fullname'] = $user['HoTen'];
                $message = 'Đăng nhập thành công! Chào mừng ' . $user['HoTen'];
            }
        } catch(PDOException $e) {
            $error = 'Lỗi database: ' . $e->getMessage();
        }
    }
}

// Đăng xuất
if($action == 'logout') {
    session_destroy();
    header('Location: simple_auth.php');
    exit;
}
?>

<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Đăng Nhập/Đăng Ký - Cửa hàng Hướng dương</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        
        .container {
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            padding: 40px;
            width: 100%;
            max-width: 500px;
            position: relative;
        }
        
        .header {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .logo {
            font-size: 60px;
            margin-bottom: 15px;
            animation: bounce 2s infinite;
        }
        
        @keyframes bounce {
            0%, 20%, 50%, 80%, 100% {
                transform: translateY(0);
            }
            40% {
                transform: translateY(-10px);
            }
            60% {
                transform: translateY(-5px);
            }
        }
        
        h1 {
            color: #2c3e50;
            font-size: 28px;
            margin-bottom: 10px;
        }
        
        .subtitle {
            color: #7f8c8d;
            font-size: 16px;
        }
        
        .tabs {
            display: flex;
            margin-bottom: 30px;
            background: #f8f9fa;
            border-radius: 10px;
            padding: 5px;
        }
        
        .tab {
            flex: 1;
            padding: 12px;
            text-align: center;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s ease;
            font-weight: 600;
        }
        
        .tab.active {
            background: #007bff;
            color: white;
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,123,255,0.3);
        }
        
        .tab:hover:not(.active) {
            background: #e9ecef;
        }
        
        .form-section {
            display: none;
        }
        
        .form-section.active {
            display: block;
            animation: fadeIn 0.5s ease-in;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            margin-bottom: 8px;
            color: #2c3e50;
            font-weight: 600;
            font-size: 14px;
        }
        
        input {
            width: 100%;
            padding: 15px;
            border: 2px solid #e9ecef;
            border-radius: 10px;
            font-size: 16px;
            transition: all 0.3s ease;
            background: #f8f9fa;
        }
        
        input:focus {
            outline: none;
            border-color: #007bff;
            background: white;
            box-shadow: 0 0 0 3px rgba(0,123,255,0.1);
        }
        
        .btn {
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
        }
        
        .btn:hover {
            background: linear-gradient(135deg, #0056b3, #004085);
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(0,123,255,0.3);
        }
        
        .alert {
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 20px;
            font-weight: 500;
            animation: slideDown 0.5s ease-out;
        }
        
        @keyframes slideDown {
            from { opacity: 0; transform: translateY(-20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .alert-success {
            background: linear-gradient(135deg, #d4edda, #c3e6cb);
            color: #155724;
            border: 2px solid #c3e6cb;
        }
        
        .alert-danger {
            background: linear-gradient(135deg, #f8d7da, #f5c6cb);
            color: #721c24;
            border: 2px solid #f5c6cb;
        }
        
        .user-info {
            text-align: center;
            padding: 30px;
        }
        
        .user-info h2 {
            color: #28a745;
            margin-bottom: 15px;
        }
        
        .user-actions {
            display: flex;
            gap: 15px;
            margin-top: 20px;
        }
        
        .btn-secondary {
            background: linear-gradient(135deg, #6c757d, #5a6268);
        }
        
        .btn-secondary:hover {
            background: linear-gradient(135deg, #5a6268, #495057);
        }
        
        .btn-danger {
            background: linear-gradient(135deg, #dc3545, #c82333);
        }
        
        .btn-danger:hover {
            background: linear-gradient(135deg, #c82333, #a71e2a);
        }
        
        .users-list {
            margin-top: 30px;
            max-height: 300px;
            overflow-y: auto;
        }
        
        .users-list table {
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        
        .users-list th,
        .users-list td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e9ecef;
        }
        
        .users-list th {
            background: #f8f9fa;
            font-weight: 600;
            color: #495057;
        }
        
        .users-list tr:hover {
            background: #f8f9fa;
        }
        
        .status-indicator {
            display: inline-block;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: #28a745;
            margin-right: 8px;
        }
        
        @media (max-width: 768px) {
            .container {
                margin: 10px;
                padding: 30px 20px;
            }
            
            .user-actions {
                flex-direction: column;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <?php if(isset($_SESSION['user_id'])): ?>
            <!-- Người dùng đã đăng nhập -->
            <div class="user-info">
                <div class="logo">🌻</div>
                <h2>Chào mừng, <?php echo htmlspecialchars($_SESSION['fullname'] ?? $_SESSION['username']); ?>!</h2>
                <p>Bạn đã đăng nhập thành công vào hệ thống.</p>
                
                <div class="user-actions">
                    <a href="website.php" class="btn btn-secondary">🏠 Về trang chủ</a>
                    <a href="?action=logout" class="btn btn-danger">🚪 Đăng xuất</a>
                </div>
            </div>
            
            <!-- Hiển thị danh sách users (chỉ để test) -->
            <?php if($pdo): ?>
            <div class="users-list">
                <h3 style="margin-bottom: 15px; color: #495057;">👥 Danh sách tài khoản:</h3>
                <?php
                try {
                    $stmt = $pdo->query("SELECT MaKH, TenDN, HoTen, Email, NgayDK FROM khachhang ORDER BY NgayDK DESC LIMIT 10");
                    $users = $stmt->fetchAll();
                    
                    if($users): ?>
                        <table>
                            <thead>
                                <tr>
                                    <th>Tên đăng nhập</th>
                                    <th>Họ tên</th>
                                    <th>Email</th>
                                    <th>Ngày đăng ký</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach($users as $user): ?>
                                <tr>
                                    <td>
                                        <?php if($user['MaKH'] == $_SESSION['user_id']): ?>
                                            <span class="status-indicator"></span>
                                        <?php endif; ?>
                                        <?php echo htmlspecialchars($user['TenDN']); ?>
                                    </td>
                                    <td><?php echo htmlspecialchars($user['HoTen']); ?></td>
                                    <td><?php echo htmlspecialchars($user['Email']); ?></td>
                                    <td><?php echo date('d/m/Y', strtotime($user['NgayDK'])); ?></td>
                                </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    <?php else: ?>
                        <p>Chưa có tài khoản nào.</p>
                    <?php endif;
                } catch(PDOException $e) {
                    echo "<p>Lỗi truy vấn: " . htmlspecialchars($e->getMessage()) . "</p>";
                }
                ?>
            </div>
            <?php endif; ?>
            
        <?php else: ?>
            <!-- Form đăng nhập/đăng ký -->
            <div class="header">
                <div class="logo">🌻</div>
                <h1>Cửa hàng Hướng dương</h1>
                <p class="subtitle">Chào mừng bạn đến với hệ thống</p>
            </div>
            
            <?php if($message): ?>
                <div class="alert alert-success">✅ <?php echo htmlspecialchars($message); ?></div>
            <?php endif; ?>
            
            <?php if($error): ?>
                <div class="alert alert-danger">❌ <?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>
            
            <!-- Tabs -->
            <div class="tabs">
                <div class="tab active" onclick="showTab('login')">🔑 Đăng nhập</div>
                <div class="tab" onclick="showTab('register')">📝 Đăng ký</div>
            </div>
            
            <!-- Form Đăng nhập -->
            <div id="login" class="form-section active">
                <form method="POST" action="?action=login">
                    <div class="form-group">
                        <label>👤 Tên đăng nhập:</label>
                        <input type="text" name="tendn" required placeholder="Nhập tên đăng nhập...">
                    </div>
                    
                    <div class="form-group">
                        <label>🔒 Mật khẩu:</label>
                        <input type="password" name="matkhau" required placeholder="Nhập mật khẩu...">
                    </div>
                    
                    <button type="submit" class="btn">🚀 Đăng nhập</button>
                </form>
            </div>
            
            <!-- Form Đăng ký -->
            <div id="register" class="form-section">
                <form method="POST" action="?action=register">
                    <div class="form-group">
                        <label>👤 Tên đăng nhập:</label>
                        <input type="text" name="tendn" required placeholder="Nhập tên đăng nhập...">
                    </div>
                    
                    <div class="form-group">
                        <label>🔒 Mật khẩu:</label>
                        <input type="password" name="matkhau" required placeholder="Nhập mật khẩu (ít nhất 6 ký tự)...">
                    </div>
                    
                    <div class="form-group">
                        <label>👨‍👩‍👧‍👦 Họ và tên:</label>
                        <input type="text" name="hoten" required placeholder="Nhập họ tên đầy đủ...">
                    </div>
                    
                    <div class="form-group">
                        <label>📧 Email:</label>
                        <input type="email" name="email" required placeholder="Nhập địa chỉ email...">
                    </div>
                    
                    <div class="form-group">
                        <label>📱 Số điện thoại:</label>
                        <input type="tel" name="sodt" required placeholder="Nhập số điện thoại...">
                    </div>
                    
                    <button type="submit" class="btn">🎉 Đăng ký</button>
                </form>
            </div>
        <?php endif; ?>
    </div>
    
    <script>
        function showTab(tabName) {
            // Ẩn tất cả form sections
            document.querySelectorAll('.form-section').forEach(section => {
                section.classList.remove('active');
            });
            
            // Xóa active class từ tất cả tabs
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Hiển thị form section được chọn
            document.getElementById(tabName).classList.add('active');
            
            // Thêm active class cho tab được click
            event.target.classList.add('active');
            
            // Reset form khi chuyển tab
            document.getElementById(tabName).querySelector('form').reset();
        }
        
        // Tự động focus vào input đầu tiên
        document.addEventListener('DOMContentLoaded', function() {
            const firstInput = document.querySelector('.form-section.active input');
            if(firstInput) {
                firstInput.focus();
            }
        });
    </script>
</body>
</html>