# 💕 Love4Free

> **Free Dating Platform** - Open-source PHP-based dating website with profile creation, matching, and messaging.

---

## 📋 Overview

Love4Free is a lightweight, free dating platform built with PHP and MySQL. It provides essential dating site functionality including user registration, profile creation, photo uploads, matching, and messaging - all without subscription fees.

---

## 🎯 Features

- 👤 **User Registration** - Create accounts with email verification
- 📸 **Profile Management** - Upload photos, write bios, set preferences
- 🔍 **Search & Matching** - Find users based on criteria
- 💬 **Messaging** - Real-time chat between matched users
- ❤️ **Likes/Matching** - Express interest and match with others
- 🔒 **Privacy Controls** - Control profile visibility
- 📱 **Responsive Design** - Works on mobile and desktop

---

## 📁 Project Structure

| File | Description |
|------|-------------|
| `index.php` | Main landing page and homepage (20.8 KB) |
| `create_profile.php` | User registration and profile creation (7.4 KB) |
| `profile.php` | User profile viewing and editing (19.6 KB) |
| `db.php` | Database connection and configuration (357 B) |
| `helpers.php` | Utility functions and helpers (5.0 KB) |
| `install.php` | Database installation script (5.6 KB) |

---

## 🚀 Installation

### Requirements
- PHP 7.4+ with PDO
- MySQL 5.7+ or MariaDB 10.3+
- Web server (Apache/Nginx)

### Quick Setup

1. **Clone/Download** files to web server
2. **Create Database**:
   ```sql
   CREATE DATABASE love4free;
   ```
3. **Run Installer**:
   ```
   http://yoursite.com/install.php
   ```
4. **Configure** `db.php` with your database credentials
5. **Access Site**:
   ```
   http://yoursite.com/
   ```

### Manual Database Setup

```sql
-- Run the SQL from install.php or use the web installer
-- Tables: users, profiles, messages, likes, photos
```

---

## ⚙️ Configuration

### Database (db.php)
```php
<?php
$host = 'localhost';
$dbname = 'love4free';
$username = 'your_username';
$password = 'your_password';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Connection failed: " . $e->getMessage());
}
?>
```

### Site Settings
Edit `helpers.php` for:
- Site name and branding
- Email configuration
- Upload limits
- Age restrictions
- Content filters

---

## 🔒 Security Considerations

### ⚠️ Required Hardening
- **HTTPS Only** - Enforce SSL/TLS in production
- **Input Validation** - All user inputs are sanitized
- **Password Hashing** - bcrypt for password storage
- **SQL Injection Protection** - PDO prepared statements
- **XSS Protection** - Output encoding implemented
- **CSRF Tokens** - Add to forms for production
- **Rate Limiting** - Implement for login/registration
- **File Upload Security** - Validate image types and sizes

### Recommended Additions
- reCAPTCHA for registration
- Email verification system
- Admin moderation panel
- Report/block functionality
- Privacy policy and ToS pages

---

## 📱 Usage

### For Users
1. **Browse** - View profiles on homepage
2. **Register** - Create account via create_profile.php
3. **Complete Profile** - Add photos and information
4. **Search** - Find matches based on preferences
5. **Connect** - Like profiles and send messages
6. **Manage** - Edit profile via profile.php

### For Administrators
1. Access database directly for user management
2. Run install.php for fresh installation
3. Monitor storage for uploaded photos
4. Review reported content

---

## 🎨 Customization

### Theming
- Modify inline styles in PHP files
- Add external CSS file
- Create template system

### Features to Add
- Advanced search filters
- Photo verification
- Video chat integration
- Mobile app API
- Payment integration (for premium features)
- Analytics dashboard

---

## 📝 Database Schema

### Tables
- **users** - Account credentials and authentication
- **profiles** - Extended user information and preferences
- **photos** - Uploaded image metadata and paths
- **messages** - Private messaging between users
- **likes** - User interest and matching data
- **blocks** - Blocked user relationships

---

## 🛠️ Development

### Local Development
```bash
# Using PHP built-in server
php -S localhost:8000

# Access site
http://localhost:8000
```

### Testing
- Test on multiple browsers
- Mobile responsive testing
- Security penetration testing
- Load testing for concurrent users

---

## 📜 License & Disclaimer
---

## Comprehensive legal disclaimer

This project is intended for authorized defensive, administrative, research, or educational use only.

- Use only on systems, networks, and environments where you have explicit permission.
- Misuse may violate law, contracts, policy, or acceptable-use terms.
- Running security, hardening, monitoring, or response tooling can impact stability and may disrupt legitimate software.
- Validate all changes in a test environment before production use.
- This project is provided "AS IS", without warranties of any kind, including merchantability, fitness for a particular purpose, and non-infringement.
- Authors and contributors are not liable for direct or indirect damages, data loss, downtime, business interruption, legal exposure, or compliance impact.
- You are solely responsible for lawful operation, configuration choices, and compliance obligations in your jurisdiction.

---

<p align="center">
  <sub>Built with care by <strong>Gorstak</strong></sub>
</p>