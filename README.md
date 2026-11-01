# cmdwlt — Universal Command & Snippet Manager

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![PHP Version](https://img.shields.io/badge/php-%21%3D7.4--8.x-777bb4.svg)](https://www.php.net/)
[![SQLite](https://img.shields.io/badge/database-SQLite3-003b57.svg)](https://www.sqlite.org/)

**cmdwlt** is a fast, lightweight, single-file PHP application designed for managing shell commands, code snippets, payloads, and multi-step execution chains. Built with a terminal-inspired dark UI, it offers platform categorization, tagged organization, multi-step code handling, and security hardening out of the box.

---

## 🚀 Quick Description

> A self-hosted, single-file PHP & SQLite command vault to store, search, tag, and chain shell commands, code snippets, and security payloads across Linux, Windows, macOS, Android, and more.

---

## ✨ Features

- **Single-File Architecture:** Zero extra dependencies or complex directory setups. Runs directly on standard PHP environments with SQLite PDO enabled.
- **Cross-Platform Categorization:** Organize entries by platform (**Linux**, **Windows**, **macOS**, **Android/ADB**, **Payloads**, **Code Snippets**) and type (**Command**, **Chain**, **Payload**, **Snippet**, **One-Liner**).
- **Multi-Step Execution Chains:** Save complex multi-step execution workflows with notes per step. Join and copy full command chains instantly using `&&`, `;`, or newline separators.
- **Tagging & Instant Search:** Fast tag filtering and live client-side debounced search through titles and descriptions.
- **Security Hardened:**
  - Password hashing using `bcrypt` (cost factor 12).
  - Protection against CSRF, SQL Injection (PDO Prepared Statements), and XSS.
  - Rate limiting on authentication attempts with exponential lockout.
  - Math challenge verification for login defense.
  - Restrictive HTTP security headers (`Content-Security-Policy`, `X-Frame-Options`, `X-Robots-Tag: noindex, nofollow`, etc.).
- **Import & Export:** Full JSON export and import capabilities for seamless database backup and migration.
- **Mobile Responsive & Hotkeys:** Includes keyboard shortcuts (`N` for new, `E` for edit, `/` to search, `C` to copy chain, `P` to pin) and responsive layout adjustments for mobile browsers.

---

## 🛠️ Tech Stack

- **Backend:** PHP 7.4+ / PHP 8.x
- **Database:** SQLite 3 (via PDO in `WAL` mode)
- **Frontend:** Vanilla JS, CSS3, Inter & Monospace Typography

---

## 💻 Installation & Setup

### Prerequisites
- PHP 7.4 or higher
- `pdo_sqlite` PHP extension enabled
- Web server (Apache, Nginx, or PHP built-in CLI server)

### Quick Start

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/psvineet/cmdwlt.git
   cd cmdwlt
   ```

2. **Run the Application:**
   *Using PHP's built-in server:*
   ```bash
   php -S 0.0.0.0:8000 cmdwlt.php
   ```

   *Using Apache / Nginx:*
   Place `cmdwlt.php` in your web directory (or rename it to `index.php`). Ensure write permissions are available on the folder so SQLite can automatically create `vault.db` upon initial execution.

3. **Initialize the Vault:**
   - Open `http://localhost:8000` in your browser.
   - Complete the first-run initialization screen to set up your username and master password.

---

## ⌨️ Keyboard Shortcuts

| Key | Action |
| :--- | :--- |
| `N` | Open **New Entry** modal |
| `E` | Edit currently selected item |
| `D` | Delete currently selected item |
| `C` | Copy full multi-step command chain |
| `P` | Pin / unpin selected item to top |
| `U` | Duplicate selected item |
| `/` | Focus search bar |
| `Q` | Logout |
| `ESC` | Close active modal or sidebar |

---

## 👤 Author

**Vineet Pratap Singh**  
Website: [psvineet.me](https://psvineet.me)  
GitHub: [@psvineet](https://github.com/psvineet)

---

## 📄 License

This project is open-source and available under the [MIT License](LICENSE).
