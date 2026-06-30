package com.kopi.gudang.controller;

import com.kopi.gudang.repository.UserRepository;
import java.security.MessageDigest;
import java.math.BigInteger;
import com.kopi.gudang.entity.User;
import com.kopi.gudang.service.UserService;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.Optional;
import java.util.Random;

@Controller
public class AuthController {

    @Autowired
    private UserService userService;

    // INJEKSI ALAT KIRIM EMAIL
    @Autowired
    private JavaMailSender mailSender;

    // ==========================================
    // 1. BAGIAN LOGIN & LOGOUT (KODE LAMA KAMU)
    // ==========================================

    @GetMapping("/login")
    public String showLoginForm(HttpSession session) {
        if (session.getAttribute("user") != null) {
            return "redirect:/";
        }
        return "login";
    }

    @PostMapping("/login")
    public String processLogin(
            @RequestParam("username") String username,
            @RequestParam("password") String password,
            HttpSession session,
            Model model) {

        if (userService.authenticate(username, password)) {
            Optional<User> userOpt = userService.findByUsername(username);
            if (userOpt.isPresent()) {
                session.setAttribute("user", userOpt.get());
                return "redirect:/";
            }
        }

        model.addAttribute("error", "Username atau password salah!");
        return "login";
    }

    @GetMapping("/logout")
    public String processLogout(HttpSession session) {
        session.invalidate();
        return "redirect:/login";
    }

    // ==========================================
    // 2. BAGIAN REGISTRASI & OTP (FITUR BARU)
    // ==========================================

    @GetMapping("/register")
    public String showRegister() {
        return "register";
    }

    @PostMapping("/register/process")
    public String processRegister(@RequestParam String fullName, @RequestParam String username,
            @RequestParam String password, @RequestParam String companyCode,
            HttpSession session, RedirectAttributes redirectAttrs) {

        // PENGAMANAN: Cek Kode Perusahaan (Hanya yang tahu kodenya yang bisa daftar)
        if (!"Arabicakopi-2026".equals(companyCode)) {
            redirectAttrs.addFlashAttribute("error", "Kode Perusahaan tidak valid! Anda bukan karyawan internal.");
            return "redirect:/register";
        }

        // Cek apakah email sudah terdaftar
        if (userService.findByUsername(username).isPresent()) {
            redirectAttrs.addFlashAttribute("error", "Email sudah terdaftar di sistem.");
            return "redirect:/register";
        }

        // Generate 6 digit OTP acak
        String otp = String.format("%06d", new Random().nextInt(999999));

        // Eksekusi Kirim Email OTP
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(username);
            message.setSubject("Kode OTP Aktivasi Akun - Arabica.co");
            message.setText("Halo " + fullName + ",\n\nBerikut adalah kode OTP untuk aktivasi akun Gudang Anda:\n\n"
                    + otp + "\n\nJangan berikan kode ini kepada siapa pun.");
            mailSender.send(message);
        } catch (Exception e) {
            // CETAK ERROR ASLI KE TERMINAL AGAR KITA TAHU PENYEBABNYA
            System.out.println("ERROR KIRIM EMAIL: " + e.getMessage());
            e.printStackTrace();

            // Kembalikan ke halaman register tanpa membuat aplikasi mati
            redirectAttrs.addFlashAttribute("error", "Gagal kirim OTP: Cek console untuk detail error.");
            return "redirect:/register";
        }
        // Simpan data pendaftaran ke Session (Ingatan Sementara)
        session.setAttribute("tempFullName", fullName);
        session.setAttribute("tempEmail", username);
        session.setAttribute("tempPassword", password);
        session.setAttribute("tempOTP", otp);

        return "redirect:/verify-otp";
    }

    @GetMapping("/verify-otp")
    public String showVerifyOtp(HttpSession session, Model model) {
        String email = (String) session.getAttribute("tempEmail");
        if (email == null)
            return "redirect:/register";

        model.addAttribute("email", email);
        return "verify-otp";
    }

    @PostMapping("/verify-otp/process")
    public String processVerifyOtp(@RequestParam String otpCode, HttpSession session,
            RedirectAttributes redirectAttrs) {
        String savedOTP = (String) session.getAttribute("tempOTP");

        if (savedOTP != null && savedOTP.equals(otpCode)) {

            // OTP Cocok! Buat akun secara permanen menggunakan UserService (Otomatis
            // ter-hash)
            // OTP Cocok! Buat akun secara permanen menggunakan UserService
            User newUser = new User();
            newUser.setFullName((String) session.getAttribute("tempFullName"));
            newUser.setUsername((String) session.getAttribute("tempEmail"));
            newUser.setPassword((String) session.getAttribute("tempPassword"));
            newUser.setRole("STAFF");

            userService.registerUser(newUser);

            // Bersihkan memori session
            session.removeAttribute("tempFullName");
            session.removeAttribute("tempEmail");
            session.removeAttribute("tempPassword");
            session.removeAttribute("tempOTP");

            redirectAttrs.addFlashAttribute("success", "Aktivasi berhasil! Silakan login.");
            return "redirect:/login";
        } else {
            redirectAttrs.addFlashAttribute("error", "Kode OTP salah atau tidak valid.");
            return "redirect:/verify-otp";
        }
    }

    @Autowired
    private UserRepository userRepository;

    // ==========================================
    // 3. BAGIAN LUPA PASSWORD (FITUR BARU)
    // ==========================================

    @GetMapping("/forgot-password")
    public String showForgotPassword() {
        return "forgot-password";
    }

    @PostMapping("/forgot-password/process")
    public String processForgotPassword(@RequestParam String email, HttpSession session,
            RedirectAttributes redirectAttrs) {
        Optional<User> userOpt = userRepository.findByUsername(email);

        // Cek apakah email ada di database
        if (userOpt.isEmpty()) {
            redirectAttrs.addFlashAttribute("error", "Email tidak ditemukan di sistem!");
            return "redirect:/forgot-password";
        }

        // Buat 6 digit OTP acak
        String otp = String.format("%06d", new Random().nextInt(999999));

        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(email);
            message.setSubject("Reset Password - Arabica.co");
            message.setText("Halo " + userOpt.get().getFullName()
                    + ",\n\nBerikut adalah kode OTP untuk mereset password Anda:\n\n"
                    + otp + "\n\nJika Anda tidak meminta reset password, abaikan email ini.");
            mailSender.send(message);
        } catch (Exception e) {
            redirectAttrs.addFlashAttribute("error", "Gagal mengirim email OTP. Coba lagi.");
            return "redirect:/forgot-password";
        }

        // Simpan ke session sementara
        session.setAttribute("resetEmail", email);
        session.setAttribute("resetOTP", otp);

        return "redirect:/reset-password";
    }

    @GetMapping("/reset-password")
    public String showResetPassword(HttpSession session, Model model) {
        String email = (String) session.getAttribute("resetEmail");
        if (email == null)
            return "redirect:/forgot-password";

        model.addAttribute("email", email);
        return "reset-password";
    }

    @PostMapping("/reset-password/process")
    public String processResetPassword(@RequestParam String otpCode, @RequestParam String newPassword,
            HttpSession session, RedirectAttributes redirectAttrs) {
        String savedOTP = (String) session.getAttribute("resetOTP");
        String email = (String) session.getAttribute("resetEmail");

        if (savedOTP != null && savedOTP.equals(otpCode) && email != null) {
            Optional<User> userOpt = userRepository.findByUsername(email);

            if (userOpt.isPresent()) {
                User user = userOpt.get();
                // Hash password baru sebelum disimpan
                user.setPassword(hashPasswordLocal(newPassword));
                userRepository.save(user);

                // Bersihkan session
                session.removeAttribute("resetEmail");
                session.removeAttribute("resetOTP");

                redirectAttrs.addFlashAttribute("success", "Password berhasil diubah! Silakan login.");
                return "redirect:/login";
            }
        }

        redirectAttrs.addFlashAttribute("error", "Kode OTP salah atau tidak valid.");
        return "redirect:/reset-password";
    }

    // Fungsi hash khusus untuk class ini
    private String hashPasswordLocal(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] messageDigest = md.digest(password.getBytes());
            BigInteger no = new BigInteger(1, messageDigest);
            String hashtext = no.toString(16);
            while (hashtext.length() < 32) {
                hashtext = "0" + hashtext;
            }
            return hashtext;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}