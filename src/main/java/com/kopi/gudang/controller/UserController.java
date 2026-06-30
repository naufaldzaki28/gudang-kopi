package com.kopi.gudang.controller;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.kopi.gudang.entity.User;
import com.kopi.gudang.repository.UserRepository;

import jakarta.servlet.http.HttpSession;

@Controller
public class UserController {

    @Autowired
    private UserRepository userRepository;

    // 1. Menampilkan Halaman Kelola Akun
    @GetMapping("/users")
    public String viewUsers(Model model, HttpSession session) {
        User currentUser = (User) session.getAttribute("user");

        // Proteksi: Hanya Admin yang boleh masuk
        if (currentUser == null || !"ADMIN".equalsIgnoreCase(currentUser.getRole())) {
            return "redirect:/";
        }

        // Ambil semua data pengguna dari database
        List<User> userList = userRepository.findAll();

        model.addAttribute("currentUser", currentUser);
        model.addAttribute("users", userList);
        return "users"; // Mengarah ke file users.html nanti
    }

    // 2. Menyimpan Akun Baru
    @PostMapping("/users/add")
    public String addUser(
            @RequestParam String fullName,
            @RequestParam String username,
            @RequestParam String password,
            @RequestParam String role,
            HttpSession session,
            RedirectAttributes redirectAttrs) {

        User currentUser = (User) session.getAttribute("user");
        if (currentUser == null || !"ADMIN".equalsIgnoreCase(currentUser.getRole())) {
            return "redirect:/";
        }

        // PERBAIKAN: Sesuaikan dengan Optional<User> dari UserRepository
        java.util.Optional<User> existingUser = userRepository.findByUsername(username);
        if (existingUser.isPresent()) {
            redirectAttrs.addFlashAttribute("error", "Gagal! Username '" + username + "' sudah terdaftar.");
            return "redirect:/users";
        }

        // Buat dan simpan akun baru
        User newUser = new User();
        newUser.setFullName(fullName);
        newUser.setUsername(username);
        // PERBAIKAN: Hash password sebelum disimpan ke database!
        newUser.setPassword(hashPassword(password.trim()));
        newUser.setRole(role.toUpperCase());

        userRepository.save(newUser);

        redirectAttrs.addFlashAttribute("success",
                "Akun " + role + " atas nama " + fullName + " berhasil didaftarkan!");
        return "redirect:/users";
    }

    // 3. Menghapus Akun
    @PostMapping("/users/delete/{id}")
    public String deleteUser(@PathVariable Long id, HttpSession session, RedirectAttributes redirectAttrs) {
        User currentUser = (User) session.getAttribute("user");
        if (currentUser == null || !"ADMIN".equalsIgnoreCase(currentUser.getRole())) {
            return "redirect:/";
        }

        // Proteksi: Admin tidak boleh menghapus akunnya sendiri yang sedang dipakai
        // login
        if (currentUser.getId().equals(id)) {
            redirectAttrs.addFlashAttribute("error", "Ditolak! Anda tidak dapat menghapus akun Anda sendiri.");
            return "redirect:/users";
        }

        userRepository.deleteById(id);
        redirectAttrs.addFlashAttribute("success", "Akun berhasil dihapus dari sistem.");
        return "redirect:/users";
    }

    // Fungsi untuk mengubah teks biasa menjadi kode Hash SHA-256
    private String hashPassword(String password) {
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

    // 4. Menampilkan Halaman Edit Hak Akses (Role)
    @GetMapping("/users/edit/{id}")
    public String showEditUserForm(@PathVariable Long id, Model model, HttpSession session,
            RedirectAttributes redirectAttrs) {
        User currentUser = (User) session.getAttribute("user");
        if (currentUser == null || !"ADMIN".equalsIgnoreCase(currentUser.getRole())) {
            return "redirect:/";
        }

        java.util.Optional<User> optUser = userRepository.findById(id);
        if (optUser.isEmpty()) {
            redirectAttrs.addFlashAttribute("error", "Data pegawai tidak ditemukan.");
            return "redirect:/users";
        }

        model.addAttribute("currentUser", currentUser);
        model.addAttribute("userToEdit", optUser.get());
        return "edit-user"; // Memanggil file edit-user.html
    }

    // 5. Menyimpan Perubahan Hak Akses
    @PostMapping("/users/edit/{id}")
    public String updateUserRole(@PathVariable Long id, @RequestParam String role, HttpSession session,
            RedirectAttributes redirectAttrs) {
        User currentUser = (User) session.getAttribute("user");
        if (currentUser == null || !"ADMIN".equalsIgnoreCase(currentUser.getRole())) {
            return "redirect:/";
        }

        // Proteksi: Admin tidak boleh mengubah role-nya sendiri dari halaman ini
        if (currentUser.getId().equals(id)) {
            redirectAttrs.addFlashAttribute("error", "Ditolak! Anda tidak dapat mengubah hak akses Anda sendiri.");
            return "redirect:/users";
        }

        java.util.Optional<User> optUser = userRepository.findById(id);
        if (optUser.isPresent()) {
            User existingUser = optUser.get();
            existingUser.setRole(role.toUpperCase());
            userRepository.save(existingUser); // Simpan perubahan ke database

            redirectAttrs.addFlashAttribute("success", "Hak akses atas nama " + existingUser.getFullName()
                    + " berhasil diubah menjadi " + role.toUpperCase());
        }

        return "redirect:/users";
    }
}
