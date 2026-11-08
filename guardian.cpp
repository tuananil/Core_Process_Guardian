#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include "guardian_core.hpp"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <io.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace {

bool stdout_terminal_mi() {
#ifdef _WIN32
    return _isatty(_fileno(stdout)) != 0;
#else
    return isatty(STDOUT_FILENO) != 0;
#endif
}

// Windows konsolunda UTF-8 çıktıyı ve ANSI renk dizilerini etkinleştirir.
// Başarısız olursa renkler kapatılır (ham kaçış dizileri ekrana basılmasın diye).
bool konsolu_hazirla() {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mod = 0;
    if (h == INVALID_HANDLE_VALUE || !GetConsoleMode(h, &mod)) return false;
    return SetConsoleMode(h, mod | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0;
#else
    return true;
#endif
}

unsigned long mevcut_pid() {
#ifdef _WIN32
    return static_cast<unsigned long>(GetCurrentProcessId());
#else
    return static_cast<unsigned long>(getpid());
#endif
}

}  // namespace

int main() {
    using namespace guardian;

    // Renkler yalnızca gerçek bir terminale yazılıyorsa kullanılır; dosyaya/pipe'a
    // yönlendirilen çıktıya ANSI kaçış dizisi karışmaz.
    const bool renk_destekli = stdout_terminal_mi() && konsolu_hazirla();
    const Renkler r = renk_destekli ? ansi_renkler() : Renkler{};

    std::cout << r.cyan << "==================================================" << r.reset << '\n';
    std::cout << r.yesil << "🛡️  C++ PROCESS MEMORY GUARDIAN & INJECTION DETECTOR" << r.reset << '\n';
    std::cout << r.cyan << "==================================================" << r.reset << '\n';
    std::cout << "[+] Guardian Modülü Aktif. Mevcut Sistem PID: " << mevcut_pid() << '\n';
    std::cout << r.sari << "[!] SİMÜLASYON: Aşağıdaki bellek haritası gerçek bir süreçten okunmaz, örnek veridir."
              << r.reset << '\n';
    std::cout << r.cyan << "\n[*] Bellek Haritası Çözümleniyor..." << r.reset << '\n';
    std::cout << r.sari << "[*] Güvenlik Analizi: 'rwx' (Yazılabilir ve Çalıştırılabilir) alanlar denetleniyor...\n"
              << r.reset << '\n';

    const std::vector<HafizaSayfasi> sanal_ram = {
        {0x00400000, "r-xp", "SYS_INIT: Kernel space loaded successfully."},
        {0x00651000, "r--p", "USER_DATA: Session active for user_demo"},
        {0x7FFF0020, "rw-p", "CACHE: Normal temporary variables stored here."},
        {0x7FFF5FBC, "rwxp", "ALERT! DANGEROUS CODE DETECTED: EVIL_SHELLCODE_EXEC"}  // Sızma noktası!
    };

    rapor_yaz(std::cout, analiz_et(sanal_ram), r);
    return 0;
}
