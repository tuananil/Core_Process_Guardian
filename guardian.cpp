#include <iostream>
#include <vector>
#include <string>
#include <unistd.h>

#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define CYAN    "\033[36m"

const std::string ZARARLI_IMZA = "EVIL_SHELLCODE_EXEC";

struct HafizaSayfasi {
    uintptr_t baslangic_adresi;
    std::string izinler; 
    std::string ham_veri;
};

void bellek_bütünlük_analizi_yap(const std::vector<HafizaSayfasi>& ram_haritasi) {
    std::cout << CYAN << "\n[*] Canlı Süreç Bellek Haritası Çözümleniyor..." << RESET << std::endl;
    usleep(500000); 
    
    int tespit_sayisi = 0;

    std::cout << YELLOW << "[*] Güvenlik Analizi: 'rwx' (Yazılabilir ve Çalıştırılabilir) alanlar denetleniyor...\n" << RESET << std::endl;

    for (const auto& sayfa : ram_haritasi) {
        // Adli bilişim kuralı: Bir alan hem 'w' (yazılabilir) hem 'x' (çalıştırılabilir) ise enjeksiyon riski yüksektir.
        if (sayfa.izinler.find('w') != std::string::npos && sayfa.izinler.find('x') != std::string::npos) {
            std::cout << RED << "⚠️  [GÜVENLİK İHLALİ] Kritik İzin Kombinasyonu Tespit Edildi!" << RESET << std::endl;
            std::cout << "    📍 RAM Hücre Adresi: [0x" << std::hex << sayfa.baslangic_adresi << "]" << std::endl;
            std::cout << "    🔒 Erişim İzinleri: " << sayfa.izinler << std::endl;

            // Derinlemesine Bellek Taraması (Deep Memory Inspection)
            if (sayfa.ham_veri.find(ZARARLI_IMZA) != std::string::npos) {
                std::cout << RED << "    🔥 [DURUM] Bellek imza eşleşmesi doğrulandı! Gizli zararlı kod bulundu:" << RESET << std::endl;
                std::cout << RED << "       ↳ \"" << sayfa.ham_veri << "\"" << RESET << std::endl << std::endl;
                tespit_sayisi++;
            }
        }
    }

    // --- ADLİ RAPORLAMA EKRANI ---
    std::cout << CYAN << "==================================================" << RESET << std::endl;
    std::cout << "📊 --- ADLİ PROSES ENJEKSİYON RAPORU ---" << std::endl;
    if (tespit_sayisi > 0) {
        std::cout << RED << "🚨 DURUM: TEHLİKE! Süreç belleğine dinamik kod enjekte edilmiş. " << tespit_sayisi << " ihlal doğrulandı." << RESET << std::endl;
    } else {
        std::cout << GREEN << "✅ DURUM: GÜVENLİ. Süreç hafıza bütünlüğü koruma altında." << RESET << std::endl;
    }
    std::cout << CYAN << "==================================================" << RESET << std::endl;
}

int main() {
    std::cout << CYAN << "==================================================" << RESET << std::endl;
    std::cout << GREEN << "🛡️  C++ PROCESS MEMORY GUARDIAN & INJECTION DETECTOR" << RESET << std::endl;
    std::cout << CYAN << "==================================================" << RESET << std::endl;

    pid_t mevcut_pid = getpid();
    std::cout << "[+] Guardian Modülü Aktif. Mevcut Sistem PID: " << mevcut_pid << std::endl;


    std::vector<HafizaSayfasi> sanal_ram = {
        {0x00400000, "r-xp", "SYS_INIT: Kernel space loaded successfully."},
        {0x00651000, "r--p", "USER_DATA: Session active for user_tuana"},
        {0x7FFF0020, "rw-p", "CACHE: Normal temporary variables stored here."},
        {0x7FFF5FBC, "rwxp", "ALERT! DANGEROUS CODE DETECTED: EVIL_SHELLCODE_EXEC"} // Sızma noktası!
    };

    bellek_bütünlük_analizi_yap(sanal_ram);

    return 0;
}