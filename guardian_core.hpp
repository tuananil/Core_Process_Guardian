// guardian_core.hpp
// Bellek haritası analiz mantığı. Konsol/OS bağımlılığı içermez; böylece
// birim testleri (tests/test_guardian.cpp) ile doğrulanabilir.
#pragma once

#include <cstddef>
#include <cstdint>
#include <ios>
#include <ostream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace guardian {

inline constexpr std::string_view ZARARLI_IMZA = "EVIL_SHELLCODE_EXEC";

// Raporda tek bir bellek bölgesinin ham verisinden en fazla bu kadar bayt gösterilir.
inline constexpr std::size_t MAKS_GOSTERILEN_VERI = 256;

struct HafizaSayfasi {
    std::uintptr_t baslangic_adresi;
    std::string izinler;  // /proc/<pid>/maps biçimi: "rwxp" (r, w, x, p|s)
    std::string ham_veri;
};

enum class Ciddiyet {
    Supheli,    // W+X izin kombinasyonu var, bilinen imza yok
    Dogrulandi  // W+X izin kombinasyonu VE bilinen zararlı imza
};

struct Bulgu {
    std::uintptr_t baslangic_adresi;
    std::string izinler;
    Ciddiyet ciddiyet;
    std::string veri_onizleme;  // terminale güvenle yazdırılabilir (temizlenmiş) hâli
};

struct AnalizSonucu {
    std::vector<Bulgu> bulgular;
    std::size_t supheli_sayisi = 0;     // imzasız W+X bölgeler
    std::size_t dogrulanan_sayisi = 0;  // imza eşleşen W+X bölgeler
    std::size_t gecersiz_sayisi = 0;    // izin alanı ayrıştırılamayan kayıtlar
};

// Geçerli bir izin alanı en az "rwx" biçiminde 3 karakter içermelidir:
// [0] 'r'|'-', [1] 'w'|'-', [2] 'x'|'-'. (4. karakter 'p'/'s' serbest.)
inline bool izin_gecerli_mi(std::string_view izinler) {
    if (izinler.size() < 3) return false;
    const bool r_ok = izinler[0] == 'r' || izinler[0] == '-';
    const bool w_ok = izinler[1] == 'w' || izinler[1] == '-';
    const bool x_ok = izinler[2] == 'x' || izinler[2] == '-';
    return r_ok && w_ok && x_ok;
}

// Konumsal kontrol: yalnızca 2. karakter 'w' VE 3. karakter 'x' ise true.
// (Eski sürüm string içinde herhangi bir yerde 'w'/'x' arıyordu.)
inline bool yazilabilir_ve_calistirilabilir_mi(std::string_view izinler) {
    return izin_gecerli_mi(izinler) && izinler[1] == 'w' && izinler[2] == 'x';
}

inline bool imza_iceriyor_mu(std::string_view veri) {
    return veri.find(ZARARLI_IMZA) != std::string_view::npos;
}

// Taranan bellekten gelen veri güvenilmezdir. Kontrol karakterleri (ESC dahil)
// terminal kaçış dizisi enjeksiyonuna ve log sahteciliğine yol açabileceğinden
// yazdırılmadan önce '.' ile değiştirilir; uzunluk sınırlandırılır.
inline std::string terminal_icin_temizle(std::string_view veri) {
    std::string cikti;
    const std::size_t n = veri.size() < MAKS_GOSTERILEN_VERI ? veri.size() : MAKS_GOSTERILEN_VERI;
    cikti.reserve(n + 3);
    for (std::size_t i = 0; i < n; ++i) {
        const auto c = static_cast<unsigned char>(veri[i]);
        cikti.push_back((c < 0x20 || c == 0x7F) ? '.' : static_cast<char>(c));
    }
    if (veri.size() > n) cikti += "...";
    return cikti;
}

inline AnalizSonucu analiz_et(const std::vector<HafizaSayfasi>& ram_haritasi) {
    AnalizSonucu sonuc;
    for (const auto& sayfa : ram_haritasi) {
        if (!izin_gecerli_mi(sayfa.izinler)) {
            ++sonuc.gecersiz_sayisi;  // sessizce atlamak (fail-open) yerine say ve raporla
            continue;
        }
        // Adli bilişim kuralı: hem yazılabilir hem çalıştırılabilir alan enjeksiyon riskidir.
        if (!yazilabilir_ve_calistirilabilir_mi(sayfa.izinler)) continue;

        Bulgu b{sayfa.baslangic_adresi, sayfa.izinler, Ciddiyet::Supheli, {}};
        if (imza_iceriyor_mu(sayfa.ham_veri)) {
            b.ciddiyet = Ciddiyet::Dogrulandi;
            b.veri_onizleme = terminal_icin_temizle(sayfa.ham_veri);
            ++sonuc.dogrulanan_sayisi;
        } else {
            ++sonuc.supheli_sayisi;
        }
        sonuc.bulgular.push_back(std::move(b));
    }
    return sonuc;
}

struct Renkler {
    const char* reset = "";
    const char* kirmizi = "";
    const char* yesil = "";
    const char* sari = "";
    const char* cyan = "";
};

inline Renkler ansi_renkler() {
    return Renkler{"\033[0m", "\033[31m", "\033[32m", "\033[33m", "\033[36m"};
}

// Akışın biçim durumunu (std::hex vb.) çağıran taraf için bozmadan yazar.
inline void rapor_yaz(std::ostream& os, const AnalizSonucu& s, const Renkler& r) {
    const auto eski_bayraklar = os.flags();

    for (const auto& b : s.bulgular) {
        os << r.kirmizi << "⚠️  [GÜVENLİK İHLALİ] Kritik İzin Kombinasyonu (W+X) Tespit Edildi!" << r.reset << '\n';
        os << "    📍 RAM Hücre Adresi: [0x" << std::hex << b.baslangic_adresi << "]" << '\n';
        os.flags(eski_bayraklar);
        os << "    🔒 Erişim İzinleri: " << b.izinler << '\n';
        if (b.ciddiyet == Ciddiyet::Dogrulandi) {
            os << r.kirmizi << "    🔥 [DURUM] Bellek imza eşleşmesi doğrulandı! Gizli zararlı kod bulundu:" << r.reset << '\n';
            os << r.kirmizi << "       ↳ \"" << b.veri_onizleme << "\"" << r.reset << "\n\n";
        } else {
            os << r.sari << "    [DURUM] Bilinen imza yok; W+X bölge yine de şüphelidir." << r.reset << "\n\n";
        }
    }

    os << r.cyan << "==================================================" << r.reset << '\n';
    os << "📊 --- ADLİ PROSES ENJEKSİYON RAPORU ---" << '\n';
    if (s.dogrulanan_sayisi > 0) {
        os << r.kirmizi << "🚨 DURUM: TEHLİKE! Doğrulanan imza eşleşmesi: " << s.dogrulanan_sayisi
           << ", imzasız W+X bölge: " << s.supheli_sayisi << "." << r.reset << '\n';
    } else if (s.supheli_sayisi > 0) {
        os << r.sari << "⚠️  DURUM: ŞÜPHELİ. " << s.supheli_sayisi
           << " W+X bölge bulundu (bilinen imza eşleşmesi yok)." << r.reset << '\n';
    } else if (s.gecersiz_sayisi > 0) {
        os << r.sari << "⚠️  DURUM: TAM DOĞRULANAMADI. " << s.gecersiz_sayisi
           << " kaydın izin alanı geçersiz." << r.reset << '\n';
    } else {
        os << r.yesil << "✅ DURUM: GÜVENLİ. W+X bölge bulunamadı." << r.reset << '\n';
    }
    if (s.gecersiz_sayisi > 0 && (s.dogrulanan_sayisi > 0 || s.supheli_sayisi > 0)) {
        os << r.sari << "UYARI: " << s.gecersiz_sayisi << " kaydın izin alanı geçersiz, analiz dışı bırakıldı."
           << r.reset << '\n';
    }
    os << r.cyan << "==================================================" << r.reset << '\n';
    os.flags(eski_bayraklar);
}

}  // namespace guardian
