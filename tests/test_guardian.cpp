// Bağımlılıksız basit test koşucusu. Başarısızlıkta sıfırdan farklı kodla çıkar.
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "../guardian_core.hpp"
#include "../guardian_html.hpp"

using namespace guardian;

static int g_basarisiz = 0;
static int g_toplam = 0;

#define CHECK(kosul)                                                              \
    do {                                                                          \
        ++g_toplam;                                                               \
        if (!(kosul)) {                                                           \
            ++g_basarisiz;                                                        \
            std::cerr << "BASARISIZ " << __FILE__ << ":" << __LINE__ << "  " #kosul "\n"; \
        }                                                                         \
    } while (0)

static void test_izin_ayristirma() {
    CHECK(yazilabilir_ve_calistirilabilir_mi("rwxp"));
    CHECK(yazilabilir_ve_calistirilabilir_mi("-wxs"));
    CHECK(!yazilabilir_ve_calistirilabilir_mi("r-xp"));
    CHECK(!yazilabilir_ve_calistirilabilir_mi("rw-p"));
    CHECK(!yazilabilir_ve_calistirilabilir_mi("r--p"));
    // Regresyon: eski kod 'w' ve 'x' karakterini herhangi bir konumda arıyordu.
    CHECK(!yazilabilir_ve_calistirilabilir_mi("xw-p"));
    CHECK(!yazilabilir_ve_calistirilabilir_mi("rxwp"));
    // Geçersiz / bozuk girdi asla "W+X" sayılmaz ve geçersiz olarak işaretlenir.
    CHECK(!izin_gecerli_mi(""));
    CHECK(!izin_gecerli_mi("rw"));
    CHECK(!izin_gecerli_mi("zzzz"));
    CHECK(!yazilabilir_ve_calistirilabilir_mi("wx"));
}

static void test_analiz_mantigi() {
    const std::vector<HafizaSayfasi> ram = {
        {0x1000, "r-xp", "EVIL_SHELLCODE_EXEC"},  // imza var ama W+X değil -> yok sayılır
        {0x2000, "rwxp", "JIT code cache"},       // W+X, imza yok -> şüpheli
        {0x3000, "rwxp", "xx EVIL_SHELLCODE_EXEC xx"},  // W+X + imza -> doğrulandı
        {0x4000, "????", "bozuk"},                // geçersiz kayıt
    };
    const AnalizSonucu s = analiz_et(ram);
    CHECK(s.dogrulanan_sayisi == 1);
    CHECK(s.supheli_sayisi == 1);  // eski kod imzasız W+X bölgeyi "GÜVENLİ" sayıyordu
    CHECK(s.gecersiz_sayisi == 1);
    CHECK(s.bulgular.size() == 2);

    const AnalizSonucu bos = analiz_et({});
    CHECK(bos.bulgular.empty() && bos.dogrulanan_sayisi == 0 && bos.supheli_sayisi == 0);
}

static void test_temizleme() {
    const std::string kotu = std::string("a\x1b[31mB\x00", 8) + "\r\nC";
    const std::string t = terminal_icin_temizle(kotu);
    CHECK(t.find('\x1b') == std::string::npos);
    CHECK(t.find('\0') == std::string::npos);
    CHECK(t.find('\r') == std::string::npos && t.find('\n') == std::string::npos);

    const std::string uzun(MAKS_GOSTERILEN_VERI + 100, 'A');
    const std::string kisa = terminal_icin_temizle(uzun);
    CHECK(kisa.size() == MAKS_GOSTERILEN_VERI + 3);
    CHECK(kisa.substr(MAKS_GOSTERILEN_VERI) == "...");
}

static void test_imza_icinde_kontrol_karakteri() {
    // Terminal kaçış dizisi içeren zararlı veri rapora ham biçimde sızmamalı.
    std::vector<HafizaSayfasi> ram = {
        {0x5000, "rwxp", std::string("\x1b[2J EVIL_SHELLCODE_EXEC")}};
    std::ostringstream os;
    rapor_yaz(os, analiz_et(ram), Renkler{});
    CHECK(os.str().find('\x1b') == std::string::npos);
    CHECK(os.str().find("EVIL_SHELLCODE_EXEC") != std::string::npos);
}

static void test_hex_bayragi_sizmaz() {
    // Regresyon: std::hex kalıcı kalıyor ve sayaç onaltılık basılıyordu (10 -> "a").
    std::vector<HafizaSayfasi> ram;
    for (int i = 0; i < 10; ++i) ram.push_back({0x1000u + static_cast<unsigned>(i), "rwxp", "EVIL_SHELLCODE_EXEC"});
    std::ostringstream os;
    rapor_yaz(os, analiz_et(ram), Renkler{});
    CHECK(os.str().find("eşleşmesi: 10,") != std::string::npos);
    CHECK((os.flags() & std::ios_base::basefield) != std::ios_base::hex);
}

static void test_rapor_durumlari() {
    {
        std::ostringstream os;
        rapor_yaz(os, analiz_et({{0x1, "r-xp", "temiz"}}), Renkler{});
        CHECK(os.str().find("DURUM: GÜVENLİ") != std::string::npos);
    }
    {
        std::ostringstream os;
        rapor_yaz(os, analiz_et({{0x1, "rwxp", "jit"}}), Renkler{});
        CHECK(os.str().find("DURUM: GÜVENLİ") == std::string::npos);  // W+X varken "güvenli" denmemeli
        CHECK(os.str().find("ŞÜPHELİ") != std::string::npos);
    }
    {
        std::ostringstream os;
        rapor_yaz(os, analiz_et({{0x1, "??", "x"}}), Renkler{});
        CHECK(os.str().find("DURUM: GÜVENLİ") == std::string::npos);  // fail-open olmamalı
    }
}

static void test_sayfa_durumu() {
    CHECK(sayfa_durumu({1, "r-xp", "EVIL_SHELLCODE_EXEC"}) == Durum::Normal);
    CHECK(sayfa_durumu({1, "rwxp", "jit"}) == Durum::Supheli);
    CHECK(sayfa_durumu({1, "rwxp", "EVIL_SHELLCODE_EXEC"}) == Durum::Dogrulandi);
    CHECK(sayfa_durumu({1, "??", "x"}) == Durum::Gecersiz);
}

static std::string html_uret(const std::vector<HafizaSayfasi>& ram) {
    std::ostringstream os;
    html_rapor_yaz(os, ram, analiz_et(ram));
    return os.str();
}

static void test_html_kacis() {
    CHECK(html_kacis("<a href=\"x\">&'") == "&lt;a href=&quot;x&quot;&gt;&amp;&#39;");
    CHECK(html_kacis("duz") == "duz");
}

static void test_html_xss_ve_yapi() {
    // Bellekten gelen kötü niyetli içerik HTML'e ham girmemeli (XSS).
    const std::string xss = "<script>alert(1)</script><img src=x onerror=alert(2)> EVIL_SHELLCODE_EXEC";
    const std::string h = html_uret({{0xdeadbeef, "rwxp", xss}, {0x1000, "r--p", "\"><b>x"}});
    CHECK(h.find("<script>alert") == std::string::npos);
    CHECK(h.find("<img src=x") == std::string::npos);
    CHECK(h.find("&lt;script&gt;alert(1)&lt;/script&gt;") != std::string::npos);
    CHECK(h.find("\"><b>x") == std::string::npos);
    // Şablonun kendisi script içermemeli; CSP script'i kapatmalı.
    CHECK(h.find("<script") == std::string::npos);
    CHECK(h.find("default-src 'none'") != std::string::npos);
    // İçerik: simülasyon uyarısı, adres, durum sınıfı.
    CHECK(h.find("Simülasyon") != std::string::npos);
    CHECK(h.find("0xdeadbeef") != std::string::npos);
    CHECK(h.find("d-dogrulandi") != std::string::npos);
    CHECK(h.find("d-normal") != std::string::npos);
    CHECK(h.find("Tehlike") != std::string::npos);
}

static void test_html_ozet_durumlari() {
    CHECK(html_uret({{1, "r-xp", "temiz"}}).find("ozet guvenli") != std::string::npos);
    CHECK(html_uret({{1, "rwxp", "jit"}}).find("ozet supheli") != std::string::npos);
    CHECK(html_uret({{1, "rwxp", "jit"}}).find("ozet guvenli") == std::string::npos);
    CHECK(html_uret({{1, "??", "x"}}).find("ozet guvenli") == std::string::npos);  // fail-open yok
    CHECK(html_uret({}).find("ozet guvenli") != std::string::npos);
}

int main() {
    test_sayfa_durumu();
    test_html_kacis();
    test_html_xss_ve_yapi();
    test_html_ozet_durumlari();
    test_izin_ayristirma();
    test_analiz_mantigi();
    test_temizleme();
    test_imza_icinde_kontrol_karakteri();
    test_hex_bayragi_sizmaz();
    test_rapor_durumlari();
    std::cout << (g_toplam - g_basarisiz) << "/" << g_toplam << " kontrol basarili\n";
    return g_basarisiz == 0 ? 0 : 1;
}
