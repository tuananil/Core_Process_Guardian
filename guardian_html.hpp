// guardian_html.hpp
// Analiz sonucunu tek dosyalık, bağımsız bir HTML raporuna dönüştürür.
// - Dış kaynak yok (font/CDN/script yok); CSP ile script ve ağ erişimi kapalı.
// - Bellekten gelen veri güvenilmezdir: önce kontrol karakterleri temizlenir,
//   sonra HTML kaçışı uygulanır (XSS'e karşı).
#pragma once

#include <ostream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "guardian_core.hpp"

namespace guardian {

inline std::string html_kacis(std::string_view s) {
    std::string o;
    o.reserve(s.size());
    for (const char c : s) {
        switch (c) {
            case '&': o += "&amp;"; break;
            case '<': o += "&lt;"; break;
            case '>': o += "&gt;"; break;
            case '"': o += "&quot;"; break;
            case '\'': o += "&#39;"; break;
            default: o.push_back(c);
        }
    }
    return o;
}

inline std::string adres_hex(std::uintptr_t adres) {
    std::ostringstream ss;
    ss << "0x" << std::hex << adres;
    return ss.str();
}

namespace detay {

inline const char* durum_sinifi(Durum d) {
    switch (d) {
        case Durum::Dogrulandi: return "d-dogrulandi";
        case Durum::Supheli: return "d-supheli";
        case Durum::Gecersiz: return "d-gecersiz";
        default: return "d-normal";
    }
}

inline const char* durum_etiketi(Durum d) {
    switch (d) {
        case Durum::Dogrulandi: return "İmza doğrulandı";
        case Durum::Supheli: return "Şüpheli (W+X)";
        case Durum::Gecersiz: return "Geçersiz kayıt";
        default: return "Normal";
    }
}

inline constexpr const char* KAPAK_CSS = R"CSS(
:root{--bg:#f6f7f9;--panel:#fff;--text:#1b1f24;--muted:#5b6470;--line:#e1e5ea;
--red:#b42318;--red-bg:#fdecea;--amber:#8a5a00;--amber-bg:#fff4d6;--green:#1a7f37;--green-bg:#e3f6e8;--accent:#1f4fd8}
@media (prefers-color-scheme:dark){:root{--bg:#0f1318;--panel:#171c23;--text:#e6e9ee;--muted:#98a2b0;--line:#2a313b;
--red:#ff8a80;--red-bg:#3a1a18;--amber:#ffcf70;--amber-bg:#3a2d10;--green:#6fd08a;--green-bg:#143221;--accent:#8fb0ff}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:960px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:22px;margin:0 0 4px}
.alt{color:var(--muted);margin:0 0 16px}
.sim{background:var(--amber-bg);color:var(--amber);border:1px solid var(--amber);border-radius:8px;padding:10px 14px;margin:0 0 16px}
.ozet{border-radius:10px;padding:16px 18px;margin:0 0 16px;border:1px solid var(--line);background:var(--panel)}
.ozet strong{display:block;font-size:18px;margin-bottom:2px}
.ozet.tehlike{background:var(--red-bg);border-color:var(--red);color:var(--red)}
.ozet.supheli{background:var(--amber-bg);border-color:var(--amber);color:var(--amber)}
.ozet.guvenli{background:var(--green-bg);border-color:var(--green);color:var(--green)}
.sayac{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin:0 0 16px}
.sayac div{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.sayac b{display:block;font-size:24px;line-height:1.2}
.sayac span{color:var(--muted);font-size:13px}
.filtre{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 12px}
.filtre label{cursor:pointer;border:1px solid var(--line);background:var(--panel);border-radius:999px;padding:6px 14px;font-size:14px}
.f{position:absolute;opacity:0;pointer-events:none}
#f-hepsi:checked~.filtre label[for=f-hepsi],#f-wx:checked~.filtre label[for=f-wx],#f-dog:checked~.filtre label[for=f-dog]{background:var(--accent);border-color:var(--accent);color:#fff}
#f-hepsi:focus-visible~.filtre label[for=f-hepsi],#f-wx:focus-visible~.filtre label[for=f-wx],#f-dog:focus-visible~.filtre label[for=f-dog]{outline:2px solid var(--accent);outline-offset:2px}
#f-wx:checked~.kap tbody tr:not(.d-supheli):not(.d-dogrulandi){display:none}
#f-dog:checked~.kap tbody tr:not(.d-dogrulandi){display:none}
.kap{overflow-x:auto;background:var(--panel);border:1px solid var(--line);border-radius:10px}
table{width:100%;border-collapse:collapse;min-width:640px}
th,td{text-align:left;padding:10px 14px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:13px;color:var(--muted);font-weight:600}
tbody tr:last-child td{border-bottom:0}
code{font:13px ui-monospace,SFMono-Regular,Consolas,monospace;word-break:break-word}
.rozet{display:inline-block;border-radius:999px;padding:2px 10px;font-size:12.5px;font-weight:600;white-space:nowrap}
.d-normal .rozet{background:var(--green-bg);color:var(--green)}
.d-supheli .rozet{background:var(--amber-bg);color:var(--amber)}
.d-dogrulandi .rozet{background:var(--red-bg);color:var(--red)}
.d-gecersiz .rozet{background:var(--line);color:var(--muted)}
.d-dogrulandi td:first-child{box-shadow:inset 3px 0 var(--red)}
.d-supheli td:first-child{box-shadow:inset 3px 0 var(--amber)}
footer{color:var(--muted);font-size:13px;margin-top:16px}
)CSS";

}  // namespace detay

inline void html_rapor_yaz(std::ostream& os, const std::vector<HafizaSayfasi>& ram, const AnalizSonucu& s) {
    const char* ozet_sinif = "guvenli";
    std::string ozet_baslik = "Güvenli";
    std::string ozet_metin = "W+X izinli bölge bulunamadı.";
    if (s.dogrulanan_sayisi > 0) {
        ozet_sinif = "tehlike";
        ozet_baslik = "Tehlike: enjeksiyon belirtisi doğrulandı";
        ozet_metin = std::to_string(s.dogrulanan_sayisi) + " bölgede W+X izni ve bilinen zararlı imza birlikte bulundu.";
    } else if (s.supheli_sayisi > 0) {
        ozet_sinif = "supheli";
        ozet_baslik = "Şüpheli";
        ozet_metin = std::to_string(s.supheli_sayisi) + " W+X bölge bulundu; bilinen imza eşleşmesi yok.";
    } else if (s.gecersiz_sayisi > 0) {
        ozet_sinif = "supheli";
        ozet_baslik = "Tam doğrulanamadı";
        ozet_metin = std::to_string(s.gecersiz_sayisi) + " kaydın izin alanı geçersiz.";
    }

    os << "<!doctype html>\n<html lang=\"tr\">\n<head>\n<meta charset=\"utf-8\">\n"
          "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
          "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">\n"
          "<title>Process Guardian Raporu</title>\n<style>"
       << detay::KAPAK_CSS << "</style>\n</head>\n<body>\n<main>\n"
       << "<h1>Core Process Guardian</h1>\n"
       << "<p class=\"alt\">Bellek bütünlüğü ve enjeksiyon analizi raporu</p>\n"
       << "<div class=\"sim\"><strong>Simülasyon:</strong> Bu rapordaki bellek haritası gerçek bir süreçten "
          "okunmadı, örnek veridir.</div>\n"
       << "<section class=\"ozet " << ozet_sinif << "\" role=\"status\"><strong>" << html_kacis(ozet_baslik)
       << "</strong>" << html_kacis(ozet_metin) << "</section>\n"
       << "<div class=\"sayac\">"
       << "<div><b>" << ram.size() << "</b><span>İncelenen bölge</span></div>"
       << "<div><b>" << s.dogrulanan_sayisi << "</b><span>İmza doğrulandı</span></div>"
       << "<div><b>" << s.supheli_sayisi << "</b><span>İmzasız W+X</span></div>"
       << "<div><b>" << s.gecersiz_sayisi << "</b><span>Geçersiz kayıt</span></div>"
       << "</div>\n"
       << "<input class=\"f\" type=\"radio\" name=\"f\" id=\"f-hepsi\" checked aria-label=\"Tüm bölgeler\">"
       << "<input class=\"f\" type=\"radio\" name=\"f\" id=\"f-wx\" aria-label=\"Yalnızca W+X bölgeler\">"
       << "<input class=\"f\" type=\"radio\" name=\"f\" id=\"f-dog\" aria-label=\"Yalnızca doğrulananlar\">\n"
       << "<div class=\"filtre\"><label for=\"f-hepsi\">Tümü</label>"
          "<label for=\"f-wx\">Yalnızca W+X</label>"
          "<label for=\"f-dog\">Doğrulananlar</label></div>\n"
       << "<div class=\"kap\"><table>\n<thead><tr><th>Adres</th><th>İzinler</th><th>Durum</th><th>İçerik</th></tr></thead>\n<tbody>\n";

    for (const auto& sayfa : ram) {
        const Durum d = sayfa_durumu(sayfa);
        os << "<tr class=\"" << detay::durum_sinifi(d) << "\"><td><code>" << adres_hex(sayfa.baslangic_adresi)
           << "</code></td><td><code>" << html_kacis(terminal_icin_temizle(sayfa.izinler)) << "</code></td>"
           << "<td><span class=\"rozet\">" << detay::durum_etiketi(d) << "</span></td>"
           << "<td><code>" << html_kacis(terminal_icin_temizle(sayfa.ham_veri)) << "</code></td></tr>\n";
    }

    os << "</tbody></table></div>\n"
       << "<footer>W+X: aynı anda yazılabilir ve çalıştırılabilir bellek bölgesi. Bu, kod enjeksiyonunun tipik "
          "belirtisidir; ancak JIT kullanan meşru programlarda da görülebilir.</footer>\n"
       << "</main>\n</body>\n</html>\n";
}

}  // namespace guardian
