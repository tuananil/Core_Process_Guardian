# Core Process Guardian

Bellek haritasında **W+X (yazılabilir ve çalıştırılabilir) izinli** bölgeleri ve bilinen zararlı
imzaları arayan, C++17 ile yazılmış bir süreç enjeksiyonu algılama **prototipi**.

> **Önemli:** Mevcut sürüm gerçek bir süreci taramaz. `guardian.cpp` içindeki bellek haritası
> örnek (simülasyon) veridir. Gerçek süreç belleği okuma (ör. Windows'ta `VirtualQueryEx` /
> `ReadProcessMemory`, Linux'ta `/proc/<pid>/maps`) henüz uygulanmamıştır. Bu araç tek başına
> bir güvenlik kontrolü olarak kullanılmamalıdır.

## Özellikler

- `/proc/<pid>/maps` biçimindeki izin alanını (`rwxp`) konumsal ve doğrulayarak ayrıştırma
- W+X bölge tespiti; bilinen imza eşleşmesi varsa "doğrulandı", yoksa "şüpheli" sınıflandırması
- Geçersiz kayıtların sessizce atlanmayıp raporlanması (fail-open yok)
- Taranan bellekten gelen verinin terminale yazılmadan önce temizlenmesi (kaçış dizisi enjeksiyonuna karşı)
- Platform bağımlılığı `#ifdef _WIN32` ile ayrıldı (`usleep` kaldırıldı); yalnızca MinGW-w64 ile doğrulandı

## Yapı

| Dosya | Açıklama |
|---|---|
| `guardian_core.hpp` | Analiz ve raporlama mantığı (OS bağımlılığı yok) |
| `guardian.cpp` | Demo programı (konsol hazırlığı, örnek veri) |
| `tests/test_guardian.cpp` | Birim testleri |
| `CMakeLists.txt` | Derleme ve test tanımı |

## Derleme ve test

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
./build/guardian
```

CMake kullanmadan:

```bash
g++ -std=c++17 -Wall -Wextra -o guardian guardian.cpp
g++ -std=c++17 -Wall -Wextra -o test_guardian tests/test_guardian.cpp && ./test_guardian
```

MSVC için `/utf-8` bayrağı gerekir (CMakeLists bunu ekler).

## Teknolojiler

- C++17
- Windows API (yalnızca konsol hazırlığı ve PID için; POSIX'te `unistd.h`)

## Amaç

Süreç analizi ve sistem izleme bilgisini geliştirmek için hazırlanmış eğitim projesi.
