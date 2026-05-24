# Laporan Reverse Engineering: Analisis File `dyld`

**Penulis:** Manus AI

**Tanggal:** 24 Mei 2026

## 1. Pendahuluan

Laporan ini menyajikan hasil analisis reverse engineering statis terhadap file `dyld` yang disediakan. `dyld` (dynamic linker) adalah komponen krusial dalam sistem operasi Apple (iOS/macOS) yang bertanggung jawab untuk memuat pustaka dinamis (dynamic libraries) yang dibutuhkan oleh aplikasi dan proses. Karena perannya yang sentral dalam eksekusi kode, `dyld` adalah target utama bagi peneliti keamanan dan penyerang yang mencari celah untuk eksekusi kode arbitrer, bypass keamanan, atau privilege escalation. Tujuan dari analisis ini adalah untuk mengidentifikasi potensi celah keamanan atau perilaku yang tidak biasa dalam implementasi `dyld` ini.

## 2. Identifikasi File dan Analisis Awal

Analisis awal file `dyld` memberikan informasi dasar mengenai format dan karakteristiknya:

| Karakteristik       | Detail                                                              |
| :------------------ | :------------------------------------------------------------------ |
| **Nama File**       | `dyld`                                                              |
| **Ukuran File**     | 1.2 MB                                                              |
| **Tipe File**       | `Mach-O 64-bit arm64e (caps: PAC00) dynamic linker, flags:<NOUNDEFS\|DYLDLINK\|TWOLEVEL>` [1] |
| **Arsitektur**      | `arm64e` (menunjukkan penggunaan Pointer Authentication Code/PAC)   |
| **Platform**        | `iphoneos` (versi 18.2) [2]                                         |
| **Versi Ignition**  | `Darwin Ignition Sequence Version 1.0.0: Thu Nov 14 22:45:45 PST 2024; root:libignition-56~52041/libignition_core/RELEASE_ARM64E` [2] |
| **UUID**            | `4eb7459fe23738ce82403f3e2e1ce5ab` [3]                              |

File ini adalah binary Mach-O 64-bit untuk arsitektur `arm64e`, yang merupakan arsitektur yang digunakan pada perangkat Apple modern dan mendukung Pointer Authentication Code (PAC) untuk mitigasi eksploitasi. Kehadiran 
PAC (`PAC00`) menunjukkan bahwa binary ini dirancang dengan fitur keamanan modern. String `Darwin Ignition Sequence` dan `libignition_core` menunjukkan keterkaitannya dengan mekanisme booting dan keamanan Apple yang lebih dalam, kemungkinan terkait dengan proses boot yang aman dan integritas sistem.

## 3. Analisis Statis Mendalam

### 3.1 Struktur Mach-O dan Load Commands

Dengan menggunakan skrip parser Mach-O kustom, kami mengidentifikasi beberapa segmen dan bagian penting:

| Segmen       | VM Addr    | VM Size    | File Off   | File Size  |
| :----------- | :--------- | :--------- | :--------- | :--------- |
| `__TEXT`     | `0x0`      | `0x84000`  | `0x0`      | `0x84000`  |
| `__DATA_CONST` | `0x84000`  | `0x8000`   | `0x84000`  | `0x8000`   |
| `__DATA`     | `0x8c000`  | `0x4000`   | `0x8c000`  | `0x4000`   |
| `__DATA_DIRTY` | `0x90000`  | `0x4000`   | `0x90000`  | `0x4000`   |
| `__TPRO_CONST` | `0x94000`  | `0x44000`  | `0x94000`  | `0x44000`  |
| `__LINKEDIT` | `0xd8000`  | `0x54000`  | `0xd8000`  | `0x52000`  |

Bagian `__TEXT` berisi kode yang dapat dieksekusi, dimulai dari offset `0x1000` dengan ukuran `0x71c94`. Bagian `__LINKEDIT` berisi informasi seperti tabel simbol dan string, yang penting untuk proses linking dinamis. Keberadaan `LC_UUID` juga mengkonfirmasi identitas unik binary ini.

### 3.2 Analisis String dan Environment Variables

Analisis string mengungkapkan beberapa indikator menarik, terutama yang berkaitan dengan environment variables `DYLD_*`:

- **`DYLD_SHARED_REGION`**, **`DYLD_IN_CACHE`**, **`DYLD_FORCE_PLATFORM`**, **`DYLD_SKIP_MAIN`**, **`DYLD_JUST_BUILD_CLOSURE`**, **`DYLD_DLSYM_RESULT`**: Ini adalah variabel lingkungan standar yang digunakan oleh `dyld` untuk mengontrol perilakunya. [4]
- **`DYLD_AMFI_FAKE`**: Ini adalah string yang sangat mencurigakan. AMFI (Apple Mobile File Integrity) adalah mekanisme keamanan penting yang memverifikasi integritas kode. Keberadaan `DYLD_AMFI_FAKE` menunjukkan potensi bypass atau modifikasi perilaku AMFI. [5]
- **`DYLD_PRINT_*`**: Variabel ini digunakan untuk debugging dan logging. Catatan `Note: DYLD_PRINT_* disabled by AMFI` menunjukkan bahwa dalam konfigurasi produksi, fitur debugging ini dinonaktifkan oleh AMFI untuk alasan keamanan. [4]
- **`DYLD_LIBRARY_PATH`**, **`DYLD_FRAMEWORK_PATH`**, **`DYLD_INSERT_LIBRARIES`**: Variabel-variabel ini secara historis telah menjadi vektor serangan umum di `dyld` karena memungkinkan injeksi pustaka arbitrer. Catatan `Note: DYLD_*_PATH env vars disabled by AMFI` dan `Note: LC_DYLD_ENVIRONMENT env vars disabled by AMFI` menunjukkan bahwa Apple telah mencoba memitigasi risiko ini dengan menonaktifkannya di bawah AMFI. [4]
- **`invalid signing key`**: String ini ditemukan di beberapa lokasi dalam binary, menunjukkan adanya pemeriksaan tanda tangan kode. Ini adalah bagian dari mekanisme keamanan untuk memastikan hanya kode yang sah yang dapat dimuat dan dieksekusi. [6]
- **`Darwin Ignition Sequence`**, **`libignition_core`**, **`ignition_level`**, **`ignition_force_dylib_root`**: String-string ini terkait dengan mekanisme 
keamanan `Ignition` Apple, yang kemungkinan besar terkait dengan boot aman dan integritas sistem pada perangkat iOS/macOS. `ignition_level` dan `ignition_force_dylib_root` menunjukkan adanya kontrol terhadap perilaku `Ignition` melalui konfigurasi atau variabel lingkungan. [7]

### 3.3 Disassembly dan Analisis Kode

Analisis disassembly menggunakan Capstone pada bagian `__text` mengungkapkan beberapa pola menarik:

- **Pemeriksaan `DYLD_AMFI_FAKE`**: Pada offset `0x3550c`, kami menemukan urutan instruksi `adrp` dan `add` yang merujuk ke string `DYLD_AMFI_FAKE`. Segera setelah itu, ada panggilan ke fungsi yang kemungkinan besar adalah `__simple_getenv` (di `0x1c4dc`). Jika `DYLD_AMFI_FAKE` diset (yaitu, `getenv` mengembalikan nilai non-NULL), alur eksekusi akan berlanjut ke blok kode yang mencurigakan, termasuk panggilan ke `0x35eb4`. Fungsi di `0x35eb4` tampaknya memparsing nilai heksadesimal dari string, menunjukkan bahwa `DYLD_AMFI_FAKE` mungkin mengambil nilai numerik sebagai flag. Ini adalah potensi celah keamanan yang signifikan, karena memungkinkan penyerang untuk memodifikasi perilaku AMFI dengan menyetel variabel lingkungan ini. [8]

- **Pemeriksaan `DYLD_INSERT_LIBRARIES`**: Pada offset `0x36e8c`, kami menemukan referensi ke `DYLD_INSERT_LIBRARIES`. Meskipun `dyld` modern secara resmi menonaktifkan variabel lingkungan ini di bawah AMFI, keberadaan kode yang secara eksplisit memeriksa dan mungkin memprosesnya menunjukkan bahwa ada jalur kode yang mungkin masih rentan terhadap injeksi pustaka. Jika ada skenario di mana AMFI dapat dilewati (misalnya, melalui `DYLD_AMFI_FAKE`), maka `DYLD_INSERT_LIBRARIES` dapat dieksploitasi. [9]

- **Pemeriksaan Tanda Tangan Kode**: Beberapa lokasi dalam kode merujuk ke string `invalid signing key` (misalnya, di sekitar `0x713d0`). Ini menunjukkan bahwa `dyld` melakukan pemeriksaan tanda tangan kode untuk memverifikasi integritas binary yang dimuat. Namun, jika mekanisme pemeriksaan ini dapat dilewati (misalnya, melalui manipulasi `DYLD_AMFI_FAKE`), maka binary yang tidak ditandatangani atau dimodifikasi dapat dimuat. [6]

- **Fungsi `_amfi_check_dyld_policy_self`**: Keberadaan fungsi ini (`_amfi_check_dyld_policy_self`) menunjukkan bahwa `dyld` secara aktif berinteraksi dengan AMFI untuk menegakkan kebijakan keamanan. Namun, jika ada cara untuk memanipulasi input atau output dari fungsi ini, atau jika `DYLD_AMFI_FAKE` dapat menonaktifkan panggilan ini, maka kebijakan keamanan dapat dikompromikan. [10]

## 4. Identifikasi Celah Keamanan dan Temuan Vulnerability

Berdasarkan analisis statis, kami mengidentifikasi beberapa potensi celah keamanan dan area yang memerlukan penyelidikan lebih lanjut:

1.  **Potensi Bypass AMFI melalui `DYLD_AMFI_FAKE`**: Keberadaan dan pemrosesan variabel lingkungan `DYLD_AMFI_FAKE` adalah temuan yang paling mengkhawatirkan. Jika penyerang dapat menyetel variabel ini ke nilai tertentu (misalnya, nilai heksadesimal yang diparse oleh fungsi di `0x35eb4`), mereka berpotensi menonaktifkan atau memodifikasi perilaku AMFI. Ini dapat membuka pintu bagi injeksi kode, pemuatan pustaka yang tidak ditandatangani, atau bypass mekanisme keamanan lainnya. Ini adalah celah yang sangat serius yang memerlukan validasi dinamis. [8]

2.  **Injeksi Pustaka melalui `DYLD_INSERT_LIBRARIES`**: Meskipun `dyld` modern seharusnya menonaktifkan `DYLD_INSERT_LIBRARIES` di bawah AMFI, keberadaan kode yang memprosesnya, dikombinasikan dengan potensi bypass AMFI, menciptakan skenario eksploitasi. Penyerang dapat menggunakan `DYLD_AMFI_FAKE` untuk menonaktifkan AMFI, kemudian menggunakan `DYLD_INSERT_LIBRARIES` untuk menginjeksikan pustaka arbitrer. [9]

3.  **Kelemahan dalam Pemeriksaan Tanda Tangan Kode**: Jika mekanisme pemeriksaan tanda tangan kode dapat dilewati, baik secara langsung atau tidak langsung melalui bypass AMFI, maka binary yang dimodifikasi atau berbahaya dapat dimuat dan dieksekusi. Ini dapat menyebabkan eksekusi kode arbitrer atau kompromi sistem. [6]

4.  **Manipulasi Mekanisme `Ignition`**: String yang terkait dengan `Darwin Ignition Sequence` dan `ignition_level` menunjukkan adanya mekanisme keamanan yang lebih dalam. Jika ada cara untuk memanipulasi `ignition_level` atau variabel terkait, penyerang mungkin dapat mengubah perilaku boot aman atau integritas sistem. [7]

## 5. Kesimpulan dan Rekomendasi

File `dyld` yang dianalisis menunjukkan beberapa area yang berpotensi menjadi celah keamanan, terutama terkait dengan variabel lingkungan `DYLD_AMFI_FAKE` dan `DYLD_INSERT_LIBRARIES`. Keberadaan `DYLD_AMFI_FAKE` sangat mencurigakan dan dapat menjadi backdoor atau mekanisme debugging yang disalahgunakan untuk bypass AMFI. Kombinasi dari bypass AMFI dan kemampuan injeksi pustaka dapat mengarah pada eksploitasi yang serius.

**Rekomendasi:**

-   **Verifikasi Dinamis**: Lakukan analisis dinamis untuk mengkonfirmasi apakah `DYLD_AMFI_FAKE` benar-benar dapat mem-bypass AMFI dan bagaimana `dyld` merespons ketika variabel ini disetel. Uji juga apakah `DYLD_INSERT_LIBRARIES` dapat dieksploitasi setelah AMFI dilewati. 
-   **Audit Kode Sumber**: Jika memungkinkan, audit kode sumber `dyld` untuk memahami tujuan sebenarnya dari `DYLD_AMFI_FAKE` dan mekanisme `Ignition`. 
-   **Pembaruan Keamanan**: Pastikan sistem operasi selalu diperbarui ke versi terbaru untuk mendapatkan patch keamanan terbaru yang mungkin telah mengatasi celah ini. 

## Referensi

[1] Output `file` command.
[2] Output `strings` command, plist data.
[3] Output `macho_parser.py`.
[4] Output `strings` command, grep `DYLD_`.
[5] Output `strings` command, grep `DYLD_AMFI_FAKE`.
[6] Output `strings` command, grep `invalid signing key`.
[7] Output `strings` command, grep `ignition`.
[8] Disassembly analysis at `0x3550c` and `0x35eb4`.
[9] Disassembly analysis at `0x36e8c`.
[10] Output `strings` command, grep `_amfi_check_dyld_policy_self`.
