# PublicOSINTPy

Tool OSINT publik berbasis Python untuk mengambil informasi dari website:

- Email
- Nomor telepon/HP yang tampil di halaman
- Link sosial seperti LinkedIn, Instagram, GitHub, YouTube, X/Twitter, TikTok, WhatsApp, Telegram
- Metadata halaman
- Kemunculan nama orang/organisasi pada website

Gunakan hanya untuk tujuan legal dan etis. Jangan gunakan untuk doxxing, stalking, pelecehan, atau mengakses data yang tidak dimaksudkan untuk publik.

## Cara Pakai

Scan website:

```bash
python3 public_osint.py https://example.com
```

Cari nama pada website:

```bash
python3 public_osint.py https://example.com --name "Nama Orang"
```

Cari beberapa nama:

```bash
python3 public_osint.py https://example.com --name "Nama Satu" --name "Nama Dua"
```

Pakai file daftar nama:

```bash
python3 public_osint.py https://example.com --names-file names.txt
```

Output JSON:

```bash
python3 public_osint.py https://example.com --json
```

Simpan hasil kontak ke CSV:

```bash
python3 public_osint.py https://example.com --csv hasil.csv
```

Crawl lebih luas:

```bash
python3 public_osint.py https://example.com --depth 3 --max-urls 300 --delay 0.5
```

Ikuti subdomain:

```bash
python3 public_osint.py https://example.com --include-subdomains
```

## Opsi

- `--depth`: kedalaman crawl link internal. Default `2`.
- `--max-urls`: batas maksimal halaman yang dikunjungi. Default `120`.
- `--delay`: jeda antar request. Default `0.3` detik.
- `--timeout`: timeout request. Default `10` detik.
- `--name`: nama yang dicari di konten halaman.
- `--names-file`: file daftar nama.
- `--json`: tampilkan hasil JSON.
- `--csv`: simpan hasil kontak ke CSV.

## Catatan

Tool ini hanya membaca data yang tampil publik di halaman yang bisa diakses. Hasil nomor telepon memakai regex, jadi tetap perlu verifikasi manual karena format angka tertentu bisa salah terdeteksi.
