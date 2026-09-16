-- =========================================================
-- Settlement antar-cabang dan escrow marketplace - fase 1
-- Tanggal: 2026-09-16
-- Kompatibilitas: MariaDB 10.4+
-- =========================================================
-- Migrasi ini hanya menambahkan struktur baru.
-- Tidak mengubah saldo, transfer, transaksi, maupun pesanan lama.
-- Integrasi API dilakukan pada fase berikutnya setelah migrasi
-- berhasil diverifikasi di lingkungan lokal.
-- Validasi nominal, perbedaan cabang, jumlah detail, dan pemisahan
-- tugas pengirim/verifikator ditegakkan oleh API agar kompatibel
-- dengan parser phpMyAdmin lama yang menolak named CHECK constraint.
-- =========================================================

-- =========================================================
-- 1. Kewajiban finansial antar-cabang per transaksi sumber
-- =========================================================

CREATE TABLE IF NOT EXISTS `tb_kewajiban_antar_cabang` (
  `id_kewajiban`
    BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

  `kode_kewajiban`
    VARCHAR(50) NOT NULL,

  `jenis_sumber`
    ENUM('TransferNasabah', 'Marketplace') NOT NULL,

  `referensi_id`
    INT NOT NULL,

  `cabang_asal_id`
    INT NOT NULL,

  `cabang_tujuan_id`
    INT NOT NULL,

  `nominal`
    BIGINT UNSIGNED NOT NULL,

  `status`
    ENUM(
      'Terbuka',
      'Dibatch',
      'Selesai',
      'Dibatalkan',
      'Sengketa'
    ) NOT NULL DEFAULT 'Terbuka',

  `dibuat_oleh`
    INT NULL,

  `dibuat_pada`
    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

  `diperbarui_pada`
    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    ON UPDATE CURRENT_TIMESTAMP,

  `selesai_pada`
    DATETIME NULL,

  `dibatalkan_pada`
    DATETIME NULL,

  `catatan_status`
    VARCHAR(500) NULL,

  PRIMARY KEY (`id_kewajiban`),

  UNIQUE KEY `uk_kewajiban_kode`
    (`kode_kewajiban`),

  UNIQUE KEY `uk_kewajiban_sumber`
    (`jenis_sumber`, `referensi_id`),

  KEY `idx_kewajiban_asal_status_waktu`
    (`cabang_asal_id`, `status`, `dibuat_pada`),

  KEY `idx_kewajiban_tujuan_status_waktu`
    (`cabang_tujuan_id`, `status`, `dibuat_pada`),

  KEY `idx_kewajiban_pembuat`
    (`dibuat_oleh`),

  CONSTRAINT `fk_kewajiban_cabang_asal`
    FOREIGN KEY (`cabang_asal_id`)
    REFERENCES `tb_cabang` (`id`)
    ON UPDATE CASCADE
    ON DELETE RESTRICT,

  CONSTRAINT `fk_kewajiban_cabang_tujuan`
    FOREIGN KEY (`cabang_tujuan_id`)
    REFERENCES `tb_cabang` (`id`)
    ON UPDATE CASCADE
    ON DELETE RESTRICT,

  CONSTRAINT `fk_kewajiban_pembuat`
    FOREIGN KEY (`dibuat_oleh`)
    REFERENCES `tb_user` (`id`)
    ON UPDATE CASCADE
    ON DELETE SET NULL
)
ENGINE = InnoDB
DEFAULT CHARSET = utf8mb4
COLLATE = utf8mb4_unicode_ci;

-- =========================================================
-- 2. Bukti perpindahan dana fisik antar-rekening cabang
-- =========================================================

CREATE TABLE IF NOT EXISTS `tb_settlement_cabang` (
  `id_settlement`
    BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

  `kode_settlement`
    VARCHAR(50) NOT NULL,

  `cabang_asal_id`
    INT NOT NULL,

  `cabang_tujuan_id`
    INT NOT NULL,

  `rekening_asal_id`
    INT NULL,

  `rekening_tujuan_id`
    INT NULL,

  `rekening_asal_nama`
    VARCHAR(150) NOT NULL,

  `rekening_asal_nomor`
    VARCHAR(50) NOT NULL,

  `rekening_asal_atas_nama`
    VARCHAR(150) NOT NULL,

  `rekening_tujuan_nama`
    VARCHAR(150) NOT NULL,

  `rekening_tujuan_nomor`
    VARCHAR(50) NOT NULL,

  `rekening_tujuan_atas_nama`
    VARCHAR(150) NOT NULL,

  `nominal_total`
    BIGINT UNSIGNED NOT NULL,

  `status`
    ENUM(
      'MenungguTransfer',
      'MenungguVerifikasi',
      'Selesai',
      'Ditolak',
      'Sengketa',
      'Dibatalkan'
    ) NOT NULL DEFAULT 'MenungguTransfer',

  `referensi_bank`
    VARCHAR(100) NULL,

  `bukti_transfer`
    VARCHAR(255) NULL,

  `dibuat_oleh`
    INT NULL,

  `dikirim_oleh`
    INT NULL,

  `dikirim_pada`
    DATETIME NULL,

  `diverifikasi_oleh`
    INT NULL,

  `diverifikasi_pada`
    DATETIME NULL,

  `ditolak_oleh`
    INT NULL,

  `ditolak_pada`
    DATETIME NULL,

  `alasan_penolakan`
    VARCHAR(500) NULL,

  `catatan`
    VARCHAR(500) NULL,

  `dibuat_pada`
    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

  `diperbarui_pada`
    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    ON UPDATE CURRENT_TIMESTAMP,

  PRIMARY KEY (`id_settlement`),

  UNIQUE KEY `uk_settlement_kode`
    (`kode_settlement`),

  UNIQUE KEY `uk_settlement_referensi_bank`
    (`referensi_bank`),

  KEY `idx_settlement_asal_status_waktu`
    (`cabang_asal_id`, `status`, `dibuat_pada`),

  KEY `idx_settlement_tujuan_status_waktu`
    (`cabang_tujuan_id`, `status`, `dibuat_pada`),

  KEY `idx_settlement_rekening_asal`
    (`rekening_asal_id`),

  KEY `idx_settlement_rekening_tujuan`
    (`rekening_tujuan_id`),

  KEY `idx_settlement_pembuat`
    (`dibuat_oleh`),

  KEY `idx_settlement_pengirim`
    (`dikirim_oleh`),

  KEY `idx_settlement_verifikator`
    (`diverifikasi_oleh`),

  KEY `idx_settlement_penolak`
    (`ditolak_oleh`),

  CONSTRAINT `fk_settlement_cabang_asal`
    FOREIGN KEY (`cabang_asal_id`)
    REFERENCES `tb_cabang` (`id`)
    ON UPDATE CASCADE
    ON DELETE RESTRICT,

  CONSTRAINT `fk_settlement_cabang_tujuan`
    FOREIGN KEY (`cabang_tujuan_id`)
    REFERENCES `tb_cabang` (`id`)
    ON UPDATE CASCADE
    ON DELETE RESTRICT,

  CONSTRAINT `fk_settlement_rekening_asal`
    FOREIGN KEY (`rekening_asal_id`)
    REFERENCES `tb_rekening_penampungan` (`id`)
    ON UPDATE CASCADE
    ON DELETE SET NULL,

  CONSTRAINT `fk_settlement_rekening_tujuan`
    FOREIGN KEY (`rekening_tujuan_id`)
    REFERENCES `tb_rekening_penampungan` (`id`)
    ON UPDATE CASCADE
    ON DELETE SET NULL,

  CONSTRAINT `fk_settlement_pembuat`
    FOREIGN KEY (`dibuat_oleh`)
    REFERENCES `tb_user` (`id`)
    ON UPDATE CASCADE
    ON DELETE SET NULL,

  CONSTRAINT `fk_settlement_pengirim`
    FOREIGN KEY (`dikirim_oleh`)
    REFERENCES `tb_user` (`id`)
    ON UPDATE CASCADE
    ON DELETE SET NULL,

  CONSTRAINT `fk_settlement_verifikator`
    FOREIGN KEY (`diverifikasi_oleh`)
    REFERENCES `tb_user` (`id`)
    ON UPDATE CASCADE
    ON DELETE SET NULL,

  CONSTRAINT `fk_settlement_penolak`
    FOREIGN KEY (`ditolak_oleh`)
    REFERENCES `tb_user` (`id`)
    ON UPDATE CASCADE
    ON DELETE SET NULL
)
ENGINE = InnoDB
DEFAULT CHARSET = utf8mb4
COLLATE = utf8mb4_unicode_ci;

-- =========================================================
-- 3. Detail kewajiban yang dihimpun pada satu settlement
-- Fase pertama mengelompokkan kewajiban dengan arah yang sama.
-- Netting dua arah dapat ditambahkan setelah alur dasar stabil.
-- =========================================================

CREATE TABLE IF NOT EXISTS `tb_settlement_detail` (
  `id_detail`
    BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

  `id_settlement`
    BIGINT UNSIGNED NOT NULL,

  `id_kewajiban`
    BIGINT UNSIGNED NOT NULL,

  `nominal_dialokasikan`
    BIGINT UNSIGNED NOT NULL,

  `dibuat_pada`
    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

  PRIMARY KEY (`id_detail`),

  UNIQUE KEY `uk_settlement_detail_kewajiban`
    (`id_kewajiban`),

  UNIQUE KEY `uk_settlement_detail_pasangan`
    (`id_settlement`, `id_kewajiban`),

  KEY `idx_settlement_detail_settlement`
    (`id_settlement`),

  CONSTRAINT `fk_settlement_detail_header`
    FOREIGN KEY (`id_settlement`)
    REFERENCES `tb_settlement_cabang` (`id_settlement`)
    ON UPDATE CASCADE
    ON DELETE RESTRICT,

  CONSTRAINT `fk_settlement_detail_kewajiban`
    FOREIGN KEY (`id_kewajiban`)
    REFERENCES `tb_kewajiban_antar_cabang` (`id_kewajiban`)
    ON UPDATE CASCADE
    ON DELETE RESTRICT
)
ENGINE = InnoDB
DEFAULT CHARSET = utf8mb4
COLLATE = utf8mb4_unicode_ci;

-- =========================================================
-- 4. Dana marketplace yang ditahan sebelum pencairan
-- =========================================================

CREATE TABLE IF NOT EXISTS `tb_escrow_marketplace` (
  `id_escrow`
    BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

  `id_pesanan`
    INT NOT NULL,

  `id_pembeli`
    INT NOT NULL,

  `id_penjual`
    INT NOT NULL,

  `cabang_pembeli_id`
    INT NOT NULL,

  `cabang_penjual_id`
    INT NOT NULL,

  `nominal_barang`
    BIGINT UNSIGNED NOT NULL,

  `ongkir`
    BIGINT UNSIGNED NOT NULL DEFAULT 0,

  `total_dana`
    BIGINT UNSIGNED NOT NULL,

  `id_transaksi_pembayaran`
    INT NOT NULL,

  `id_transaksi_pencairan`
    INT NULL,

  `id_transaksi_refund`
    INT NULL,

  `id_kewajiban`
    BIGINT UNSIGNED NULL,

  `status`
    ENUM(
      'Ditahan',
      'MenungguSettlement',
      'Cair',
      'Dikembalikan',
      'Sengketa',
      'Dibatalkan'
    ) NOT NULL DEFAULT 'Ditahan',

  `ditahan_pada`
    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

  `dicairkan_pada`
    DATETIME NULL,

  `dikembalikan_pada`
    DATETIME NULL,

  `catatan`
    VARCHAR(500) NULL,

  `diperbarui_pada`
    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    ON UPDATE CURRENT_TIMESTAMP,

  PRIMARY KEY (`id_escrow`),

  UNIQUE KEY `uk_escrow_pesanan`
    (`id_pesanan`),

  UNIQUE KEY `uk_escrow_transaksi_pembayaran`
    (`id_transaksi_pembayaran`),

  UNIQUE KEY `uk_escrow_transaksi_pencairan`
    (`id_transaksi_pencairan`),

  UNIQUE KEY `uk_escrow_transaksi_refund`
    (`id_transaksi_refund`),

  UNIQUE KEY `uk_escrow_kewajiban`
    (`id_kewajiban`),

  KEY `idx_escrow_pembeli_status`
    (`id_pembeli`, `status`),

  KEY `idx_escrow_penjual_status`
    (`id_penjual`, `status`),

  KEY `idx_escrow_cabang_pembeli_status`
    (`cabang_pembeli_id`, `status`),

  KEY `idx_escrow_cabang_penjual_status`
    (`cabang_penjual_id`, `status`),

  CONSTRAINT `fk_escrow_pesanan`
    FOREIGN KEY (`id_pesanan`)
    REFERENCES `tb_pesanan` (`id_pesanan`)
    ON UPDATE CASCADE
    ON DELETE RESTRICT,

  CONSTRAINT `fk_escrow_pembeli`
    FOREIGN KEY (`id_pembeli`)
    REFERENCES `tb_user` (`id`)
    ON UPDATE CASCADE
    ON DELETE RESTRICT,

  CONSTRAINT `fk_escrow_penjual`
    FOREIGN KEY (`id_penjual`)
    REFERENCES `tb_user` (`id`)
    ON UPDATE CASCADE
    ON DELETE RESTRICT,

  CONSTRAINT `fk_escrow_cabang_pembeli`
    FOREIGN KEY (`cabang_pembeli_id`)
    REFERENCES `tb_cabang` (`id`)
    ON UPDATE CASCADE
    ON DELETE RESTRICT,

  CONSTRAINT `fk_escrow_cabang_penjual`
    FOREIGN KEY (`cabang_penjual_id`)
    REFERENCES `tb_cabang` (`id`)
    ON UPDATE CASCADE
    ON DELETE RESTRICT,

  CONSTRAINT `fk_escrow_transaksi_pembayaran`
    FOREIGN KEY (`id_transaksi_pembayaran`)
    REFERENCES `tb_transaksi` (`id`)
    ON UPDATE CASCADE
    ON DELETE RESTRICT,

  CONSTRAINT `fk_escrow_transaksi_pencairan`
    FOREIGN KEY (`id_transaksi_pencairan`)
    REFERENCES `tb_transaksi` (`id`)
    ON UPDATE CASCADE
    ON DELETE RESTRICT,

  CONSTRAINT `fk_escrow_transaksi_refund`
    FOREIGN KEY (`id_transaksi_refund`)
    REFERENCES `tb_transaksi` (`id`)
    ON UPDATE CASCADE
    ON DELETE RESTRICT,

  CONSTRAINT `fk_escrow_kewajiban`
    FOREIGN KEY (`id_kewajiban`)
    REFERENCES `tb_kewajiban_antar_cabang` (`id_kewajiban`)
    ON UPDATE CASCADE
    ON DELETE RESTRICT
)
ENGINE = InnoDB
DEFAULT CHARSET = utf8mb4
COLLATE = utf8mb4_unicode_ci;
