-- =========================================================
-- Pengamanan reset PIN Nasabah
-- Tanggal: 2026-09-11
-- =========================================================
-- 1. Mencadangkan seluruh data pengguna sebelum perubahan.
-- 2. Menambahkan status PIN sementara dan masa berlakunya.
-- 3. Mencatat Administrator yang melakukan reset.
-- 4. Membuat tabel audit reset PIN tanpa menyimpan PIN.
-- =========================================================

CREATE TABLE IF NOT EXISTS
  `tb_user_backup_reset_pin_20260911`
LIKE
  `tb_user`;

INSERT IGNORE INTO
  `tb_user_backup_reset_pin_20260911`
SELECT *
FROM `tb_user`;

-- =========================================================
-- Status reset PIN pada akun Nasabah
-- =========================================================

ALTER TABLE `tb_user`
  ADD COLUMN `pin_wajib_diubah`
    TINYINT UNSIGNED NOT NULL DEFAULT 0
    AFTER `pin_terkunci_sampai`,

  ADD COLUMN `pin_reset_oleh`
    INT NULL
    AFTER `pin_wajib_diubah`,

  ADD COLUMN `pin_reset_pada`
    DATETIME NULL
    AFTER `pin_reset_oleh`,

  ADD COLUMN `pin_reset_kedaluwarsa`
    DATETIME NULL
    AFTER `pin_reset_pada`,

  ADD KEY `idx_user_pin_wajib_diubah`
    (`pin_wajib_diubah`),

  ADD KEY `idx_user_pin_reset_oleh`
    (`pin_reset_oleh`),

  ADD CONSTRAINT `fk_user_pin_reset_oleh`
    FOREIGN KEY (`pin_reset_oleh`)
    REFERENCES `tb_user` (`id`)
    ON UPDATE CASCADE
    ON DELETE SET NULL,

  ADD CONSTRAINT `chk_user_pin_wajib_diubah`
    CHECK (`pin_wajib_diubah` IN (0, 1)),

  ADD CONSTRAINT `chk_user_pin_reset_masa_berlaku`
    CHECK (
      `pin_wajib_diubah` = 0
      OR (
        `pin_reset_pada` IS NOT NULL
        AND `pin_reset_kedaluwarsa` IS NOT NULL
        AND `pin_reset_kedaluwarsa` >
          `pin_reset_pada`
      )
    );

-- =========================================================
-- Audit reset PIN
-- PIN plaintext maupun hash tidak disimpan pada tabel ini.
-- =========================================================

CREATE TABLE `tb_reset_pin_log` (
  `id_log`
    BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

  `id_nasabah`
    INT NULL,

  `nama_nasabah`
    VARCHAR(255) NOT NULL,

  `direset_oleh`
    INT NULL,

  `nama_pereset`
    VARCHAR(255) NOT NULL,

  `level_pereset`
    VARCHAR(50) NOT NULL,

  `cabang_id`
    INT NULL,

  `kedaluwarsa_pada`
    DATETIME NOT NULL,

  `ip_address`
    VARCHAR(45) NULL,

  `user_agent`
    VARCHAR(255) NULL,

  `dibuat_pada`
    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

  PRIMARY KEY (`id_log`),

  KEY `idx_reset_pin_nasabah_waktu`
    (`id_nasabah`, `dibuat_pada`),

  KEY `idx_reset_pin_pereset`
    (`direset_oleh`),

  KEY `idx_reset_pin_cabang`
    (`cabang_id`),

  CONSTRAINT `fk_reset_pin_nasabah`
    FOREIGN KEY (`id_nasabah`)
    REFERENCES `tb_user` (`id`)
    ON UPDATE CASCADE
    ON DELETE SET NULL,

  CONSTRAINT `fk_reset_pin_pereset`
    FOREIGN KEY (`direset_oleh`)
    REFERENCES `tb_user` (`id`)
    ON UPDATE CASCADE
    ON DELETE SET NULL,

  CONSTRAINT `fk_reset_pin_cabang`
    FOREIGN KEY (`cabang_id`)
    REFERENCES `tb_cabang` (`id`)
    ON UPDATE CASCADE
    ON DELETE SET NULL
)
ENGINE = InnoDB
DEFAULT CHARSET = utf8mb4
COLLATE = utf8mb4_unicode_ci;

-- =========================================================
-- Verifikasi migrasi
-- =========================================================

SELECT
  `id`,
  `nama`,
  `level`,
  `cabang_id`,
  `pin_wajib_diubah`,
  `pin_reset_oleh`,
  `pin_reset_pada`,
  `pin_reset_kedaluwarsa`
FROM `tb_user`
ORDER BY `id`;

SELECT COUNT(*) AS `jumlah_log_reset_pin`
FROM `tb_reset_pin_log`;
