-- =========================================================
-- Pengamanan rate limit pendaftaran API
-- Tanggal: 2026-09-11
-- =========================================================
-- 1. Membatasi pendaftaran berdasarkan alamat IP.
-- 2. Username disimpan sebagai SHA-256, bukan teks asli.
-- 3. Mencatat hasil percobaan tanpa menyimpan password.
-- 4. Catatan lama dibersihkan berkala oleh endpoint register.
-- =========================================================

CREATE TABLE `tb_register_attempt` (
  `id_attempt`
    BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

  `ip_address`
    VARCHAR(45) NOT NULL,

  `username_hash`
    CHAR(64) NOT NULL,

  `user_agent`
    VARCHAR(255) NULL,

  `berhasil`
    TINYINT(1) NOT NULL DEFAULT 0,

  `id_user`
    INT NULL,

  `dicoba_pada`
    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

  PRIMARY KEY (`id_attempt`),

  KEY `idx_register_attempt_ip_waktu`
    (`ip_address`, `dicoba_pada`),

  KEY `idx_register_attempt_username_waktu`
    (`username_hash`, `dicoba_pada`),

  KEY `idx_register_attempt_waktu`
    (`dicoba_pada`),

  KEY `idx_register_attempt_user`
    (`id_user`),

  CONSTRAINT `fk_register_attempt_user`
    FOREIGN KEY (`id_user`)
    REFERENCES `tb_user` (`id`)
    ON UPDATE CASCADE
    ON DELETE SET NULL,

  CONSTRAINT `chk_register_attempt_username_hash`
    CHECK (
      `username_hash`
        REGEXP '^[0-9a-f]{64}$'
    ),

  CONSTRAINT `chk_register_attempt_berhasil`
    CHECK (`berhasil` IN (0, 1))
)
ENGINE = InnoDB
DEFAULT CHARSET = utf8mb4
COLLATE = utf8mb4_unicode_ci;

-- =========================================================
-- Verifikasi migrasi
-- =========================================================

SELECT COUNT(*) AS `jumlah_percobaan_pendaftaran`
FROM `tb_register_attempt`;
