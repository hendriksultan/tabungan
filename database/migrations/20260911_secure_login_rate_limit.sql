-- =========================================================
-- Pengamanan percobaan login API
-- Tanggal: 2026-09-11
-- =========================================================
-- 1. Mencatat hanya percobaan login yang gagal.
-- 2. Username disimpan sebagai SHA-256, bukan teks asli.
-- 3. Mendukung rate limit berdasarkan username dan alamat IP.
-- 4. Login berhasil tetap diaudit melalui tb_api_token.
-- =========================================================

CREATE TABLE `tb_login_attempt` (
  `id_attempt`
    BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

  `username_hash`
    CHAR(64) NOT NULL,

  `id_user`
    INT NULL,

  `ip_address`
    VARCHAR(45) NOT NULL,

  `user_agent`
    VARCHAR(255) NULL,

  `dicoba_pada`
    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

  PRIMARY KEY (`id_attempt`),

  KEY `idx_login_attempt_username_waktu`
    (`username_hash`, `dicoba_pada`),

  KEY `idx_login_attempt_ip_waktu`
    (`ip_address`, `dicoba_pada`),

  KEY `idx_login_attempt_waktu`
    (`dicoba_pada`),

  KEY `idx_login_attempt_user`
    (`id_user`),

  CONSTRAINT `fk_login_attempt_user`
    FOREIGN KEY (`id_user`)
    REFERENCES `tb_user` (`id`)
    ON UPDATE CASCADE
    ON DELETE SET NULL,

  CONSTRAINT `chk_login_attempt_username_hash`
    CHECK (
      `username_hash`
        REGEXP '^[0-9a-f]{64}$'
    )
)
ENGINE = InnoDB
DEFAULT CHARSET = utf8mb4
COLLATE = utf8mb4_unicode_ci;

-- =========================================================
-- Verifikasi migrasi
-- =========================================================

SELECT COUNT(*) AS `jumlah_percobaan_login`
FROM `tb_login_attempt`;
