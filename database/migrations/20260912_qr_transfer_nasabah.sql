-- QR Transfer internal Tabungan Makmur.
-- QR bersifat dinamis, kedaluwarsa, dan hanya dapat dipakai satu kali.

CREATE TABLE IF NOT EXISTS `tb_qr_transfer` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `token_hash` CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `id_penerima` INT NOT NULL,
  `nominal` INT UNSIGNED NULL,
  `status` ENUM('Aktif', 'Digunakan', 'Kedaluwarsa', 'Dibatalkan') NOT NULL DEFAULT 'Aktif',
  `kedaluwarsa_pada` DATETIME NOT NULL,
  `dibuat_pada` DATETIME NOT NULL,
  `digunakan_pada` DATETIME NULL,
  `id_transfer` INT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_qr_transfer_token_hash` (`token_hash`),
  KEY `idx_qr_transfer_penerima_status` (`id_penerima`, `status`),
  KEY `idx_qr_transfer_kedaluwarsa` (`kedaluwarsa_pada`),
  KEY `idx_qr_transfer_id_transfer` (`id_transfer`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
