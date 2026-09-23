-- =========================================================
-- Role Koordinator Cabang - fase 1
-- Tanggal: 2026-09-23
-- Kompatibilitas: MariaDB 10.4+
-- =========================================================

ALTER TABLE `tb_user`
  MODIFY COLUMN `level`
    ENUM('Nasabah', 'Administrator', 'Koordinator', 'Super Admin')
    NOT NULL DEFAULT 'Nasabah';

CREATE TABLE IF NOT EXISTS `tb_koordinator_cabang` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `id_koordinator` INT NOT NULL,
  `cabang_id` INT NOT NULL,
  `status` ENUM('Aktif', 'Nonaktif') NOT NULL DEFAULT 'Aktif',
  `ditugaskan_oleh` INT NULL,
  `ditugaskan_pada` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `diperbarui_pada` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    ON UPDATE CURRENT_TIMESTAMP,

  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_koordinator_cabang`
    (`id_koordinator`, `cabang_id`),
  KEY `idx_koordinator_status`
    (`id_koordinator`, `status`),
  KEY `idx_cabang_koordinator_status`
    (`cabang_id`, `status`),
  KEY `idx_koordinator_pemberi_tugas`
    (`ditugaskan_oleh`),

  CONSTRAINT `fk_koordinator_user`
    FOREIGN KEY (`id_koordinator`)
    REFERENCES `tb_user` (`id`)
    ON UPDATE CASCADE
    ON DELETE CASCADE,

  CONSTRAINT `fk_koordinator_cabang`
    FOREIGN KEY (`cabang_id`)
    REFERENCES `tb_cabang` (`id`)
    ON UPDATE CASCADE
    ON DELETE RESTRICT,

  CONSTRAINT `fk_koordinator_pemberi_tugas`
    FOREIGN KEY (`ditugaskan_oleh`)
    REFERENCES `tb_user` (`id`)
    ON UPDATE CASCADE
    ON DELETE SET NULL
)
ENGINE = InnoDB
DEFAULT CHARSET = utf8mb4
COLLATE = utf8mb4_unicode_ci;
