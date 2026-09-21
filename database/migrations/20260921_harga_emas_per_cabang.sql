-- =========================================================
-- Harga emas per cabang
-- Tanggal: 2026-09-21
-- Kompatibilitas: MariaDB 10.4+
-- Jalankan satu kali setelah struktur multi-cabang tersedia.
-- =========================================================

CREATE TABLE IF NOT EXISTS
  `tb_harga_emas_backup_per_cabang_20260921`
LIKE
  `tb_harga_emas`;

INSERT IGNORE INTO
  `tb_harga_emas_backup_per_cabang_20260921`
  (`id`, `harga_beli`, `harga_jual`, `tanggal`)
SELECT
  `id`, `harga_beli`, `harga_jual`, `tanggal`
FROM `tb_harga_emas`;

ALTER TABLE `tb_harga_emas`
  ADD COLUMN IF NOT EXISTS `cabang_id`
    INT NULL AFTER `id`,
  ADD COLUMN IF NOT EXISTS `diperbarui_oleh`
    INT NULL AFTER `tanggal`,
  ADD COLUMN IF NOT EXISTS `diperbarui_pada`
    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    ON UPDATE CURRENT_TIMESTAMP
    AFTER `diperbarui_oleh`;

SET @cabang_harga_default = (
  SELECT `id`
  FROM `tb_cabang`
  ORDER BY `is_pusat` DESC, `id` ASC
  LIMIT 1
);

UPDATE `tb_harga_emas`
SET `cabang_id` = @cabang_harga_default
WHERE `cabang_id` IS NULL;

ALTER TABLE `tb_harga_emas`
  MODIFY `cabang_id` INT NOT NULL;

DROP INDEX IF EXISTS `tanggal`
  ON `tb_harga_emas`;

CREATE UNIQUE INDEX IF NOT EXISTS
  `uk_harga_emas_cabang_tanggal`
  ON `tb_harga_emas`
    (`cabang_id`, `tanggal`);

CREATE INDEX IF NOT EXISTS
  `idx_harga_emas_cabang_terbaru`
  ON `tb_harga_emas`
    (`cabang_id`, `tanggal`, `id`);

ALTER TABLE `tb_harga_emas`
  ADD CONSTRAINT `fk_harga_emas_cabang`
    FOREIGN KEY (`cabang_id`)
    REFERENCES `tb_cabang` (`id`)
    ON UPDATE CASCADE
    ON DELETE RESTRICT,
  ADD CONSTRAINT `fk_harga_emas_operator`
    FOREIGN KEY (`diperbarui_oleh`)
    REFERENCES `tb_user` (`id`)
    ON UPDATE CASCADE
    ON DELETE SET NULL;

-- Salin harga terbaru sebagai harga awal setiap cabang aktif.
INSERT INTO `tb_harga_emas` (
  `cabang_id`,
  `harga_beli`,
  `harga_jual`,
  `tanggal`,
  `diperbarui_oleh`,
  `diperbarui_pada`
)
SELECT
  c.`id`,
  harga_terakhir.`harga_beli`,
  harga_terakhir.`harga_jual`,
  CURRENT_DATE,
  NULL,
  CURRENT_TIMESTAMP
FROM `tb_cabang` AS c
INNER JOIN (
  SELECT h.`harga_beli`, h.`harga_jual`
  FROM `tb_harga_emas` AS h
  ORDER BY h.`tanggal` DESC, h.`id` DESC
  LIMIT 1
) AS harga_terakhir
  ON 1 = 1
WHERE c.`status` = 'Aktif'
ON DUPLICATE KEY UPDATE
  `harga_beli` = VALUES(`harga_beli`),
  `harga_jual` = VALUES(`harga_jual`),
  `diperbarui_pada` = CURRENT_TIMESTAMP;

SELECT
  h.`id`,
  h.`cabang_id`,
  c.`kode` AS `kode_cabang`,
  c.`nama` AS `nama_cabang`,
  h.`harga_beli`,
  h.`harga_jual`,
  h.`tanggal`,
  h.`diperbarui_oleh`,
  h.`diperbarui_pada`
FROM `tb_harga_emas` AS h
INNER JOIN `tb_cabang` AS c
  ON c.`id` = h.`cabang_id`
ORDER BY
  h.`tanggal` DESC,
  c.`is_pusat` DESC,
  c.`nama` ASC,
  h.`id` DESC;
