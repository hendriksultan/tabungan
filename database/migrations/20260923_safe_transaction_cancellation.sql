-- =========================================================
-- Pembatalan transaksi dan transfer yang aman serta auditable
-- Tanggal: 2026-09-23
-- Kompatibilitas: MariaDB 10.4+
--
-- Jalankan satu kali sebelum mengunggah controller/view baru.
-- Backup database penuh tetap disarankan sebelum migrasi produksi.
-- =========================================================

-- Status transfer diseragamkan agar pembatalan dapat dicatat tanpa
-- menghapus histori. Nilai lama selain Sukses dianggap Dibatalkan.
ALTER TABLE `tb_transfer`
  MODIFY COLUMN `status_transfer`
    VARCHAR(30) NOT NULL DEFAULT 'Sukses';

UPDATE `tb_transfer`
SET `status_transfer` = 'Dibatalkan'
WHERE `status_transfer` <> 'Sukses';

ALTER TABLE `tb_transfer`
  MODIFY COLUMN `status_transfer`
    ENUM('Sukses', 'Dibatalkan') NOT NULL DEFAULT 'Sukses',

  ADD COLUMN IF NOT EXISTS `dibatalkan_oleh`
    INT NULL AFTER `status_transfer`,

  ADD COLUMN IF NOT EXISTS `dibatalkan_pada`
    DATETIME NULL AFTER `dibatalkan_oleh`,

  ADD COLUMN IF NOT EXISTS `alasan_pembatalan`
    VARCHAR(500) NULL AFTER `dibatalkan_pada`,

  ADD INDEX IF NOT EXISTS `idx_transfer_status_batal`
    (`status_transfer`, `dibatalkan_pada`),

  ADD INDEX IF NOT EXISTS `idx_transfer_pembatal`
    (`dibatalkan_oleh`);

ALTER TABLE `tb_transaksi`
  ADD COLUMN IF NOT EXISTS `dibatalkan_oleh`
    INT NULL AFTER `status_konfirmasi`,

  ADD COLUMN IF NOT EXISTS `dibatalkan_pada`
    DATETIME NULL AFTER `dibatalkan_oleh`,

  ADD COLUMN IF NOT EXISTS `alasan_pembatalan`
    VARCHAR(500) NULL AFTER `dibatalkan_pada`,

  ADD INDEX IF NOT EXISTS `idx_transaksi_status_batal`
    (`status_konfirmasi`, `dibatalkan_pada`),

  ADD INDEX IF NOT EXISTS `idx_transaksi_pembatal`
    (`dibatalkan_oleh`);

-- Transfer lintas cabang lama yang belum mempunyai kewajiban settlement
-- tidak langsung ditagihkan. Data ditandai Sengketa agar dapat direkonsiliasi
-- terlebih dahulu dan tidak menimbulkan pembayaran ganda.
INSERT IGNORE INTO `tb_kewajiban_antar_cabang` (
  `kode_kewajiban`,
  `jenis_sumber`,
  `referensi_id`,
  `cabang_asal_id`,
  `cabang_tujuan_id`,
  `nominal`,
  `status`,
  `dibuat_oleh`,
  `catatan_status`
)
SELECT
  CONCAT('KWA-AUDIT-TRF-', LPAD(t.`id`, 10, '0')),
  'TransferNasabah',
  t.`id`,
  t.`cabang_asal_id`,
  t.`cabang_tujuan_id`,
  CAST(t.`nominal` AS UNSIGNED),
  'Sengketa',
  COALESCE(t.`dibuat_oleh`, t.`idPengirim`),
  'Audit migrasi 20260923: transfer lama belum memiliki kewajiban settlement.'
FROM `tb_transfer` AS t
LEFT JOIN `tb_kewajiban_antar_cabang` AS k
  ON k.`jenis_sumber` = 'TransferNasabah'
 AND k.`referensi_id` = t.`id`
WHERE t.`status_transfer` = 'Sukses'
  AND t.`cabang_asal_id` <> t.`cabang_tujuan_id`
  AND k.`id_kewajiban` IS NULL;

-- Ringkasan audit setelah migrasi.
SELECT
  COUNT(*) AS `transfer_lintas_cabang_perlu_rekonsiliasi`,
  COALESCE(SUM(`nominal`), 0) AS `total_nominal_perlu_rekonsiliasi`
FROM `tb_kewajiban_antar_cabang`
WHERE `jenis_sumber` = 'TransferNasabah'
  AND `status` = 'Sengketa'
  AND `catatan_status` LIKE 'Audit migrasi 20260923:%';
