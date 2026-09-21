-- Integrasi escrow marketplace - fase 2
-- Prasyarat: 20260916_interbranch_settlement_phase1.sql
-- Kompatibilitas: MariaDB 10.4+

ALTER TABLE `tb_escrow_marketplace`
  ADD COLUMN IF NOT EXISTS `sengketa_diajukan_oleh` INT NULL
    AFTER `dikembalikan_pada`,
  ADD COLUMN IF NOT EXISTS `sengketa_pada` DATETIME NULL
    AFTER `sengketa_diajukan_oleh`,
  ADD COLUMN IF NOT EXISTS `alasan_sengketa` VARCHAR(500) NULL
    AFTER `sengketa_pada`,
  ADD COLUMN IF NOT EXISTS `diselesaikan_oleh` INT NULL
    AFTER `alasan_sengketa`,
  ADD COLUMN IF NOT EXISTS `diselesaikan_pada` DATETIME NULL
    AFTER `diselesaikan_oleh`;

CREATE INDEX IF NOT EXISTS `idx_escrow_status_waktu`
  ON `tb_escrow_marketplace` (`status`, `diperbarui_pada`);

-- Backfill pesanan aktif yang dibayar sebelum integrasi escrow.
INSERT INTO `tb_escrow_marketplace` (
  `id_pesanan`, `id_pembeli`, `id_penjual`,
  `cabang_pembeli_id`, `cabang_penjual_id`,
  `nominal_barang`, `ongkir`, `total_dana`,
  `id_transaksi_pembayaran`, `status`, `ditahan_pada`, `catatan`
)
SELECT
  p.`id_pesanan`, p.`id_pembeli`, t.`id_user`,
  p.`cabang_pembeli_id`, p.`cabang_toko_id`,
  p.`total_harga`, p.`ongkir`, p.`nominal_dibayar`,
  p.`id_transaksi_pembayaran`, 'Ditahan',
  COALESCE(p.`dibayar_pada`, p.`terdaftar`, CURRENT_TIMESTAMP),
  'Backfill escrow dari pesanan aktif sebelum integrasi fase 2'
FROM `tb_pesanan` AS p
INNER JOIN `tb_toko` AS t ON t.`id_toko` = p.`id_toko`
LEFT JOIN `tb_escrow_marketplace` AS e
  ON e.`id_pesanan` = p.`id_pesanan`
WHERE e.`id_escrow` IS NULL
  AND p.`status_pesanan` IN ('Diproses', 'Dikirim')
  AND p.`id_transaksi_pembayaran` IS NOT NULL
  AND p.`nominal_dibayar` IS NOT NULL
  AND p.`nominal_dibayar` = (p.`total_harga` + p.`ongkir`)
  AND p.`cabang_pembeli_id` IS NOT NULL
  AND p.`cabang_toko_id` IS NOT NULL;
