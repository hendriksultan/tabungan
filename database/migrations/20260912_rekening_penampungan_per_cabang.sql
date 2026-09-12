-- Rekening penampungan dinamis per cabang.
-- Aman dijalankan lebih dari satu kali: tabel dan data awal tidak diduplikasi.

CREATE TABLE IF NOT EXISTS `tb_rekening_penampungan` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `cabang_id` INT(11) NOT NULL,
  `jenis` VARCHAR(30) NOT NULL DEFAULT 'Bank',
  `nama_bank` VARCHAR(100) NOT NULL,
  `nomor_rekening` VARCHAR(50) NOT NULL,
  `atas_nama` VARCHAR(150) NOT NULL,
  `icon` VARCHAR(30) NOT NULL DEFAULT 'card',
  `status` ENUM('Aktif', 'Nonaktif') NOT NULL DEFAULT 'Aktif',
  `urutan` SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  `created_by` INT(11) NULL,
  `updated_by` INT(11) NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_rekening_cabang_nomor` (`cabang_id`, `nomor_rekening`),
  KEY `idx_rekening_cabang_status_urutan` (`cabang_id`, `status`, `urutan`),
  CONSTRAINT `fk_rekening_penampungan_cabang`
    FOREIGN KEY (`cabang_id`) REFERENCES `tb_cabang` (`id`)
    ON UPDATE CASCADE ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Pindahkan dua rekening yang sebelumnya hardcoded ke cabang Kantor Pusat.
-- Baris hanya dibuat apabila rekening dengan nomor yang sama belum ada.
INSERT INTO `tb_rekening_penampungan`
  (`cabang_id`, `jenis`, `nama_bank`, `nomor_rekening`, `atas_nama`, `icon`, `status`, `urutan`)
SELECT
  c.`id`,
  'Bank',
  'BCA (Bank Central Asia)',
  '0380463563',
  'a.n. Mohammad Lukman Nurdin',
  'card',
  'Aktif',
  10
FROM `tb_cabang` c
WHERE c.`is_pusat` = 1
  AND NOT EXISTS (
    SELECT 1
    FROM `tb_rekening_penampungan` r
    WHERE r.`cabang_id` = c.`id`
      AND r.`nomor_rekening` = '0380463563'
  )
LIMIT 1;

INSERT INTO `tb_rekening_penampungan`
  (`cabang_id`, `jenis`, `nama_bank`, `nomor_rekening`, `atas_nama`, `icon`, `status`, `urutan`)
SELECT
  c.`id`,
  'E-Wallet',
  'DANA',
  '085793771111',
  'a.n. Mohammad Lukman Nurdin',
  'wallet',
  'Aktif',
  20
FROM `tb_cabang` c
WHERE c.`is_pusat` = 1
  AND NOT EXISTS (
    SELECT 1
    FROM `tb_rekening_penampungan` r
    WHERE r.`cabang_id` = c.`id`
      AND r.`nomor_rekening` = '085793771111'
  )
LIMIT 1;

-- Pemeriksaan hasil migrasi.
SELECT
  r.`id`,
  c.`kode` AS `kode_cabang`,
  c.`nama` AS `nama_cabang`,
  r.`jenis`,
  r.`nama_bank`,
  r.`nomor_rekening`,
  r.`atas_nama`,
  r.`status`,
  r.`urutan`
FROM `tb_rekening_penampungan` r
INNER JOIN `tb_cabang` c ON c.`id` = r.`cabang_id`
ORDER BY c.`is_pusat` DESC, c.`nama` ASC, r.`urutan` ASC, r.`id` ASC;
