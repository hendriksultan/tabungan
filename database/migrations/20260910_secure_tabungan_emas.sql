-- =========================================================
-- Pengamanan fitur tabungan emas
-- Tanggal: 2026-09-10
-- =========================================================
-- 1. Mencadangkan tabel transaksi sebelum perubahan.
-- 2. Menambahkan request key untuk idempotensi.
-- 3. Menambahkan harga acuan dan informasi masa kunci.
-- 4. Menambahkan index dan check constraint.
-- 5. Membuat tabel pengaturan kunci emas per Nasabah.
-- 6. Melakukan backfill transaksi emas lama.
-- 7. Membuat pengaturan awal untuk pemilik emas lama.
-- =========================================================

CREATE TABLE IF NOT EXISTS
  `tb_transaksi_backup_emas_20260910`
LIKE
  `tb_transaksi`;

INSERT IGNORE INTO
  `tb_transaksi_backup_emas_20260910`
SELECT *
FROM `tb_transaksi`;

-- =========================================================
-- Kolom keamanan dan audit transaksi emas
-- =========================================================

ALTER TABLE `tb_transaksi`
  ADD COLUMN `harga_emas_acuan`
    INT UNSIGNED NULL
    AFTER `gram_emas`,

  ADD COLUMN `durasi_kunci_bulan`
    SMALLINT UNSIGNED NULL
    AFTER `harga_emas_acuan`,

  ADD COLUMN `emas_terkunci_sampai`
    DATETIME NULL
    AFTER `durasi_kunci_bulan`,

  ADD COLUMN `request_key`
    VARCHAR(64) NULL
    AFTER `referensi_id`,

  ADD UNIQUE KEY `uk_transaksi_request_key`
    (`request_key`),

  ADD KEY `idx_transaksi_emas`
    (
      `idNasabah`,
      `status_konfirmasi`,
      `gram_emas`
    ),

  ADD CONSTRAINT `chk_transaksi_harga_emas`
    CHECK (
      `harga_emas_acuan` IS NULL
      OR `harga_emas_acuan` > 0
    ),

  ADD CONSTRAINT `chk_transaksi_durasi_emas`
    CHECK (
      `durasi_kunci_bulan` IS NULL
      OR `durasi_kunci_bulan`
        BETWEEN 6 AND 120
    );

-- =========================================================
-- Tabel pengaturan masa kunci emas per Nasabah
-- =========================================================

CREATE TABLE `tb_kunci_emas` (
  `id_kunci`
    INT NOT NULL AUTO_INCREMENT,

  `id_nasabah`
    INT NOT NULL,

  `durasi_bulan`
    SMALLINT UNSIGNED NOT NULL DEFAULT 6,

  `terkunci_sampai`
    DATETIME NULL,

  `ditetapkan_oleh`
    INT NULL,

  `ditetapkan_pada`
    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

  `diperbarui_pada`
    DATETIME NOT NULL
    DEFAULT CURRENT_TIMESTAMP
    ON UPDATE CURRENT_TIMESTAMP,

  PRIMARY KEY (`id_kunci`),

  UNIQUE KEY `uk_kunci_emas_nasabah`
    (`id_nasabah`),

  KEY `idx_kunci_emas_admin`
    (`ditetapkan_oleh`),

  CONSTRAINT `fk_kunci_emas_nasabah`
    FOREIGN KEY (`id_nasabah`)
    REFERENCES `tb_user` (`id`)
    ON UPDATE CASCADE
    ON DELETE CASCADE,

  CONSTRAINT `fk_kunci_emas_admin`
    FOREIGN KEY (`ditetapkan_oleh`)
    REFERENCES `tb_user` (`id`)
    ON UPDATE CASCADE
    ON DELETE SET NULL,

  CONSTRAINT `chk_kunci_emas_durasi`
    CHECK (
      `durasi_bulan`
        BETWEEN 6 AND 120
    )
)
ENGINE = InnoDB
DEFAULT CHARSET = utf8mb4
COLLATE = utf8mb4_unicode_ci;

-- =========================================================
-- Backfill harga acuan transaksi emas lama
-- =========================================================

UPDATE `tb_transaksi`
SET `harga_emas_acuan` =
  CAST(
    ROUND(
      ABS(
        `nominal` / `gram_emas`
      )
    )
    AS UNSIGNED
  )
WHERE `status_konfirmasi` = 'Sukses'
  AND `gram_emas` IS NOT NULL
  AND `gram_emas` <> 0
  AND `nominal` > 0
  AND `harga_emas_acuan` IS NULL;

-- =========================================================
-- Backfill masa kunci pembelian emas lama
-- =========================================================

UPDATE `tb_transaksi`
SET
  `durasi_kunci_bulan` = 6,

  `emas_terkunci_sampai` =
    DATE_ADD(
      `terdaftar`,
      INTERVAL 6 MONTH
    )
WHERE `status_konfirmasi` = 'Sukses'
  AND `gram_emas` > 0
  AND (
    `durasi_kunci_bulan` IS NULL
    OR `emas_terkunci_sampai` IS NULL
  );

-- =========================================================
-- Pengaturan awal Nasabah yang masih memiliki saldo emas
-- =========================================================

INSERT INTO `tb_kunci_emas` (
  `id_nasabah`,
  `durasi_bulan`,
  `terkunci_sampai`,
  `ditetapkan_oleh`,
  `ditetapkan_pada`,
  `diperbarui_pada`
)
SELECT
  pembelian.idNasabah,
  6,
  pembelian.terkunci_sampai,
  (
    SELECT admin.id
    FROM `tb_user` AS admin
    WHERE admin.level = 'Super Admin'
      AND admin.login = 'Ya'
    ORDER BY admin.id ASC
    LIMIT 1
  ),
  CURRENT_TIMESTAMP,
  CURRENT_TIMESTAMP
FROM (
  SELECT
    transaksi.idNasabah,
    MAX(
      transaksi.emas_terkunci_sampai
    ) AS terkunci_sampai
  FROM `tb_transaksi` AS transaksi
  WHERE transaksi.status_konfirmasi = 'Sukses'
    AND transaksi.gram_emas > 0
  GROUP BY transaksi.idNasabah
) AS pembelian
INNER JOIN (
  SELECT
    saldo.idNasabah,
    SUM(saldo.gram_emas) AS total_gram
  FROM `tb_transaksi` AS saldo
  WHERE saldo.status_konfirmasi = 'Sukses'
    AND saldo.gram_emas <> 0
  GROUP BY saldo.idNasabah
  HAVING SUM(saldo.gram_emas) > 0
) AS pemilik_emas
  ON pemilik_emas.idNasabah =
    pembelian.idNasabah
INNER JOIN `tb_user` AS nasabah
  ON nasabah.id = pembelian.idNasabah
  AND nasabah.level = 'Nasabah'
ON DUPLICATE KEY UPDATE
  `durasi_bulan` =
    GREATEST(
      `durasi_bulan`,
      VALUES(`durasi_bulan`)
    ),

  `terkunci_sampai` =
    CASE
      WHEN `terkunci_sampai` IS NULL
        THEN VALUES(`terkunci_sampai`)
      WHEN VALUES(`terkunci_sampai`) >
        `terkunci_sampai`
        THEN VALUES(`terkunci_sampai`)
      ELSE `terkunci_sampai`
    END,

  `diperbarui_pada` =
    CURRENT_TIMESTAMP;