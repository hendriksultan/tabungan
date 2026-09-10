-- =========================================================
-- Pengamanan update aplikasi OTA/APK
-- Tanggal: 2026-09-10
-- =========================================================
-- 1. Mencadangkan konfigurasi aplikasi.
-- 2. Menambahkan metadata nama, ukuran, dan SHA-256 APK.
-- 3. Mencatat Super Admin pengunggah APK berikutnya.
-- 4. Menambahkan index, foreign key, dan constraint.
-- 5. Melakukan backfill metadata APK versi 1.0.7.
-- =========================================================

CREATE TABLE IF NOT EXISTS
  `tb_aplikasi_backup_ota_20260910`
LIKE
  `tb_aplikasi`;

INSERT IGNORE INTO
  `tb_aplikasi_backup_ota_20260910`
SELECT *
FROM `tb_aplikasi`;

-- =========================================================
-- Metadata integritas APK
-- =========================================================

ALTER TABLE `tb_aplikasi`
  ADD COLUMN `apk_nama_file`
    VARCHAR(255) NULL
    AFTER `link_apk`,

  ADD COLUMN `apk_ukuran`
    BIGINT UNSIGNED NULL
    AFTER `apk_nama_file`,

  ADD COLUMN `apk_sha256`
    CHAR(64) NULL
    AFTER `apk_ukuran`,

  ADD COLUMN `apk_diupload_oleh`
    INT NULL
    AFTER `apk_sha256`,

  ADD KEY `idx_aplikasi_apk_admin`
    (`apk_diupload_oleh`),

  ADD CONSTRAINT `fk_aplikasi_apk_admin`
    FOREIGN KEY (`apk_diupload_oleh`)
    REFERENCES `tb_user` (`id`)
    ON UPDATE CASCADE
    ON DELETE SET NULL,

  ADD CONSTRAINT `chk_aplikasi_apk_ukuran`
    CHECK (
      `apk_ukuran` IS NULL
      OR `apk_ukuran`
        BETWEEN 1024 AND 209715200
    ),

  ADD CONSTRAINT `chk_aplikasi_apk_sha256`
    CHECK (
      `apk_sha256` IS NULL
      OR `apk_sha256`
        REGEXP '^[0-9a-f]{64}$'
    );

-- =========================================================
-- Backfill metadata APK aktif versi 1.0.7
-- =========================================================

UPDATE `tb_aplikasi`
SET
  `apk_nama_file` =
    'TabunganMakmur_v1_0_7_1788347961.apk',

  `apk_ukuran` =
    89430318,

  `apk_sha256` =
    'a31ee7303477626f82d74797738e151698a4a66b9ffe5bffded1b5b3d51c8221',

  /*
   * Pengunggah file lama tidak dapat dipastikan,
   * sehingga tidak boleh ditebak.
   */
  `apk_diupload_oleh` =
    NULL
WHERE `id` = 1
  AND `versi_aplikasi` = '1.0.7'
  AND SUBSTRING_INDEX(
    `link_apk`,
    '/',
    -1
  ) =
    'TabunganMakmur_v1_0_7_1788347961.apk';

-- =========================================================
-- Verifikasi migrasi
-- =========================================================

SELECT
  `id`,
  `versi_aplikasi`,
  `apk_nama_file`,
  `apk_ukuran`,
  `apk_sha256`,
  CHAR_LENGTH(`apk_sha256`)
    AS `panjang_sha256`,
  `apk_diupload_oleh`,
  `tgl_update_apk`
FROM `tb_aplikasi`
WHERE `id` = 1;