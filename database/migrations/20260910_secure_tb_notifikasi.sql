-- =========================================================
-- Pengamanan tabel notifikasi
-- Tanggal: 2026-09-10
-- =========================================================
-- 1. Mencadangkan dan membersihkan notifikasi yatim.
-- 2. Menormalkan nilai is_read.
-- 3. Menambahkan index untuk daftar dan jumlah unread.
-- 4. Menambahkan foreign key dan check constraint.
-- =========================================================

CREATE TABLE IF NOT EXISTS
    `tb_notifikasi_backup_orphan_20260910`
LIKE
    `tb_notifikasi`;

INSERT IGNORE INTO
    `tb_notifikasi_backup_orphan_20260910`
SELECT n.*
FROM `tb_notifikasi` n
LEFT JOIN `tb_user` u
    ON u.id = n.id_user
WHERE u.id IS NULL;

DELETE n
FROM `tb_notifikasi` n
LEFT JOIN `tb_user` u
    ON u.id = n.id_user
WHERE u.id IS NULL;

UPDATE `tb_notifikasi`
SET `is_read` = CASE
    WHEN `is_read` = 1 THEN 1
    ELSE 0
END
WHERE `is_read` IS NULL
   OR `is_read` NOT IN (0, 1);

ALTER TABLE `tb_notifikasi`
    MODIFY `is_read`
        TINYINT(1) UNSIGNED NOT NULL DEFAULT 0,

    ADD KEY `idx_notifikasi_user_read_id`
        (`id_user`, `is_read`, `id_notifikasi`),

    ADD CONSTRAINT `fk_notifikasi_user`
        FOREIGN KEY (`id_user`)
        REFERENCES `tb_user` (`id`)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    ADD CONSTRAINT `chk_notifikasi_is_read`
        CHECK (`is_read` IN (0, 1));