-- Pengamanan tabel wishlist
-- Tanggal: 2026-09-10

ALTER TABLE `tb_wishlist`
    ADD UNIQUE KEY `uk_wishlist_pembeli_produk`
        (`id_pembeli`, `id_produk`),

    ADD KEY `idx_wishlist_produk`
        (`id_produk`),

    ADD CONSTRAINT `fk_wishlist_pembeli`
        FOREIGN KEY (`id_pembeli`)
        REFERENCES `tb_user` (`id`)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    ADD CONSTRAINT `fk_wishlist_produk`
        FOREIGN KEY (`id_produk`)
        REFERENCES `tb_produk` (`id_produk`)
        ON UPDATE CASCADE
        ON DELETE CASCADE;