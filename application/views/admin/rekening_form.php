<?php
$rekeningForm = isset($rekeningForm) && is_array($rekeningForm)
    ? $rekeningForm
    : [];
$jenis = $rekeningForm['jenis'] ?? 'Bank';
?>

<div class="form-group">
    <label>Jenis</label>
    <select name="jenis" class="form-control" required>
        <?php foreach (['Bank', 'E-Wallet', 'Lainnya'] as $pilihan): ?>
            <option
                value="<?= html_escape($pilihan) ?>"
                <?= $jenis === $pilihan ? 'selected' : '' ?>>
                <?= html_escape($pilihan) ?>
            </option>
        <?php endforeach; ?>
    </select>
</div>

<div class="form-group">
    <label>Nama Bank / Layanan</label>
    <input
        type="text"
        name="nama_bank"
        class="form-control"
        maxlength="100"
        value="<?= html_escape($rekeningForm['nama_bank'] ?? '') ?>"
        placeholder="Contoh: BCA atau DANA"
        required>
</div>

<div class="form-group">
    <label>Nomor Rekening / Akun</label>
    <input
        type="text"
        name="nomor_rekening"
        class="form-control"
        maxlength="50"
        value="<?= html_escape($rekeningForm['nomor_rekening'] ?? '') ?>"
        placeholder="Masukkan nomor rekening"
        required>
</div>

<div class="form-group">
    <label>Atas Nama</label>
    <input
        type="text"
        name="atas_nama"
        class="form-control"
        maxlength="150"
        value="<?= html_escape($rekeningForm['atas_nama'] ?? '') ?>"
        placeholder="Contoh: a.n. Nama Pemilik"
        required>
</div>

<div class="form-group">
    <label>Urutan Tampil</label>
    <input
        type="number"
        name="urutan"
        class="form-control"
        min="0"
        max="9999"
        value="<?= (int) ($rekeningForm['urutan'] ?? 0) ?>"
        required>
    <small class="text-muted">Angka lebih kecil tampil lebih dahulu.</small>
</div>
