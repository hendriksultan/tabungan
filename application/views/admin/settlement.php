<?php
$statusClass = [
    'MenungguTransfer'   => 'label-default',
    'MenungguVerifikasi'=> 'label-warning',
    'Selesai'            => 'label-success',
    'Ditolak'            => 'label-danger',
    'Sengketa'           => 'label-danger',
    'Dibatalkan'         => 'label-default'
];

function formatRupiahSettlement($nominal)
{
    return 'Rp ' . number_format((int) $nominal, 0, ',', '.');
}
?>

<div class="content-wrapper">
    <section class="content-header">
        <h1>
            <?= html_escape($title) ?>
            <small><?= html_escape($subtitle) ?></small>
        </h1>
        <ol class="breadcrumb">
            <li>
                <a href="<?= base_url('admin/dashboard') ?>">
                    <i class="fa fa-dashboard"></i> Dashboard
                </a>
            </li>
            <li class="active"><?= html_escape($title) ?></li>
        </ol>
    </section>

    <section class="content">
        <?php if ($isSuperAdmin): ?>
            <div class="alert alert-info">
                <i class="fa fa-eye"></i>
                Super Admin memantau kewajiban dan settlement seluruh cabang.
                Pengiriman dan verifikasi dilakukan Administrator cabang terkait.
            </div>
        <?php else: ?>
            <div class="alert alert-info">
                <i class="fa fa-info-circle"></i>
                Kewajiban dari cabang Anda dapat digabung jika seluruhnya menuju
                cabang yang sama. Admin cabang tujuan akan memverifikasi dana masuk.
            </div>
        <?php endif; ?>

        <div class="row">
            <div class="col-md-4 col-sm-6">
                <div class="info-box">
                    <span class="info-box-icon bg-yellow">
                        <i class="fa fa-exchange"></i>
                    </span>
                    <div class="info-box-content">
                        <span class="info-box-text">Kewajiban Terbuka</span>
                        <span class="info-box-number">
                            <?= (int) $kewajibanTerbuka->num_rows() ?>
                        </span>
                    </div>
                </div>
            </div>

            <div class="col-md-4 col-sm-6">
                <div class="info-box">
                    <span class="info-box-icon bg-aqua">
                        <i class="fa fa-clock-o"></i>
                    </span>
                    <div class="info-box-content">
                        <span class="info-box-text">Menunggu Verifikasi</span>
                        <span class="info-box-number">
                            <?php
                            $jumlahMenunggu = 0;
                            foreach ($settlement->result_array() as $item) {
                                if ($item['status'] === 'MenungguVerifikasi') {
                                    $jumlahMenunggu++;
                                }
                            }
                            echo $jumlahMenunggu;
                            ?>
                        </span>
                    </div>
                </div>
            </div>

            <div class="col-md-4 col-sm-6">
                <div class="info-box">
                    <span class="info-box-icon bg-green">
                        <i class="fa fa-check-circle"></i>
                    </span>
                    <div class="info-box-content">
                        <span class="info-box-text">Settlement Selesai</span>
                        <span class="info-box-number">
                            <?php
                            $jumlahSelesai = 0;
                            foreach ($settlement->result_array() as $item) {
                                if ($item['status'] === 'Selesai') {
                                    $jumlahSelesai++;
                                }
                            }
                            echo $jumlahSelesai;
                            ?>
                        </span>
                    </div>
                </div>
            </div>
        </div>

        <div class="box box-warning">
            <div class="box-header with-border">
                <h3 class="box-title">
                    <i class="fa fa-list"></i> Kewajiban Belum Dibayar
                </h3>
            </div>

            <?php if (!$isSuperAdmin): ?>
                <form
                    id="formKirimSettlement"
                    action="<?= base_url('admin/settlement/kirim') ?>"
                    method="POST"
                    enctype="multipart/form-data">
                    <input
                        type="hidden"
                        name="<?= $this->security->get_csrf_token_name() ?>"
                        value="<?= $this->security->get_csrf_hash() ?>">
            <?php endif; ?>

            <div class="box-body">
                <?php if (!$isSuperAdmin): ?>
                    <div class="form-group">
                        <button
                            type="button"
                            id="btnBukaKirim"
                            class="btn btn-primary"
                            data-toggle="modal"
                            data-target="#modalKirimSettlement"
                            disabled>
                            <i class="fa fa-upload"></i>
                            Bayar Kewajiban Terpilih
                        </button>
                        <span class="text-muted" style="margin-left: 10px;">
                            <span id="jumlahTerpilih">0</span> kewajiban •
                            <strong id="totalTerpilih">Rp 0</strong>
                        </span>
                    </div>
                <?php endif; ?>

                <div class="table-responsive">
                    <table class="table table-bordered table-striped table-hover dataTable">
                        <thead>
                            <tr>
                                <?php if (!$isSuperAdmin): ?>
                                    <th style="width: 35px;"></th>
                                <?php endif; ?>
                                <th>Kode</th>
                                <th>Sumber</th>
                                <th>Cabang Asal</th>
                                <th>Cabang Tujuan</th>
                                <th>Nominal</th>
                                <th>Dibuat</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($kewajibanTerbuka->result_array() as $row): ?>
                                <tr>
                                    <?php if (!$isSuperAdmin): ?>
                                        <td class="text-center">
                                            <input
                                                type="checkbox"
                                                class="pilih-kewajiban"
                                                name="kewajiban_ids[]"
                                                value="<?= (int) $row['id_kewajiban'] ?>"
                                                data-cabang-tujuan="<?= (int) $row['cabang_tujuan_id'] ?>"
                                                data-nominal="<?= (int) $row['nominal'] ?>">
                                        </td>
                                    <?php endif; ?>
                                    <td><strong><?= html_escape($row['kode_kewajiban']) ?></strong></td>
                                    <td>
                                        <?= html_escape($row['jenis_sumber']) ?>
                                        <br>
                                        <small class="text-muted">
                                            Referensi #<?= (int) $row['referensi_id'] ?>
                                        </small>
                                    </td>
                                    <td>
                                        <?= html_escape($row['nama_cabang_asal']) ?>
                                        <br>
                                        <small class="text-muted"><?= html_escape($row['kode_cabang_asal']) ?></small>
                                    </td>
                                    <td>
                                        <?= html_escape($row['nama_cabang_tujuan']) ?>
                                        <br>
                                        <small class="text-muted"><?= html_escape($row['kode_cabang_tujuan']) ?></small>
                                    </td>
                                    <td><strong><?= formatRupiahSettlement($row['nominal']) ?></strong></td>
                                    <td><?= html_escape(date('d-m-Y H:i', strtotime($row['dibuat_pada']))) ?></td>
                                    <td><span class="label label-warning">Terbuka</span></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>

                <?php if ($kewajibanTerbuka->num_rows() === 0): ?>
                    <p class="text-center text-muted" style="margin: 18px 0;">
                        Tidak ada kewajiban terbuka.
                    </p>
                <?php endif; ?>
            </div>

            <?php if (!$isSuperAdmin): ?>
                <div class="modal fade" id="modalKirimSettlement" tabindex="-1" role="dialog">
                    <div class="modal-dialog" role="document">
                        <div class="modal-content">
                            <div class="modal-header">
                                <button type="button" class="close" data-dismiss="modal">&times;</button>
                                <h4 class="modal-title">Kirim Bukti Settlement</h4>
                            </div>
                            <div class="modal-body">
                                <div class="alert alert-warning">
                                    Pastikan nominal dan rekening tujuan sesuai sebelum mengirim.
                                </div>

                                <div class="form-group">
                                    <label>Rekening Asal</label>
                                    <div class="settlement-account-list">
                                        <?php foreach ($rekeningAsal->result_array() as $rekening): ?>
                                            <label class="settlement-account-card">
                                                <input
                                                    type="radio"
                                                    name="rekening_asal_id"
                                                    value="<?= (int) $rekening['id'] ?>"
                                                    required>
                                                <span class="settlement-account-check">
                                                    <i class="fa fa-check"></i>
                                                </span>
                                                <span class="settlement-account-body">
                                                    <span class="label label-primary">
                                                        <?= html_escape($rekening['jenis']) ?>
                                                    </span>
                                                    <strong class="settlement-account-bank">
                                                        <?= html_escape($rekening['nama_bank']) ?>
                                                    </strong>
                                                    <span class="settlement-account-line">
                                                        <i class="fa fa-credit-card"></i>
                                                        <?= html_escape($rekening['nomor_rekening']) ?>
                                                    </span>
                                                    <span class="settlement-account-line text-muted">
                                                        <i class="fa fa-user"></i>
                                                        <?= html_escape($rekening['atas_nama']) ?>
                                                    </span>
                                                </span>
                                            </label>
                                        <?php endforeach; ?>

                                        <?php if ($rekeningAsal->num_rows() === 0): ?>
                                            <div class="alert alert-danger" style="margin-bottom:0;">
                                                Cabang Anda belum memiliki rekening aktif.
                                            </div>
                                        <?php endif; ?>
                                    </div>
                                </div>

                                <div class="form-group">
                                    <label>Rekening Tujuan</label>
                                    <div
                                        id="pesanPilihKewajiban"
                                        class="alert alert-info"
                                        style="margin-bottom:10px;">
                                        Pilih kewajiban terlebih dahulu agar rekening tujuan ditampilkan.
                                    </div>
                                    <div class="settlement-account-list" id="rekeningTujuanSettlement">
                                        <?php foreach ($rekeningTujuan->result_array() as $rekening): ?>
                                            <?php if ((int) $rekening['cabang_id'] === (int) $cabangId) continue; ?>
                                            <label
                                                class="settlement-account-card rekening-tujuan-card"
                                                data-cabang="<?= (int) $rekening['cabang_id'] ?>"
                                                style="display:none;">
                                                <input
                                                    type="radio"
                                                    name="rekening_tujuan_id"
                                                    value="<?= (int) $rekening['id'] ?>">
                                                <span class="settlement-account-check">
                                                    <i class="fa fa-check"></i>
                                                </span>
                                                <span class="settlement-account-body">
                                                    <span class="settlement-account-branch">
                                                        <i class="fa fa-building"></i>
                                                        <?= html_escape($rekening['nama_cabang']) ?>
                                                        <small>(<?= html_escape($rekening['kode_cabang']) ?>)</small>
                                                    </span>
                                                    <span>
                                                        <span class="label label-success">
                                                            <?= html_escape($rekening['jenis']) ?>
                                                        </span>
                                                        <strong class="settlement-account-bank">
                                                            <?= html_escape($rekening['nama_bank']) ?>
                                                        </strong>
                                                    </span>
                                                    <span class="settlement-account-line">
                                                        <i class="fa fa-credit-card"></i>
                                                        <?= html_escape($rekening['nomor_rekening']) ?>
                                                    </span>
                                                    <span class="settlement-account-line text-muted">
                                                        <i class="fa fa-user"></i>
                                                        <?= html_escape($rekening['atas_nama']) ?>
                                                    </span>
                                                </span>
                                            </label>
                                        <?php endforeach; ?>
                                    </div>
                                    <div
                                        id="rekeningTujuanKosong"
                                        class="alert alert-danger"
                                        style="display:none; margin-bottom:0;">
                                        Cabang tujuan belum memiliki rekening aktif.
                                    </div>
                                    <small class="text-muted">
                                        Hanya rekening milik cabang tujuan yang dapat dipilih.
                                    </small>
                                </div>

                                <div class="form-group">
                                    <label>Referensi Bank</label>
                                    <input
                                        type="text"
                                        name="referensi_bank"
                                        class="form-control"
                                        maxlength="100"
                                        placeholder="Contoh: FT-20260921-001"
                                        required>
                                </div>

                                <div class="form-group">
                                    <label>Bukti Transfer</label>
                                    <input
                                        type="file"
                                        name="bukti_transfer"
                                        class="form-control"
                                        accept=".jpg,.jpeg,.png,.pdf"
                                        required>
                                    <small class="text-muted">
                                        JPG, JPEG, PNG, atau PDF. Maksimal 5 MB.
                                    </small>
                                </div>

                                <div class="form-group">
                                    <label>Catatan <small>(opsional)</small></label>
                                    <textarea
                                        name="catatan"
                                        class="form-control"
                                        maxlength="500"
                                        rows="3"></textarea>
                                </div>

                                <div class="well well-sm">
                                    Total yang akan dikirim:
                                    <strong id="totalTerpilihModal">Rp 0</strong>
                                </div>
                            </div>
                            <div class="modal-footer">
                                <button type="button" class="btn btn-default" data-dismiss="modal">Batal</button>
                                <button
                                    type="submit"
                                    class="btn btn-primary"
                                    onclick="return confirm('Kirim bukti settlement untuk diverifikasi admin tujuan?');">
                                    <i class="fa fa-send"></i> Kirim untuk Verifikasi
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
                </form>
            <?php endif; ?>
        </div>

        <div class="box box-primary">
            <div class="box-header with-border">
                <h3 class="box-title">
                    <i class="fa fa-history"></i> Riwayat Settlement
                </h3>
            </div>
            <div class="box-body">
                <div class="table-responsive">
                    <table class="table table-bordered table-striped table-hover dataTable">
                        <thead>
                            <tr>
                                <th>Kode</th>
                                <th>Arah Dana</th>
                                <th>Kewajiban</th>
                                <th>Nominal</th>
                                <th>Rekening</th>
                                <th>Bukti</th>
                                <th>Status</th>
                                <th>Waktu</th>
                                <th style="min-width: 155px;">Aksi</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($settlement->result_array() as $row): ?>
                                <tr>
                                    <td>
                                        <strong><?= html_escape($row['kode_settlement']) ?></strong>
                                        <br>
                                        <small class="text-muted">
                                            Ref: <?= html_escape($row['referensi_bank'] ?: '-') ?>
                                        </small>
                                    </td>
                                    <td>
                                        <?= html_escape($row['nama_cabang_asal']) ?>
                                        <i class="fa fa-long-arrow-right text-muted"></i>
                                        <?= html_escape($row['nama_cabang_tujuan']) ?>
                                    </td>
                                    <td>
                                        <?= (int) $row['jumlah_kewajiban'] ?> item
                                        <br>
                                        <small class="text-muted">
                                            <?= html_escape($row['daftar_kewajiban'] ?: '-') ?>
                                        </small>
                                    </td>
                                    <td><strong><?= formatRupiahSettlement($row['nominal_total']) ?></strong></td>
                                    <td>
                                        <small>
                                            <strong>Asal:</strong>
                                            <?= html_escape($row['rekening_asal_nama']) ?>
                                            <?= html_escape($row['rekening_asal_nomor']) ?>
                                            <br>
                                            <strong>Tujuan:</strong>
                                            <?= html_escape($row['rekening_tujuan_nama']) ?>
                                            <?= html_escape($row['rekening_tujuan_nomor']) ?>
                                        </small>
                                    </td>
                                    <td>
                                        <?php if (!empty($row['bukti_transfer'])): ?>
                                            <a
                                                href="<?= html_escape(base_url($row['bukti_transfer'])) ?>"
                                                target="_blank"
                                                rel="noopener"
                                                class="btn btn-info btn-xs">
                                                <i class="fa fa-file-image-o"></i> Lihat
                                            </a>
                                        <?php else: ?>
                                            <span class="text-muted">-</span>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <span class="label <?= isset($statusClass[$row['status']]) ? $statusClass[$row['status']] : 'label-default' ?>">
                                            <?= html_escape($row['status']) ?>
                                        </span>
                                        <?php if ($row['status'] === 'Ditolak'): ?>
                                            <br>
                                            <small class="text-danger">
                                                <?= html_escape($row['alasan_penolakan']) ?>
                                            </small>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <small>
                                            Dikirim:<br>
                                            <?= html_escape($row['dikirim_pada'] ?: '-') ?>
                                            <?php if (!empty($row['diverifikasi_pada'])): ?>
                                                <br>Diverifikasi:<br>
                                                <?= html_escape($row['diverifikasi_pada']) ?>
                                            <?php endif; ?>
                                        </small>
                                    </td>
                                    <td>
                                        <?php if (
                                            !$isSuperAdmin &&
                                            (int) $row['cabang_tujuan_id'] === (int) $cabangId &&
                                            $row['status'] === 'MenungguVerifikasi'
                                        ): ?>
                                            <form
                                                action="<?= base_url('admin/settlement/verifikasi/' . (int) $row['id_settlement']) ?>"
                                                method="POST"
                                                style="display:inline-block;"
                                                onsubmit="return confirm('Dana sudah benar-benar masuk ke rekening cabang Anda?');">
                                                <input
                                                    type="hidden"
                                                    name="<?= $this->security->get_csrf_token_name() ?>"
                                                    value="<?= $this->security->get_csrf_hash() ?>">
                                                <button type="submit" class="btn btn-success btn-xs">
                                                    <i class="fa fa-check"></i> Verifikasi
                                                </button>
                                            </form>
                                            <button
                                                type="button"
                                                class="btn btn-danger btn-xs"
                                                data-toggle="modal"
                                                data-target="#modalTolak<?= (int) $row['id_settlement'] ?>">
                                                <i class="fa fa-times"></i> Tolak
                                            </button>
                                        <?php elseif (
                                            !$isSuperAdmin &&
                                            (int) $row['cabang_asal_id'] === (int) $cabangId &&
                                            $row['status'] === 'Ditolak'
                                        ): ?>
                                            <button
                                                type="button"
                                                class="btn btn-warning btn-xs"
                                                data-toggle="modal"
                                                data-target="#modalKirimUlang<?= (int) $row['id_settlement'] ?>">
                                                <i class="fa fa-repeat"></i> Kirim Ulang
                                            </button>
                                        <?php else: ?>
                                            <span class="text-muted">-</span>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>

                <?php if ($settlement->num_rows() === 0): ?>
                    <p class="text-center text-muted" style="margin: 18px 0;">
                        Belum ada riwayat settlement.
                    </p>
                <?php endif; ?>
            </div>
        </div>
    </section>
</div>

<?php if (!$isSuperAdmin): ?>
    <?php foreach ($settlement->result_array() as $row): ?>
        <?php if (
            (int) $row['cabang_tujuan_id'] === (int) $cabangId &&
            $row['status'] === 'MenungguVerifikasi'
        ): ?>
            <div class="modal fade" id="modalTolak<?= (int) $row['id_settlement'] ?>" tabindex="-1" role="dialog">
                <div class="modal-dialog" role="document">
                    <div class="modal-content">
                        <form
                            action="<?= base_url('admin/settlement/tolak/' . (int) $row['id_settlement']) ?>"
                            method="POST">
                            <input
                                type="hidden"
                                name="<?= $this->security->get_csrf_token_name() ?>"
                                value="<?= $this->security->get_csrf_hash() ?>">
                            <div class="modal-header">
                                <button type="button" class="close" data-dismiss="modal">&times;</button>
                                <h4 class="modal-title">Tolak Settlement</h4>
                            </div>
                            <div class="modal-body">
                                <p>
                                    Settlement <strong><?= html_escape($row['kode_settlement']) ?></strong>
                                    sebesar <strong><?= formatRupiahSettlement($row['nominal_total']) ?></strong>.
                                </p>
                                <div class="form-group">
                                    <label>Alasan Penolakan</label>
                                    <textarea
                                        name="alasan_penolakan"
                                        class="form-control"
                                        rows="4"
                                        maxlength="500"
                                        required></textarea>
                                </div>
                            </div>
                            <div class="modal-footer">
                                <button type="button" class="btn btn-default" data-dismiss="modal">Batal</button>
                                <button type="submit" class="btn btn-danger">
                                    <i class="fa fa-times"></i> Tolak Settlement
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        <?php endif; ?>

        <?php if (
            (int) $row['cabang_asal_id'] === (int) $cabangId &&
            $row['status'] === 'Ditolak'
        ): ?>
            <div class="modal fade" id="modalKirimUlang<?= (int) $row['id_settlement'] ?>" tabindex="-1" role="dialog">
                <div class="modal-dialog" role="document">
                    <div class="modal-content">
                        <form
                            action="<?= base_url('admin/settlement/kirim_ulang/' . (int) $row['id_settlement']) ?>"
                            method="POST"
                            enctype="multipart/form-data">
                            <input
                                type="hidden"
                                name="<?= $this->security->get_csrf_token_name() ?>"
                                value="<?= $this->security->get_csrf_hash() ?>">
                            <div class="modal-header">
                                <button type="button" class="close" data-dismiss="modal">&times;</button>
                                <h4 class="modal-title">Kirim Ulang Settlement</h4>
                            </div>
                            <div class="modal-body">
                                <div class="alert alert-danger">
                                    <strong>Alasan ditolak:</strong><br>
                                    <?= html_escape($row['alasan_penolakan']) ?>
                                </div>
                                <div class="form-group">
                                    <label>Referensi Bank Baru</label>
                                    <input
                                        type="text"
                                        name="referensi_bank"
                                        class="form-control"
                                        maxlength="100"
                                        required>
                                </div>
                                <div class="form-group">
                                    <label>Bukti Transfer Pengganti</label>
                                    <input
                                        type="file"
                                        name="bukti_transfer"
                                        class="form-control"
                                        accept=".jpg,.jpeg,.png,.pdf"
                                        required>
                                </div>
                                <div class="form-group">
                                    <label>Catatan <small>(opsional)</small></label>
                                    <textarea
                                        name="catatan"
                                        class="form-control"
                                        maxlength="500"
                                        rows="3"></textarea>
                                </div>
                            </div>
                            <div class="modal-footer">
                                <button type="button" class="btn btn-default" data-dismiss="modal">Batal</button>
                                <button type="submit" class="btn btn-warning">
                                    <i class="fa fa-repeat"></i> Kirim Ulang
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        <?php endif; ?>
    <?php endforeach; ?>
<?php endif; ?>

<?php if (!$isSuperAdmin): ?>
<style>
.settlement-account-list {
    display: grid;
    gap: 10px;
}

.settlement-account-card {
    position: relative;
    display: flex;
    align-items: flex-start;
    width: 100%;
    margin: 0;
    padding: 13px 46px 13px 14px;
    border: 1px solid #d2d6de;
    border-radius: 7px;
    background: #ffffff;
    cursor: pointer;
    font-weight: 400;
    transition: border-color .2s, box-shadow .2s, background .2s;
}

.settlement-account-card:hover {
    border-color: #3c8dbc;
    background: #f7fbfe;
}

.settlement-account-card.selected {
    border-color: #00a65a;
    box-shadow: 0 0 0 2px rgba(0, 166, 90, .14);
    background: #f5fff9;
}

.settlement-account-card input[type="radio"] {
    position: absolute;
    opacity: 0;
    pointer-events: none;
}

.settlement-account-check {
    position: absolute;
    top: 50%;
    right: 14px;
    display: flex;
    align-items: center;
    justify-content: center;
    width: 24px;
    height: 24px;
    border: 2px solid #c8ced3;
    border-radius: 50%;
    color: transparent;
    transform: translateY(-50%);
}

.settlement-account-card.selected .settlement-account-check {
    border-color: #00a65a;
    background: #00a65a;
    color: #ffffff;
}

.settlement-account-body,
.settlement-account-line,
.settlement-account-branch {
    display: block;
}

.settlement-account-bank {
    display: inline-block;
    margin-left: 6px;
    color: #222d32;
}

.settlement-account-line {
    margin-top: 6px;
    word-break: break-word;
}

.settlement-account-line i,
.settlement-account-branch i {
    width: 18px;
    color: #7a8690;
}

.settlement-account-branch {
    margin-bottom: 9px;
    padding-bottom: 8px;
    border-bottom: 1px solid #edf0f2;
    color: #3c8dbc;
    font-weight: 600;
}
</style>
<script>
document.addEventListener('DOMContentLoaded', function () {
    var checkboxes = Array.prototype.slice.call(
        document.querySelectorAll('.pilih-kewajiban')
    );
    var tombol = document.getElementById('btnBukaKirim');
    var jumlah = document.getElementById('jumlahTerpilih');
    var total = document.getElementById('totalTerpilih');
    var totalModal = document.getElementById('totalTerpilihModal');
    var kartuTujuan = Array.prototype.slice.call(
        document.querySelectorAll('.rekening-tujuan-card')
    );
    var semuaKartuRekening = Array.prototype.slice.call(
        document.querySelectorAll('.settlement-account-card')
    );
    var pesanPilih = document.getElementById('pesanPilihKewajiban');
    var rekeningKosong = document.getElementById('rekeningTujuanKosong');

    function rupiah(nilai) {
        return 'Rp ' + Number(nilai).toLocaleString('id-ID');
    }

    function perbaruiPilihan() {
        var terpilih = checkboxes.filter(function (item) {
            return item.checked;
        });
        var cabangTujuan = terpilih.length
            ? terpilih[0].getAttribute('data-cabang-tujuan')
            : '';
        var nominal = terpilih.reduce(function (hasil, item) {
            return hasil + Number(item.getAttribute('data-nominal') || 0);
        }, 0);

        checkboxes.forEach(function (item) {
            var berbeda = cabangTujuan &&
                item.getAttribute('data-cabang-tujuan') !== cabangTujuan;
            item.disabled = !item.checked && !!berbeda;
        });

        var jumlahRekeningTujuan = 0;
        kartuTujuan.forEach(function (kartu) {
            var sesuai = !!cabangTujuan &&
                kartu.getAttribute('data-cabang') === cabangTujuan;
            var radio = kartu.querySelector('input[type="radio"]');
            kartu.style.display = sesuai ? 'flex' : 'none';
            if (radio) {
                radio.required = sesuai;
            }
            if (sesuai) {
                jumlahRekeningTujuan++;
            } else if (radio) {
                radio.checked = false;
                kartu.classList.remove('selected');
            }
        });

        pesanPilih.style.display = cabangTujuan ? 'none' : 'block';
        rekeningKosong.style.display =
            cabangTujuan && jumlahRekeningTujuan === 0 ? 'block' : 'none';

        jumlah.textContent = terpilih.length;
        total.textContent = rupiah(nominal);
        totalModal.textContent = rupiah(nominal);
        tombol.disabled = terpilih.length === 0;
    }

    checkboxes.forEach(function (item) {
        item.addEventListener('change', perbaruiPilihan);
    });

    semuaKartuRekening.forEach(function (kartu) {
        var radio = kartu.querySelector('input[type="radio"]');
        if (!radio) return;
        radio.addEventListener('change', function () {
            var nama = radio.getAttribute('name');
            semuaKartuRekening.forEach(function (kartuLain) {
                var radioLain = kartuLain.querySelector('input[type="radio"]');
                if (radioLain && radioLain.getAttribute('name') === nama) {
                    kartuLain.classList.toggle('selected', radioLain.checked);
                }
            });
        });
    });
    perbaruiPilihan();
});
</script>
<?php endif; ?>
