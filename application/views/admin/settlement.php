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
                                    <select name="rekening_asal_id" class="form-control" required>
                                        <option value="">-- Pilih Rekening Cabang Anda --</option>
                                        <?php foreach ($rekeningAsal->result_array() as $rekening): ?>
                                            <option value="<?= (int) $rekening['id'] ?>">
                                                <?= html_escape(
                                                    $rekening['nama_bank'] . ' • ' .
                                                    $rekening['nomor_rekening'] . ' • ' .
                                                    $rekening['atas_nama']
                                                ) ?>
                                            </option>
                                        <?php endforeach; ?>
                                    </select>
                                </div>

                                <div class="form-group">
                                    <label>Rekening Tujuan</label>
                                    <select
                                        name="rekening_tujuan_id"
                                        id="rekeningTujuanSettlement"
                                        class="form-control"
                                        required>
                                        <option value="">-- Pilih Rekening Cabang Tujuan --</option>
                                        <?php foreach ($rekeningTujuan->result_array() as $rekening): ?>
                                            <?php if ((int) $rekening['cabang_id'] === (int) $cabangId) continue; ?>
                                            <option
                                                value="<?= (int) $rekening['id'] ?>"
                                                data-cabang="<?= (int) $rekening['cabang_id'] ?>">
                                                <?= html_escape(
                                                    $rekening['nama_cabang'] . ' • ' .
                                                    $rekening['nama_bank'] . ' • ' .
                                                    $rekening['nomor_rekening'] . ' • ' .
                                                    $rekening['atas_nama']
                                                ) ?>
                                            </option>
                                        <?php endforeach; ?>
                                    </select>
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
<script>
document.addEventListener('DOMContentLoaded', function () {
    var checkboxes = Array.prototype.slice.call(
        document.querySelectorAll('.pilih-kewajiban')
    );
    var tombol = document.getElementById('btnBukaKirim');
    var jumlah = document.getElementById('jumlahTerpilih');
    var total = document.getElementById('totalTerpilih');
    var totalModal = document.getElementById('totalTerpilihModal');
    var rekeningTujuan = document.getElementById('rekeningTujuanSettlement');

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

        Array.prototype.slice.call(rekeningTujuan.options).forEach(function (option) {
            if (!option.value) {
                option.hidden = false;
                return;
            }
            option.hidden = !cabangTujuan ||
                option.getAttribute('data-cabang') !== cabangTujuan;
        });

        if (
            rekeningTujuan.selectedOptions.length &&
            rekeningTujuan.selectedOptions[0].hidden
        ) {
            rekeningTujuan.value = '';
        }

        jumlah.textContent = terpilih.length;
        total.textContent = rupiah(nominal);
        totalModal.textContent = rupiah(nominal);
        tombol.disabled = terpilih.length === 0;
    }

    checkboxes.forEach(function (item) {
        item.addEventListener('change', perbaruiPilihan);
    });
    perbaruiPilihan();
});
</script>
<?php endif; ?>
