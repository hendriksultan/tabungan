<?php
$userLevel = strtolower(
    (string) $this->session->userdata('level')
);

$userId = (int) $this->session->userdata('id');
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
            <li class="active">Data Transfer</li>
        </ol>
    </section>

    <section class="content">
        <div class="box box-primary">
            <?php if ($userLevel === 'nasabah'): ?>
                <div class="box-header with-border">
                    <button
                        class="btn btn-warning"
                        data-toggle="modal"
                        data-target="#tambahData">
                        <i class="fa fa-send"></i>
                        Transfer Saldo
                    </button>
                </div>
            <?php endif; ?>

            <div class="box-body">
                <div class="table-responsive">
                    <table
                        class="table table-bordered table-striped table-hover"
                        id="dataTable">
                        <thead>
                            <tr>
                                <th width="40">No.</th>
                                <th>Kode</th>
                                <th>Dari</th>
                                <th>Kepada</th>

                                <?php if (
                                    $userLevel === 'administrator' ||
                                    $userLevel === 'super admin'
                                ): ?>
                                    <th>Nominal</th>
                                <?php else: ?>
                                    <th>Masuk</th>
                                    <th>Keluar</th>
                                <?php endif; ?>

                                <th>Keterangan</th>
                                <th>Status</th>
                                <th>Waktu</th>
                            </tr>
                        </thead>

                        <tbody>
                            <?php $no = 1; ?>

                            <?php foreach (
                                $transfer->result_array() as $row
                            ): ?>
                                <tr>
                                    <td><?= $no++ ?></td>

                                    <td>
                                        <code>
                                            <?= html_escape(
                                                $row['kode_transfer']
                                            ) ?>
                                        </code>
                                    </td>

                                    <td>
                                        <strong>
                                            <?= html_escape(
                                                $row['nama_pengirim']
                                                    ?: 'Tidak ditemukan'
                                            ) ?>
                                        </strong>
                                        <br>
                                        <small class="text-muted">
                                            <i class="fa fa-building"></i>
                                            <?= html_escape(
                                                $row['nama_cabang_asal']
                                                    ?: '-'
                                            ) ?>
                                        </small>
                                    </td>

                                    <td>
                                        <strong>
                                            <?= html_escape(
                                                $row['nama_penerima']
                                                    ?: 'Tidak ditemukan'
                                            ) ?>
                                        </strong>
                                        <br>
                                        <small class="text-muted">
                                            <i class="fa fa-building"></i>
                                            <?= html_escape(
                                                $row['nama_cabang_tujuan']
                                                    ?: '-'
                                            ) ?>
                                        </small>
                                    </td>

                                    <?php if (
                                        $userLevel === 'administrator' ||
                                        $userLevel === 'super admin'
                                    ): ?>
                                        <td>
                                            Rp
                                            <?= number_format(
                                                (float) $row['nominal'],
                                                0,
                                                ',',
                                                '.'
                                            ) ?>
                                        </td>
                                    <?php else: ?>
                                        <?php if (
                                            (int) $row['idPengirim'] ===
                                            $userId
                                        ): ?>
                                            <td></td>
                                            <td class="text-danger">
                                                - Rp
                                                <?= number_format(
                                                    (float) $row['nominal'],
                                                    0,
                                                    ',',
                                                    '.'
                                                ) ?>
                                            </td>
                                        <?php else: ?>
                                            <td class="text-success">
                                                + Rp
                                                <?= number_format(
                                                    (float) $row['nominal'],
                                                    0,
                                                    ',',
                                                    '.'
                                                ) ?>
                                            </td>
                                            <td></td>
                                        <?php endif; ?>
                                    <?php endif; ?>

                                    <td>
                                        <?= html_escape(
                                            $row['keterangan']
                                        ) ?>
                                    </td>

                                    <td>
                                        <?php if (
                                            $row['status_transfer'] ===
                                            'Sukses'
                                        ): ?>
                                            <span class="label label-success">
                                                Sukses
                                            </span>
                                        <?php else: ?>
                                            <span class="label label-danger">
                                                Dibatalkan
                                            </span>
                                        <?php endif; ?>
                                    </td>

                                    <td>
                                        <?= date(
                                            'd-m-Y H:i:s',
                                            strtotime($row['terdaftar'])
                                        ) ?>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </section>
</div>

<!-- Modal transfer -->
<div
    class="modal fade"
    id="tambahData"
    tabindex="-1"
    role="dialog">
    <div class="modal-dialog" role="document">
        <div class="modal-content">
            <form
                action="<?= base_url('admin/transfer/insert') ?>"
                method="post">
                <input
                    type="hidden"
                    name="<?= $this->security->get_csrf_token_name() ?>"
                    value="<?= $this->security->get_csrf_hash() ?>">

                <div class="modal-header">
                    <button
                        type="button"
                        class="close"
                        data-dismiss="modal">
                        <span>&times;</span>
                    </button>

                    <h4 class="modal-title">
                        Transfer Saldo
                    </h4>
                </div>

                <div class="modal-body">
                    <div class="form-group">
                        <label>Nasabah penerima</label>

                        <select
                            name="idPenerima"
                            class="form-control select2"
                            required
                            style="width:100%;">
                            <option value="">
                                -- Pilih Nasabah Penerima --
                            </option>

                            <?php foreach (
                                $nasabah->result_array() as $item
                            ): ?>
                                <option value="<?= (int) $item['id'] ?>">
                                    <?= html_escape(
                                        $item['nama'] .
                                            ' — ' .
                                            $item['nama_cabang']
                                    ) ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>

                    <div class="form-group">
                        <label>Nominal</label>

                        <input
                            type="text"
                            name="nominal"
                            class="form-control"
                            placeholder="Contoh: 100000"
                            inputmode="numeric"
                            required>
                    </div>

                    <div class="form-group">
                        <label>Keterangan</label>

                        <input
                            type="text"
                            name="keterangan"
                            class="form-control"
                            maxlength="255"
                            placeholder="Keterangan transfer"
                            required>
                    </div>

                    <div class="checkbox">
                        <label>
                            <input
                                type="checkbox"
                                name="setuju"
                                value="1"
                                id="setujuCheckbox"
                                required>
                            Saya memahami bahwa transfer yang berhasil
                            tidak dapat dihapus.
                        </label>
                    </div>
                </div>

                <div class="modal-footer">
                    <button
                        type="button"
                        class="btn btn-default"
                        data-dismiss="modal">
                        Batal
                    </button>

                    <button
                        type="submit"
                        class="btn btn-primary"
                        id="saveButton"
                        disabled>
                        <i class="fa fa-send"></i>
                        Transfer
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>