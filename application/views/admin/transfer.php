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

                                <?php if (
                                    $userLevel === 'administrator' ||
                                    $userLevel === 'super admin'
                                ): ?>
                                    <th width="110">Aksi</th>
                                <?php endif; ?>
                            </tr>
                        </thead>

                        <tbody>
                            <?php $no = 1; ?>

                            <?php foreach (
                                $transfer->result_array() as $row
                            ): ?>
                                <?php
                                $canCancelTransfer = (
                                    $row['status_transfer'] === 'Sukses' &&
                                    empty($row['dibatalkan_pada']) &&
                                    (
                                        $userLevel === 'super admin' ||
                                        (
                                            $userLevel === 'administrator' &&
                                            (int) $row['cabang_asal_id'] ===
                                            (int) $this->session->userdata('cabang_id')
                                        )
                                    )
                                );
                                ?>
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

                                            <?php if (!empty(
                                                $row['alasan_pembatalan']
                                            )): ?>
                                                <br>
                                                <small class="text-muted">
                                                    <?= html_escape(
                                                        $row['alasan_pembatalan']
                                                    ) ?>
                                                </small>
                                            <?php endif; ?>

                                            <br>
                                            <small class="text-muted">
                                                <i class="fa fa-user"></i>
                                                Oleh:
                                                <?php if (!empty(
                                                    $row['nama_pembatal']
                                                )): ?>
                                                    <strong>
                                                        <?= html_escape(
                                                            $row['nama_pembatal']
                                                        ) ?>
                                                    </strong>

                                                    <?php if (!empty(
                                                        $row['level_pembatal']
                                                    )): ?>
                                                        (<?= html_escape(
                                                            $row['level_pembatal']
                                                        ) ?>)
                                                    <?php endif; ?>

                                                    <?php if (!empty(
                                                        $row['kode_cabang_pembatal']
                                                    )): ?>
                                                        &mdash;
                                                        <?= html_escape(
                                                            $row['kode_cabang_pembatal']
                                                        ) ?>

                                                        <?php if (!empty(
                                                            $row['nama_cabang_pembatal']
                                                        )): ?>
                                                            &middot;
                                                            <?= html_escape(
                                                                $row['nama_cabang_pembatal']
                                                            ) ?>
                                                        <?php endif; ?>
                                                    <?php endif; ?>
                                                <?php else: ?>
                                                    <em>Tidak tercatat</em>
                                                <?php endif; ?>
                                            </small>

                                            <?php if (!empty(
                                                $row['dibatalkan_pada']
                                            )): ?>
                                                <br>
                                                <small class="text-muted">
                                                    <i class="fa fa-clock-o"></i>
                                                    <?= date(
                                                        'd-m-Y H:i:s',
                                                        strtotime(
                                                            $row['dibatalkan_pada']
                                                        )
                                                    ) ?>
                                                </small>
                                            <?php endif; ?>
                                        <?php endif; ?>
                                    </td>

                                    <td>
                                        <?= date(
                                            'd-m-Y H:i:s',
                                            strtotime($row['terdaftar'])
                                        ) ?>
                                    </td>

                                    <?php if (
                                        $userLevel === 'administrator' ||
                                        $userLevel === 'super admin'
                                    ): ?>
                                        <td>
                                            <?php if ($canCancelTransfer): ?>
                                                <button
                                                    type="button"
                                                    class="btn btn-danger btn-xs"
                                                    data-toggle="modal"
                                                    data-target="#batalkanTransfer<?= (int) $row['id'] ?>">
                                                    <i class="fa fa-undo"></i>
                                                    Batalkan
                                                </button>
                                            <?php else: ?>
                                                <span class="text-muted">-</span>
                                            <?php endif; ?>
                                        </td>
                                    <?php endif; ?>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </section>
</div>

<?php if (
    $userLevel === 'administrator' ||
    $userLevel === 'super admin'
): ?>
    <?php foreach ($transfer->result_array() as $row): ?>
        <?php
        $canCancelTransfer = (
            $row['status_transfer'] === 'Sukses' &&
            empty($row['dibatalkan_pada']) &&
            (
                $userLevel === 'super admin' ||
                (
                    $userLevel === 'administrator' &&
                    (int) $row['cabang_asal_id'] ===
                    (int) $this->session->userdata('cabang_id')
                )
            )
        );

        if (!$canCancelTransfer) {
            continue;
        }
        ?>

        <div
            class="modal fade"
            id="batalkanTransfer<?= (int) $row['id'] ?>"
            tabindex="-1"
            role="dialog">
            <div class="modal-dialog" role="document">
                <div class="modal-content">
                    <form
                        action="<?= base_url(
                                    'admin/transfer/batalkan/' .
                                        (int) $row['id']
                                ) ?>"
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
                                Batalkan Transfer
                                <?= html_escape($row['kode_transfer']) ?>
                            </h4>
                        </div>

                        <div class="modal-body">
                            <div class="alert alert-warning">
                                Saldo Rp
                                <?= number_format(
                                    (float) $row['nominal'],
                                    0,
                                    ',',
                                    '.'
                                ) ?>
                                akan dikembalikan kepada pengirim dan
                                dikurangi dari penerima.
                            </div>

                            <div class="form-group">
                                <label>Alasan pembatalan</label>
                                <textarea
                                    name="alasan_pembatalan"
                                    class="form-control"
                                    rows="4"
                                    minlength="10"
                                    maxlength="500"
                                    required></textarea>
                                <small class="text-muted">
                                    Minimal 10 karakter dan akan disimpan
                                    sebagai catatan audit.
                                </small>
                            </div>
                        </div>

                        <div class="modal-footer">
                            <button
                                type="button"
                                class="btn btn-default"
                                data-dismiss="modal">
                                Kembali
                            </button>

                            <button
                                type="submit"
                                class="btn btn-danger">
                                <i class="fa fa-undo"></i>
                                Konfirmasi Pembatalan
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    <?php endforeach; ?>
<?php endif; ?>

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
