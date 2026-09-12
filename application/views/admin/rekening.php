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
                Super Admin dapat memantau rekening seluruh cabang.
                Perubahan dilakukan oleh Administrator cabang masing-masing.
            </div>
        <?php endif; ?>

        <div class="box">
            <div class="box-header with-border">
                <?php if (!$isSuperAdmin): ?>
                    <button
                        type="button"
                        class="btn btn-primary"
                        data-toggle="modal"
                        data-target="#tambahRekening">
                        <i class="fa fa-plus"></i> Tambah Rekening
                    </button>
                <?php endif; ?>
            </div>

            <div class="box-body">
                <div class="table-responsive">
                    <table
                        class="table table-bordered table-striped table-hover"
                        id="dataTable">
                        <thead>
                            <tr>
                                <th style="width: 45px;">#</th>
                                <th>Cabang</th>
                                <th>Jenis</th>
                                <th>Bank / Layanan</th>
                                <th>Nomor</th>
                                <th>Atas Nama</th>
                                <th>Status</th>
                                <th>Urutan</th>
                                <?php if (!$isSuperAdmin): ?>
                                    <th style="width: 150px;">Aksi</th>
                                <?php endif; ?>
                            </tr>
                        </thead>
                        <tbody>
                            <?php $no = 1; ?>
                            <?php foreach ($rekening->result_array() as $row): ?>
                                <tr>
                                    <td><?= $no++ ?></td>
                                    <td>
                                        <?= html_escape($row['nama_cabang']) ?>
                                        <br>
                                        <small class="text-muted">
                                            <?= html_escape($row['kode_cabang']) ?>
                                        </small>
                                    </td>
                                    <td><?= html_escape($row['jenis']) ?></td>
                                    <td><?= html_escape($row['nama_bank']) ?></td>
                                    <td><strong><?= html_escape($row['nomor_rekening']) ?></strong></td>
                                    <td><?= html_escape($row['atas_nama']) ?></td>
                                    <td>
                                        <span class="label <?= $row['status'] === 'Aktif' ? 'label-success' : 'label-default' ?>">
                                            <?= html_escape($row['status']) ?>
                                        </span>
                                    </td>
                                    <td><?= (int) $row['urutan'] ?></td>

                                    <?php if (!$isSuperAdmin): ?>
                                        <td>
                                            <button
                                                type="button"
                                                class="btn btn-warning btn-xs"
                                                data-toggle="modal"
                                                data-target="#editRekening<?= (int) $row['id'] ?>">
                                                <i class="fa fa-pencil"></i> Edit
                                            </button>

                                            <form
                                                action="<?= base_url('admin/rekening/toggle_status/' . (int) $row['id']) ?>"
                                                method="POST"
                                                style="display: inline-block;">
                                                <input
                                                    type="hidden"
                                                    name="<?= $this->security->get_csrf_token_name() ?>"
                                                    value="<?= $this->security->get_csrf_hash() ?>">
                                                <button
                                                    type="submit"
                                                    class="btn btn-xs <?= $row['status'] === 'Aktif' ? 'btn-danger' : 'btn-success' ?>"
                                                    onclick="return confirm('Yakin ingin mengubah status rekening ini?')">
                                                    <i class="fa <?= $row['status'] === 'Aktif' ? 'fa-ban' : 'fa-check' ?>"></i>
                                                    <?= $row['status'] === 'Aktif' ? 'Nonaktifkan' : 'Aktifkan' ?>
                                                </button>
                                            </form>
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

<?php if (!$isSuperAdmin): ?>
    <div class="modal fade" id="tambahRekening" tabindex="-1" role="dialog">
        <div class="modal-dialog" role="document">
            <div class="modal-content">
                <div class="modal-header">
                    <button type="button" class="close" data-dismiss="modal">&times;</button>
                    <h4 class="modal-title">Tambah Rekening Penampungan</h4>
                </div>
                <form action="<?= base_url('admin/rekening/insert') ?>" method="POST">
                    <input
                        type="hidden"
                        name="<?= $this->security->get_csrf_token_name() ?>"
                        value="<?= $this->security->get_csrf_hash() ?>">
                    <div class="modal-body">
                        <?php $this->load->view('admin/rekening_form', ['rekeningForm' => null]); ?>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-default" data-dismiss="modal">Batal</button>
                        <button type="submit" class="btn btn-primary">
                            <i class="fa fa-save"></i> Simpan
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <?php foreach ($rekening->result_array() as $row): ?>
        <div class="modal fade" id="editRekening<?= (int) $row['id'] ?>" tabindex="-1" role="dialog">
            <div class="modal-dialog" role="document">
                <div class="modal-content">
                    <div class="modal-header">
                        <button type="button" class="close" data-dismiss="modal">&times;</button>
                        <h4 class="modal-title">Edit Rekening Penampungan</h4>
                    </div>
                    <form action="<?= base_url('admin/rekening/update/' . (int) $row['id']) ?>" method="POST">
                        <input
                            type="hidden"
                            name="<?= $this->security->get_csrf_token_name() ?>"
                            value="<?= $this->security->get_csrf_hash() ?>">
                        <div class="modal-body">
                            <?php $this->load->view('admin/rekening_form', ['rekeningForm' => $row]); ?>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-default" data-dismiss="modal">Batal</button>
                            <button type="submit" class="btn btn-primary">
                                <i class="fa fa-save"></i> Simpan Perubahan
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    <?php endforeach; ?>
<?php endif; ?>
