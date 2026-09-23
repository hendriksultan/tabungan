<div class="content-wrapper">
    <section class="content-header">
        <h1>
            <?= html_escape($title) ?>
            <small><?= html_escape($subtitle) ?></small>
        </h1>
        <ol class="breadcrumb">
            <li><a href="<?= base_url('admin/dashboard') ?>"><i class="fa fa-dashboard"></i> Dashboard</a></li>
            <li class="active"><?= html_escape($title) ?></li>
        </ol>
    </section>

    <?php $userLevel = strtolower($this->session->userdata('level')); ?>

    <section class="content">
        <?php if (!empty($isReadOnly)): ?>
            <div class="alert alert-info">
                <i class="fa fa-eye"></i>
                Mode hanya baca: log aktivitas dapat dilihat, tetapi tidak
                dapat dihapus.
            </div>
        <?php endif; ?>

        <div class="box">
            <div class="box-body">
                <div class="table-responsive">
                    <table class="table table-bordered table-striped table-hover" id="dataTable">
                        <thead>
                            <tr>
                                <th width="10px">#</th>
                                <th>User</th>
                                <th>Cabang</th>
                                <th>IP Address</th>
                                <th>Device</th>
                                <th>Sebagai</th>
                                <th>Status</th>
                                <th>Waktu</th>
                                <?php if (empty($isReadOnly)) { ?>
                                    <th>Opsi</th>
                                <?php } ?>
                            </tr>
                        </thead>
                        <tbody>
                            <?php
                                $no = 1;
                                foreach ($log->result_array() as $row) {
                            ?>
                                <tr>
                                    <td><?= $no++ ?></td>
                                    <td>
                                        <?= html_escape(
                                            $row['nama_user'] ?: 'User tidak ditemukan'
                                        ) ?>
                                    </td>
                                    <td>
                                        <?= html_escape($row['nama_cabang'] ?: '-') ?>
                                        <?php if (!empty($row['kode_cabang'])): ?>
                                            <br>
                                            <span class="label label-info">
                                                <?= html_escape($row['kode_cabang']) ?>
                                            </span>
                                        <?php endif; ?>
                                    </td>
                                    <td><?= html_escape($row['ipAddress']) ?></td>
                                    <td><?= html_escape($row['device']) ?></td>
                                    <td><?= html_escape($row['level_user'] ?: '-') ?></td>
                                    <td>
                                        <?php
                                            if($row['status'] == 'Login') {
                                                echo '<div class="label label-success">' .
                                                    html_escape($row['status']) . '</div>';
                                            } else {
                                                echo '<div class="label label-danger">' .
                                                    html_escape($row['status']) . '</div>';
                                            }
                                        ?>
                                    </td>
                                    <td><?= date('d F Y H:i:s', strtotime($row['terdaftar'])) ?></td>
                                    
                                    <?php if (empty($isReadOnly)) { ?>
                                        <td>
                                            <a href="<?= base_url('admin/log/delete/').$row['id'] ?>" class="btn btn-danger btn-xs tombol-yakin" data-isidata="Ingin menghapus data ini?">
                                                <div class="fa fa-trash"></div> Delete
                                            </a>
                                        </td>
                                    <?php } ?>
                                </tr>
                            <?php } ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </section>
</div>
