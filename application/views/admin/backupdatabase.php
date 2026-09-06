<div class="content-wrapper">
    <section class="content-header">
        <h1>
            <?= $title ?>
            <small><?= $subtitle ?></small>
        </h1>
        <ol class="breadcrumb">
            <li><a href="<?= base_url('admin/dashboard') ?>"><i class="fa fa-dashboard"></i> Dashboard</a></li>
            <li class="active"><?= $title ?></li>
        </ol>
    </section>
    <section class="content">
        <div class="box">
            <div class="box-header">
                <a href="<?= base_url('admin/backupdatabase/backup_database') ?>" class="btn btn-danger">
                    <div class="fa fa-database"></div> Backup Database
                </a>
            </div>
            <div class="box-body">
                <div class="table-responsive">
                    <table class="table table-bordered table-striped table-hover" id="dataTable">
                        <thead>
                            <tr>
                                <th width="10px">#</th>
                                <th>User</th>
                                <th>Database</th>
                                <th>Terdaftar</th>
                                <th>Aksi</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php
                                $no = 1;
                                foreach ($backupdb->result_array() as $row) {
                            ?>
                                <tr>
                                    <td><?= $no++ ?></td>
                                    <td>
                                        <?php
                                            $this->db->where('id', $row['idUser'] );
                                            foreach ($this->db->get('tb_user')->result() as $dUsr) {
                                                echo $dUsr->nama;
                                            }
                                        ?>
                                    </td>
                                    <td><?= $row['database'] ?></td>
                                    <td><?= date('d F Y H:i:s', strtotime($row['terdaftar'])) ?></td>
                                    <td>
                                        <a href="<?= base_url('/assets/database_backup/').$row['database'] ?>" class="btn btn-primary btn-xs">
                                            <div class="fa fa-download"></div> Download
                                        </a>
                                        <a href="<?= base_url('admin/backupdatabase/delete/').$row['id'] ?>" class="btn btn-danger btn-xs tombol-yakin" data-isidata="Ingin menghapus data ini?">
                                                    <div class="fa fa-trash"></div> Delete
                                                </a>
                                    </td>
                                </tr>
                            <?php } ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </section>
</div>