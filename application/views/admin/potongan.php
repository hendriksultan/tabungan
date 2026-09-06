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
    
    <?php $userLevel = strtolower($this->session->userdata('level')); ?>

    <section class="content">
        <div class="box">
            <div class="box-header">
                <?php if($userLevel == 'administrator' || $userLevel == 'super admin') { ?>
                    <button class="btn btn-primary" data-toggle="modal" data-target="#tambahData">
                        <div class="fa fa-plus"></div> Tambah Data
                    </button>
                <?php } ?>
            </div>
            <div class="box-body">
                <div class="table-responsive">
                    <table class="table table-bordered table-striped table-hover" id="dataTable">
                        <thead>
                            <tr>
                                <th width="10px">#</th>
                                <th>Admin</th>
                                <th>Nominal</th>
                                <th>Keterangan</th>
                                <th>Total Nasabah</th>
                                <th>Total Nominal</th>
                                <th>Terdaftar</th>
                                <?php if($userLevel == 'administrator' || $userLevel == 'super admin') { ?>
                                    <th>Aksi</th>
                                <?php } ?>
                            </tr>
                        </thead>
                        <tbody>
                            <?php
                                $no = 1;
                                foreach ($potongan->result_array() as $row) {
                            ?>
                                <tr>
                                    <td><?= $no++ ?></td>
                                    <td>
                                        <?php
                                            $this->db->where('id', $row['idAdmin']);
                                            foreach ($this->db->get('tb_user')->result() as $dUsr) {
                                                echo $dUsr->nama;
                                            }
                                        ?>
                                    </td>
                                    <td>Rp. <?= number_format($row['nominal'],0,',','.') ?></td>
                                    <td><?= $row['keterangan'] ?></td>
                                    <td>
                                        <?php
                                            $this->db->where('idPotongan', $row['id']);
                                            echo $this->db->get('tb_transaksi')->num_rows();
                                        ?>
                                    </td>
                                    <td>
                                        <?php
                                            foreach ($this->db->query('SELECT SUM(nominal) AS totalNominal FROM tb_transaksi WHERE idPotongan="'.$row['id'].'" ')->result() as $tPot) {
                                                echo 'Rp. ' . number_format($tPot->totalNominal,0,',','.');
                                            }
                                        ?>
                                    </td>
                                    <td><?= date('d F Y H:i:s', strtotime($row['terdaftar'])) ?></td>
                                    
                                    <?php if($userLevel == 'administrator' || $userLevel == 'super admin') { ?>
                                        <td>
                                            <a href="<?= base_url('admin/potongan/delete/').$row['id'] ?>" class="btn btn-danger btn-xs tombol-yakin" data-isidata="Ingin menghapus data ini?">
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

<div class="modal fade" id="tambahData" tabindex="-1" role="dialog" aria-labelledby="myModalLabel">
    <div class="modal-dialog" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                <h4 class="modal-title" id="myModalLabel">Tambah <?= $title ?></h4>
            </div>
            <form action="<?= base_url('admin/potongan/insert') ?>" method="POST">
                <input type="hidden" name="<?= $this->security->get_csrf_token_name();?>" value="<?=$this->security->get_csrf_hash();?>" style="display: none">
                <div class="modal-body">
                    <div class="form-group">
                        <label>Nominal</label>
                        <input type="number" name="nominal" class="form-control" placeholder="Nominal" required>
                    </div>
                    <div class="form-group">
                        <label>Keterangan</label>
                        <input type="text" name="keterangan" class="form-control" placeholder="Keterangan" required>
                    </div>
                    <div class="form-group">
                        <input type="checkbox" name="setuju" id="setujuCheckbox" required> Saya mengerti saldo semua nasabah yang terdaftar akan terpotong!
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="reset" class="btn btn-danger"><div class="fa fa-trash"></div> Reset</button>
                    <button type="submit" class="btn btn-primary" id="saveButton" disabled><div class="fa fa-save"></div> Save</button>
                </div>
            </form>
        </div>
    </div>
</div>