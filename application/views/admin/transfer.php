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
           <?php 
    $userLevel = strtolower($this->session->userdata('level'));
    if($userLevel == 'nasabah') { 
?>
                <div class="box-header">
                    <button class="btn btn-warning" data-toggle="modal" data-target="#tambahData">
                        <div class="fa fa-send"></div>&nbsp; Transfer Saldo
                    </button>
                </div>
            <?php } ?>
            <div class="box-body">
                <div class="table-responsive">
                    <table class="table table-bordered table-striped table-hover" id="dataTable">
                        <thead>
                            <tr>
                                <th width="10px">#</th>
                                <th>Dari</th>
                                <th>Kepada</th>
                               <?php if($userLevel == 'administrator' || $userLevel == 'super admin') { ?>
                                    <th>Nominal</th>
                                <?php } else { ?>
                                    <th>Masuk</th>
                                    <th>Keluar</th>
                                <?php } ?>
                                <th>Keterangan</th>
                                <th>Waktu</th>
                                <?php if($userLevel == 'administrator' || $userLevel == 'super admin') { ?>
                                    <th>Aksi</th>
                                <?php } ?>
                            </tr>
                        </thead>
                        <tbody>
                            <?php
                                $no = 1;
                                foreach ($transfer->result_array() as $row) {
                            ?>
                                <tr>
                                    <td><?= $no++ ?></td>
                                    <td>
                                        <?php  
                                            $this->db->where('id', $row['idPengirim']);
                                            foreach ($this->m_model->get_desc('tb_user')->result() as $dPeng) {
                                                echo $dPeng->nama;
                                            }
                                        ?>
                                    </td>
                                    <td>
                                        <?php  
                                            $this->db->where('id', $row['idPenerima']);
                                            foreach ($this->m_model->get_desc('tb_user')->result() as $dPene) {
                                                echo $dPene->nama;
                                            }
                                        ?>
                                    </td>
                                    <?php if($userLevel == 'administrator' || $userLevel == 'super admin') { ?>
                                        <td>Rp. <?= number_format($row['nominal'],0,',','.') ?></td>
                                    <?php } else { ?>
                                        <?php if($row['idPengirim'] == $this->session->userdata('id')) { ?>
                                            <td></td>
                                            <td>Rp. <?= number_format($row['nominal'],0,',','.') ?></td>
                                        <?php } else { ?>
                                            <td>Rp. <?= number_format($row['nominal'],0,',','.') ?></td>
                                            <td></td>
                                        <?php } ?>
                                    <?php } ?>
                                    <td><?= $row['keterangan'] ?></td>
                                    <td><?= date('d F Y H:i:s', strtotime($row['terdaftar'])) ?></td>
                                  <?php if($userLevel == 'administrator' || $userLevel == 'super admin') { ?>
                                    <td>
                                        <a href="<?= base_url('admin/transfer/delete/').$row['id'] ?>" class="btn btn-danger btn-xs tombol-yakin" data-isidata="Ingin menghapus data ini?">
                                                    <div class="fa fa-trash"></div> Delete</a>
                                                    <?php } ?>
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

<!-- Modal Tambah Data -->
<div class="modal fade" id="tambahData" tabindex="-1" role="dialog" aria-labelledby="myModalLabel">
    <div class="modal-dialog" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                <h4 class="modal-title" id="myModalLabel">Tambah <?= $title ?></h4>
            </div>
            <form action="<?= base_url('admin/transfer/insert') ?>" method="POST">
                <input type="hidden" name="<?= $this->security->get_csrf_token_name();?>" value="<?=$this->security->get_csrf_hash();?>" style="display: none">
                <div class="modal-body">
                    <div class="form-group">
                        <label>Nasabah Penerima</label>
                        <select name="idPenerima" class="form-control select2" required style="width: 100%">
                            <option value="" selected disabled>-- Pilih Nasabah Penerima --</option>
                            <?php foreach ($nasabah->result() as $nsbh) { ?>
                                <option value="<?= $nsbh->id ?>"><?= $nsbh->nama ?></option>
                            <?php } ?>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Nominal</label>
                        <input type="text" name="nominal" class="form-control" placeholder="Nominal" required>
                    </div>
                    <div class="form-group">
                        <label>Keterangan</label>
                        <input type="text" name="keterangan" class="form-control" placeholder="Keterangan" required>
                    </div>
                    <div class="form-group">
                        <input type="checkbox" name="setuju" id="setujuCheckbox" required> Saya mengerti transfer tidak dapat dibatalkan!
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="reset" class="btn btn-danger"><div class="fa fa-trash"></div>&nbsp; Reset</button>
                    <button type="submit" class="btn btn-primary" id="saveButton" disabled><div class="fa fa-send"></div>&nbsp; Transfer</button>
                </div>
            </form>
        </div>
    </div>
</div>