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
        <?php
        $userLevel = strtolower($this->session->userdata('level'));
        if ($userLevel == 'nasabah') {
        ?>
            <div class="row">
                <div class="col-md-4 col-sm-6 col-xs-12">
                    <div class="info-box bg-green">
                        <span class="info-box-icon"><i class="fa fa-level-up"></i></span>

                        <div class="info-box-content">
                            <span class="info-box-text">Total Masuk</span>
                            <span class="info-box-number">
                                <?php
                                // HANYA HITUNG YANG SUKSES
                                foreach ($this->db->query('SELECT SUM(nominal) AS totalTabunganMasuk FROM tb_transaksi WHERE idNasabah="' . $this->session->userdata('id') . '" AND jenis="Masuk" AND status_konfirmasi="Sukses"')->result() as $tbMsk) {
                                }
                                foreach ($this->db->query('SELECT SUM(nominal) AS totalTransferMasuk FROM tb_transfer WHERE idPenerima="' . $this->session->userdata('id') . '"')->result() as $tfMsk) {
                                }

                                $totalMasuk = $tbMsk->totalTabunganMasuk + $tfMsk->totalTransferMasuk;

                                echo 'Rp. ' . number_format($totalMasuk, 0, ',', '.');
                                ?>
                            </span>

                            <div class="progress">
                                <div class="progress-bar" style="width: 100%"></div>
                            </div>
                            <span class="progress-description">
                                Transaksi Masuk + Transfer Masuk
                            </span>
                        </div>
                    </div>
                </div>
                <div class="col-md-4 col-sm-6 col-xs-12">
                    <div class="info-box bg-red">
                        <span class="info-box-icon"><i class="fa fa-level-down"></i></span>

                        <div class="info-box-content">
                            <span class="info-box-text">Total Keluar</span>
                            <span class="info-box-number">
                                <?php
                                // HANYA HITUNG YANG SUKSES
                                foreach ($this->db->query('SELECT SUM(nominal) AS totalTabunganKeluar FROM tb_transaksi WHERE idNasabah="' . $this->session->userdata('id') . '" AND jenis="Keluar" AND status_konfirmasi="Sukses"')->result() as $tbKlr) {
                                }
                                foreach ($this->db->query('SELECT SUM(nominal) AS totalTransferKeluar FROM tb_transfer WHERE idPengirim="' . $this->session->userdata('id') . '"')->result() as $tfKlr) {
                                }

                                $totalKeluar = $tbKlr->totalTabunganKeluar + $tfKlr->totalTransferKeluar;

                                echo 'Rp. ' . number_format($totalKeluar, 0, ',', '.');
                                ?>
                            </span>

                            <div class="progress">
                                <div class="progress-bar" style="width: 100%"></div>
                            </div>
                            <span class="progress-description">
                                Transaksi Keluar + Transfer Keluar
                            </span>
                        </div>
                    </div>
                </div>
                <div class="col-md-4 col-sm-6 col-xs-12">
                    <div class="info-box bg-yellow">
                        <span class="info-box-icon"><i class="fa fa-money"></i></span>

                        <div class="info-box-content">
                            <span class="info-box-text">Sisa Saldo</span>
                            <span class="info-box-number"><?= 'Rp. ' . number_format($totalMasuk - $totalKeluar, 0, ',', '.') ?></span>

                            <div class="progress">
                                <div class="progress-bar" style="width: 100%"></div>
                            </div>
                            <span class="progress-description">
                                Total Masuk - Total Keluar
                            </span>
                        </div>
                    </div>
                </div>
            </div>
        <?php } ?>
        <div class="box">
            <?php if ($userLevel == 'administrator' || $userLevel == 'super admin') { ?>
                <div class="box-header">
                    <button class="btn btn-primary" style="border-radius: 4px" data-toggle="modal" data-target="#tambahData">
                        <div class="fa fa-plus"></div> Tambah Data
                    </button>
                    <button class="btn btn-success" style="border-radius: 4px" data-toggle="modal" data-target="#cekSaldo">
                        <div class="fa fa-calendar"></div> Cek Saldo
                    </button>
                    <button class="btn btn-warning" style="border-radius: 4px" data-toggle="modal" data-target="#rekapData">
                        <div class="fa fa-print"></div> Rekap Data
                    </button>
                </div>
            <?php } ?>
            <div class="box-body">
                <div class="table-responsive">
                    <table class="table table-bordered table-striped table-hover" id="dataTable">
                        <thead>
                            <tr>
                                <th width="10px">#</th>
                                <th>Nasabah</th>

                                <?php if ($userLevel == 'super admin'): ?>
                                    <th>Cabang</th>
                                <?php endif; ?>

                                <th>Tanggal</th>
                                <th>Masuk</th>
                                <th>Keluar</th>
                                <th>Keterangan</th>
                                <th>Status</th>
                                <th>Bukti</th>
                                <th>Waktu</th>
                                <?php if ($userLevel == 'administrator' || $userLevel == 'super admin') { ?>
                                    <th>Aksi</th>
                                <?php } ?>
                            </tr>
                        </thead>
                        <tbody>
                            <?php
                            $no = 1;
                            foreach ($transaksi->result_array() as $row) {
                            ?>
                                <tr>
                                    <td><?= $no++ ?></td>
                                    <td>
                                        <?= html_escape(
                                            !empty($row['nama_nasabah'])
                                                ? $row['nama_nasabah']
                                                : 'Nasabah tidak ditemukan'
                                        ) ?>
                                    </td>

                                    <?php if ($userLevel == 'super admin'): ?>
                                        <td>
                                            <?php if (!empty($row['nama_cabang'])): ?>
                                                <?= html_escape($row['nama_cabang']) ?>
                                                <br>
                                                <span class="label label-info">
                                                    <?= html_escape($row['kode_cabang']) ?>
                                                </span>
                                            <?php else: ?>
                                                <span class="label label-danger">
                                                    Belum ada cabang
                                                </span>
                                            <?php endif; ?>
                                        </td>
                                    <?php endif; ?>
                                    <td><?= date('d M Y', strtotime($row['tanggal'])) ?></td>
                                    <?php if ($row['jenis'] == 'Masuk') { ?>
                                        <td>Rp. <?= number_format($row['nominal'], 0, ',', '.') ?></td>
                                        <td></td>
                                    <?php } else { ?>
                                        <td></td>
                                        <td>Rp. <?= number_format($row['nominal'], 0, ',', '.') ?></td>
                                    <?php } ?>
                                    <td><?= $row['keterangan'] ?></td>

                                    <td>
                                        <?php if ($row['status_konfirmasi'] == 'Pending') { ?>
                                            <span class="label label-warning">Pending</span>
                                        <?php } elseif ($row['status_konfirmasi'] == 'Sukses') { ?>
                                            <span class="label label-success">Sukses</span>
                                        <?php } else { ?>
                                            <span class="label label-danger">Ditolak</span>
                                        <?php } ?>
                                    </td>

                                    <td>
                                        <?php if (!empty($row['bukti_transfer'])) { ?>
                                            <a href="<?= base_url('assets/bukti_transfer/' . $row['bukti_transfer']) ?>" target="_blank" class="btn btn-info btn-xs" style="border-radius: 4px;">
                                                <i class="fa fa-image"></i> Lihat
                                            </a>
                                        <?php } else { ?>
                                            -
                                        <?php } ?>
                                    </td>

                                    <td><?= date('H:i:s', strtotime($row['terdaftar'])) ?></td>
                                    <?php if ($userLevel == 'administrator' || $userLevel == 'super admin') { ?>
                                        <td>
                                            <?php $row['idPotongan']  ?>
                                            <button class="btn btn-warning btn-xs" data-toggle="modal" data-target="#editData<?= $row['id'] ?>" style="border-radius: 4px;">
                                                <div class="fa fa-edit"></div> Edit
                                            </button>
                                            <a href="<?= base_url('admin/transaksi/delete/') . $row['id'] ?>" class="btn btn-danger btn-xs tombol-yakin" data-isidata="Ingin menghapus data ini?" style="border-radius: 4px;">
                                                <div class="fa fa-trash"></div> Delete
                                            </a>
                                            <?php  ?>
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
        <div class="modal-content" style="border-radius: 5px">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                <h4 class="modal-title" id="myModalLabel">Tambah <?= $title ?></h4>
            </div>
            <form action="<?= base_url('admin/transaksi/insert') ?>" method="POST">
                <input type="hidden" name="<?= $this->security->get_csrf_token_name(); ?>" value="<?= $this->security->get_csrf_hash(); ?>" style="display: none">
                <div class="modal-body">
                    <div class="form-group">
                        <label>Nasabah</label>
                        <select name="idNasabah" class="form-control select2" required style="width: 100%">
                            <option value="" selected disabled>-- Pilih Nasabah --</option>
                            <?php foreach ($nasabah->result() as $nsbh) { ?>
                                <option value="<?= $nsbh->id ?>"><?= $nsbh->nama ?></option>
                            <?php } ?>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Tanggal</label>
                        <input type="text" name="tanggal" class="form-control" id="datepicker" placeholder="Tanggal" style="border-radius: 4px" required>
                    </div>
                    <div class="form-group">
                        <label>Nominal</label>
                        <input type="number" name="nominal" class="form-control" placeholder="Nominal" style="border-radius: 4px" required>
                    </div>
                    <div class="form-group">
                        <label>Jenis</label>
                        <select name="jenis" class="form-control" style="border-radius: 4px" required>
                            <option value="" selected disabled>-- Pilih Jenis --</option>
                            <option value="Masuk">Masuk</option>
                            <option value="Keluar">Keluar</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Keterangan</label>
                        <input type="text" name="keterangan" class="form-control" placeholder="Keterangan" style="border-radius: 4px" required>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="reset" class="btn btn-danger" style="border-radius: 4px">
                        <div class="fa fa-trash"></div> Reset
                    </button>
                    <button type="submit" class="btn btn-primary" style="border-radius: 4px">
                        <div class="fa fa-save"></div> Save
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>

<?php foreach ($transaksi->result() as $edt) { ?>
    <div class="modal fade" id="editData<?= $edt->id ?>" tabindex="-1" role="dialog" aria-labelledby="myModalLabel">
        <div class="modal-dialog" role="document">
            <div class="modal-content" style="border-radius: 5px">
                <div class="modal-header">
                    <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                    <h4 class="modal-title" id="myModalLabel">Edit <?= $title ?></h4>
                </div>
                <form action="<?= base_url('admin/transaksi/update/') . $edt->id ?>" method="POST">
                    <input type="hidden" name="<?= $this->security->get_csrf_token_name(); ?>" value="<?= $this->security->get_csrf_hash(); ?>" style="display: none">
                    <div class="modal-body">
                        <div class="form-group">
                            <label>Tanggal</label>
                            <input type="text" name="tanggal" class="form-control" id="datepicker4" style="border-radius: 4px" value="<?= $edt->tanggal ?>" required>
                        </div>
                        <div class="form-group">
                            <label>Nominal</label>
                            <input type="number" name="nominal" class="form-control" style="border-radius: 4px" placeholder="Nominal" value="<?= $edt->nominal ?>" required>
                        </div>
                        <div class="form-group">
                            <label>Keterangan</label>
                            <input type="text" name="keterangan" class="form-control" style="border-radius: 4px" placeholder="Keterangan" value="<?= $edt->keterangan ?>" required>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="reset" class="btn btn-danger" style="border-radius: 4px">
                            <div class="fa fa-trash"></div> Reset
                        </button>
                        <button type="submit" class="btn btn-primary" style="border-radius: 4px">
                            <div class="fa fa-save"></div> Update
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>
<?php } ?>

<div class="modal fade" id="cekSaldo" tabindex="-1" role="dialog" aria-labelledby="myModalLabel">
    <div class="modal-dialog" role="document">
        <div class="modal-content" style="border-radius: 5px">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                <h4 class="modal-title" id="myModalLabel">Cek Saldo</h4>
            </div>
            <form action="<?= base_url('admin/transaksi/carinasabah') ?>" method="POST">
                <input type="hidden" name="<?= $this->security->get_csrf_token_name(); ?>" value="<?= $this->security->get_csrf_hash(); ?>" style="display: none">
                <div class="modal-body">
                    <div class="form-group">
                        <label>Nasabah</label>
                        <select name="idNasabah" class="form-control select2" required style="width: 100%">
                            <option value="" selected disabled>-- Pilih Nasabah --</option>
                            <?php foreach ($nasabah->result() as $nsbh) { ?>
                                <option value="<?= $nsbh->id ?>"><?= $nsbh->nama ?></option>
                            <?php } ?>
                        </select>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="submit" class="btn btn-primary" style="border-radius: 4px">
                        <div class="fa fa-search"></div> Check
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>

<div class="modal fade" id="rekapData" tabindex="-1" role="dialog" aria-labelledby="myModalLabel">
    <div class="modal-dialog" role="document">
        <div class="modal-content" style="border-radius: 5px">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                <h4 class="modal-title" id="myModalLabel">Rekap <?= $title ?></h4>
            </div>
            <form action="<?= base_url('admin/transaksi/rekap') ?>" method="POST">
                <input type="hidden" name="<?= $this->security->get_csrf_token_name(); ?>" value="<?= $this->security->get_csrf_hash(); ?>" style="display: none">
                <div class="modal-body">
                    <div class="form-group">
                        <label>Dari Tanggal</label>
                        <input type="text" name="dariTanggal" class="form-control" id="datepicker2" placeholder="Dari Tanggal" required>
                    </div>
                    <div class="form-group">
                        <label>Sampai Tanggal</label>
                        <input type="text" name="sampaiTanggal" class="form-control" id="datepicker3" placeholder="Sampai Tanggal" required>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="reset" class="btn btn-danger" style="border-radius: 4px">
                        <div class="fa fa-trash"></div> Reset
                    </button>
                    <button type="submit" class="btn btn-primary" style="border-radius: 4px">
                        <div class="fa fa-print"></div> Rekap
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>