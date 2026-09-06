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
        <div class="row">
            <!-- Total Masuk -->
            <div class="col-md-4 col-sm-6 col-xs-12">
                <div class="info-box bg-green">
                    <span class="info-box-icon"><i class="fa fa-level-up"></i></span>
                    <div class="info-box-content">
                        <span class="info-box-text">Total Masuk</span>
                        <span class="info-box-number">
                            <?= 'Rp. ' . number_format($totalMasuk,0,',','.') ?>
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

            <!-- Total Keluar -->
            <div class="col-md-4 col-sm-6 col-xs-12">
                <div class="info-box bg-red">
                    <span class="info-box-icon"><i class="fa fa-level-down"></i></span>
                    <div class="info-box-content">
                        <span class="info-box-text">Total Keluar</span>
                        <span class="info-box-number">
                            <?= 'Rp. ' . number_format($totalKeluar,0,',','.') ?>
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

            <!-- Sisa Saldo -->
            <div class="col-md-4 col-sm-6 col-xs-12">
                <div class="info-box bg-yellow">
                    <span class="info-box-icon"><i class="fa fa-money"></i></span>
                    <div class="info-box-content">
                        <span class="info-box-text">Sisa Saldo</span>
                        <span class="info-box-number">
                            <?= 'Rp. ' . number_format($sisaSaldo,0,',','.') ?>
                        </span>
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

        <!-- Detail Nasabah -->
        <div class="row">
            <div class="col-md-3">
                <div class="box">
                    <div class="box-header">
                        <button class="btn btn-primary" onclick="history.back(-1)">
                            <div class="fa fa-arrow-left"></div> Kembali
                        </button>
                    </div>
                    <div class="box-body">
                        <div class="table-responsive">
                            <table class="table table-bordered table-striped table-hover">
                                <?php foreach ($user->result() as $dUsr) { ?>
                                    <tr>
                                        <td width="120px">Nama Lengkap</td>
                                        <td width="10px">:</td>
                                        <td><?= $dUsr->nama ?></td>
                                    </tr>
                                    <tr>
                                        <td>Jenis Kelamin</td>
                                        <td>:</td>
                                        <td><?= $dUsr->jenisKelamin ?></td>
                                    </tr>
                                    <tr>
                                        <td>Telp</td>
                                        <td>:</td>
                                        <td><?= $dUsr->telp ?></td>
                                    </tr>
                                    <tr>
                                        <td>Email</td>
                                        <td>:</td>
                                        <td><?= $dUsr->email ?></td>
                                    </tr>
                                    <tr>
                                        <td>Alamat</td>
                                        <td>:</td>
                                        <td><?= $dUsr->alamat ?></td>
                                    </tr>
                                    <tr>
                                        <td>Terdaftar</td>
                                        <td>:</td>
                                        <td><?= date('d M Y H:i:s', strtotime($dUsr->terdaftar)) ?></td>
                                    </tr>
                                <?php } ?>
                            </table>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Riwayat Transaksi -->
            <div class="col-md-9">
                <div class="box">
                    <div class="box-header">
                        <h4 class="box-title">Riwayat Transaksi</h4>
                    </div>
                    <div class="box-body">
                        <div class="table-responsive">
                            <table class="table table-bordered table-striped table-hover dataTable">
                                <thead>
                                    <tr>
                                        <th width="10px">#</th>
                                        <th>Nasabah</th>
                                        <th>Tanggal</th>
                                        <th>Masuk</th>
                                        <th>Keluar</th>
                                        <th>Keterangan</th>
                                        <th>Waktu</th>
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
                                                <?php  
                                                    $this->db->where('id', $row['idNasabah']);
                                                    foreach ($this->m_model->get_desc('tb_user')->result() as $dataNasabah) {
                                                        echo $dataNasabah->nama;
                                                    }
                                                ?>
                                            </td>
                                            <td><?= date('d M Y', strtotime($row['tanggal'])) ?></td>
                                            <?php if($row['jenis'] == 'Masuk') { ?>
                                                <td>Rp. <?= number_format($row['nominal'],0,',','.') ?></td>
                                                <td></td>
                                            <?php } else { ?>
                                                <td></td>
                                                <td>Rp. <?= number_format($row['nominal'],0,',','.') ?></td>
                                            <?php } ?>
                                            <td><?= $row['keterangan'] ?></td>
                                            <td><?= date('d M Y H:i:s', strtotime($row['terdaftar'])) ?></td>
                                        </tr>
                                    <?php } ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Riwayat Transfer -->
        <div class="box">
            <div class="box-header">
                <h4 class="box-title">Riwayat Transfer</h4>
            </div>
            <div class="box-body">
                <div class="table-responsive">
                    <table class="table table-bordered table-striped table-hover dataTable">
                        <thead>
                            <tr>
                                <th width="10px">#</th>
                                <th>Dari</th>
                                <th>Kepada</th>
                                <th>Masuk</th>
                                <th>Keluar</th>
                                <th>Keterangan</th>
                                <th>Waktu</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php
                                $no = 1;
                                foreach ($transfer->result_array() as $dTf) {
                            ?>
                                <tr>
                                    <td><?= $no++ ?></td>
                                    <td>
                                        <?php  
                                            $this->db->where('id', $dTf['idPengirim']);
                                            foreach ($this->m_model->get_desc('tb_user')->result() as $dPeng) {
                                                echo $dPeng->nama;
                                            }
                                        ?>
                                    </td>
                                    <td>
                                        <?php  
                                            $this->db->where('id', $dTf['idPenerima']);
                                            foreach ($this->m_model->get_desc('tb_user')->result() as $dPene) {
                                                echo $dPene->nama;
                                            }
                                        ?>
                                    </td>
                                    <?php if($dTf['idPengirim'] == $idNasabah) { ?>
                                        <td></td>
                                        <td>Rp. <?= number_format($dTf['nominal'],0,',','.') ?></td>
                                    <?php } else { ?>
                                        <td>Rp. <?= number_format($dTf['nominal'],0,',','.') ?></td>
                                        <td></td>
                                    <?php } ?>
                                    <td><?= $dTf['keterangan'] ?></td>
                                    <td><?= date('d M Y H:i:s', strtotime($dTf['terdaftar'])) ?></td>
                                </tr>
                            <?php } ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </section>
</div>
