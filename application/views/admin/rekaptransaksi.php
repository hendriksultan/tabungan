<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <!-- The above 3 meta tags *must* come first in the head; any other head content must come *after* these tags -->
        <title><?= $title ?></title>

        <!-- Bootstrap -->
        <link rel="stylesheet" href="<?= base_url('assets') ?>/bower_components/bootstrap/dist/css/bootstrap.min.css">

        <!-- HTML5 shim and Respond.js for IE8 support of HTML5 elements and media queries -->
        <!-- WARNING: Respond.js doesn't work if you view the page via file:// -->
        <!--[if lt IE 9]>
        <script src="https://cdn.jsdelivr.net/npm/html5shiv@3.7.3/dist/html5shiv.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/respond.js@1.4.2/dest/respond.min.js"></script>
        <![endif]-->
    </head>
    <?php
        date_default_timezone_set('Asia/Jakarta');
    ?>
    <body>
        <div class="container">
            <h3><center><b><?= strtoupper($title) ?></b></center></h3>

            <table>
                <tr>
                    <td width="100px">Tanggal</td>
                    <td width="10px">:</td>
                    <td>
                        <?php
                            if($dariTanggal == $sampaiTanggal) {
                                echo date('d F Y', strtotime($dariTanggal));
                            } else {
                                echo date('d F Y', strtotime($dariTanggal)) . ' s/d ' . date('d F Y', strtotime($sampaiTanggal));
                            }
                        ?>
                    </td>
                </tr>
                <tr>
                    <td>Jumlah</td>
                    <td>:</td>
                    <td><?= $transaksi->num_rows() ?> Transaksi</td>
                </tr>
                <tr>
                    <td>Masuk</td>
                    <td>:</td>
                    <td>
                        <?php
                            foreach ($jumlahMasuk->result() as $msk) {
                                echo 'Rp. ' . number_format($msk->jumlahMasuk,0,',','.');
                            }
                        ?>
                    </td>
                </tr>
                <tr>
                    <td>Keluar</td>
                    <td>:</td>
                    <td>
                        <?php
                            foreach ($jumlahKeluar->result() as $klr) {
                                echo 'Rp. ' . number_format($klr->jumlahKeluar,0,',','.');
                            }
                        ?>
                    </td>
                </tr>
            </table> <br>

            <div class="table-responsive">
                <table class="table table-bordered table-striped table-hover">
                    <thead>
                        <tr>
                            <th width="10px">#</th>
                            <th>Nasabah</th>
                            <th>Tanggal</th>
                            <th>Masuk</th>
                            <th>Keluar</th>
                            <th>Keterangan</th>
                            <th>Terdaftar</th>
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
                                <td><?= date('d F Y', strtotime($row['tanggal'])) ?></td>
                                <?php if($row['jenis'] == 'Masuk') { ?>
                                    <td>Rp. <?= number_format($row['nominal'],0,',','.') ?></td>
                                    <td></td>
                                <?php } else { ?>
                                    <td></td>
                                    <td>Rp. <?= number_format($row['nominal'],0,',','.') ?></td>
                                <?php } ?>
                                <td><?= $row['keterangan'] ?></td>
                                <td><?= date('d F Y H:i:s', strtotime($row['terdaftar'])) ?></td>
                            </tr>
                        <?php } ?>
                    </tbody>
                </table>
            </div>

            <font style="position: fixed; bottom: 0">
                <small><i>Dicetak pada <?= date('d F Y H:i:s') ?> Oleh <?= $this->session->userdata('nama') ?>, <?= current_url() ?></i></small>
            </font>
        </div>

        <!-- jQuery (necessary for Bootstrap's JavaScript plugins) -->
        <script src="<?= base_url('assets') ?>/bower_components/jquery/dist/jquery.min.js"></script>
        <!-- Include all compiled plugins (below), or include individual files as needed -->
        <script src="<?= base_url('assets') ?>/bower_components/bootstrap/dist/js/bootstrap.min.js"></script>
        <script>
            window.print();
        </script>
    </body>
</html>