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

        <style>
            .info-box {
                border-radius: 4px;
                box-shadow: 0 4px 8px rgba(0,0,0,0.1);
                transition: transform 0.3s, box-shadow 0.3s;
                color: #fff;
                height: 100%;
            }
            .info-box:hover {
                transform: translateY(-5px);
                box-shadow: 0 8px 16px rgba(0,0,0,0.2);
            }
            .info-box .info-box-icon {
                border-top-left-radius: 4px;
                border-bottom-left-radius: 4px;
                font-size: 40px;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .progress { height: 5px; background-color: rgba(255,255,255,0.3); margin: 5px 0; }
            .progress-bar { background-color: rgba(255,255,255,0.7); }
            .more-info { display: block; margin-top: 8px; font-size: 14px; font-weight: 500; color: #fff; text-decoration: none; transition: opacity 0.2s; }
            .more-info i { margin-left: 5px; transition: transform 0.3s; }
            .more-info:hover { opacity: 0.9; }
            .more-info:hover i { transform: translateX(4px); }
            .info-box-number1 { display: block; font-weight: bold; font-size: 18px; padding-top: 2px; margin-top: 4px; }
            .bg-green { background: linear-gradient(45deg, #28a745, #71dd8a); }
            .bg-red { background: linear-gradient(45deg, #dc3545, #ff7b7b); }
            .bg-orange { background: linear-gradient(45deg, #fd7e14, #ffb366); }
            .bg-blue { background: linear-gradient(45deg, #007bff, #66b0ff); }
            .bg-purple { background: linear-gradient(45deg, #6f42c1, #b18eff); }
            .bg-yellow { background: linear-gradient(45deg, #ffc107, #ffe066); }
            .bg-teal { background: linear-gradient(45deg, #20c997, #70e1d5); }

            /* Card styling untuk chart */
            .card {
                background: #fff;
                border-radius: 4px;
                padding: 20px;
                box-shadow: 0 4px 10px rgba(0,0,0,0.1);
                margin-bottom: 15px;
                margin-top: 4px;
                height: 100%;
            }
            .card h4 {
                font-size: 16px;
                margin-bottom: 15px;
                font-weight: 600;
            }
            .card canvas {
                width: 100% !important;
                height: 280px !important;
            }
        </style>

        <?php 
    $userLevel = strtolower($this->session->userdata('level'));
    if($userLevel == 'administrator' || $userLevel == 'super admin') { 
?>
        <div class="row">
            <!-- Total Masuk -->
            <div class="col-12 col-sm-6 col-md-4 mb-3">
                <div class="info-box bg-green">
                    <span class="info-box-icon"><i class="fa fa-level-down"></i></span>
                    <div class="info-box-content">
                        <span class="info-box-text">Total Masuk</span>
                        <span class="info-box-number"><?= 'Rp. ' . number_format($saldo_detail['totalMasuk'],0,',','.') ?></span>
                        <div class="progress"><div class="progress-bar" style="width:100%"></div></div>
                        <span class="progress-description">Transaksi Masuk + Transfer Masuk</span>
                    </div>
                </div>
            </div>

            <!-- Total Keluar -->
            <div class="col-12 col-sm-6 col-md-4 mb-3">
                <div class="info-box bg-red">
                    <span class="info-box-icon"><i class="fa fa-level-up"></i></span>
                    <div class="info-box-content">
                        <span class="info-box-text">Total Keluar</span>
                        <span class="info-box-number"><?= 'Rp. ' . number_format($saldo_detail['totalKeluar'],0,',','.') ?></span>
                        <div class="progress"><div class="progress-bar" style="width:100%"></div></div>
                        <span class="progress-description">Transaksi Keluar + Transfer Keluar</span>
                    </div>
                </div>
            </div>

            <!-- Sisa Saldo -->
            <div class="col-12 col-sm-6 col-md-4 mb-3">
                <div class="info-box bg-orange">
                    <span class="info-box-icon"><i class="fa fa-money"></i></span>
                    <div class="info-box-content">
                        <span class="info-box-text">Sisa Saldo</span>
                        <span class="info-box-number"><?= 'Rp. ' . number_format($saldo_detail['sisaSaldo'],0,',','.') ?></span>
                        <div class="progress"><div class="progress-bar" style="width:100%"></div></div>
                        <span class="progress-description">Sisa Saldo Seluruh Nasabah</span>
                    </div>
                </div>
            </div>

            <!-- Total Transaksi -->
            <div class="col-12 col-sm-6 col-md-4 mb-3">
                <div class="info-box bg-red">
                    <span class="info-box-icon"><i class="fa fa-book"></i></span>
                    <div class="info-box-content">
                        <span class="info-box-text">Total Transaksi</span>
                        <span class="info-box-number1"><?= $this->db->query('SELECT id FROM tb_transaksi')->num_rows(); ?></span>
                        <a href="<?= base_url('admin/transaksi') ?>" class="more-info">More info <i class="fa fa-arrow-circle-right"></i></a>
                    </div>
                </div>
            </div>
            
            <!-- Total Transfer -->
            <div class="col-12 col-sm-6 col-md-4 mb-3">
                <div class="info-box bg-purple">
                    <span class="info-box-icon"><i class="fa fa-send"></i></span>
                    <div class="info-box-content">
                        <span class="info-box-text">Total Transfer</span>
                        <span class="info-box-number1"><?= $this->db->query('SELECT id FROM tb_transfer')->num_rows(); ?></span>
                        <a href="<?= base_url('admin/transfer') ?>" class="more-info">More info <i class="fa fa-arrow-circle-right"></i></a>
                    </div>
                </div>
            </div>
            
            
            <!-- Total Nasabah -->
            <div class="col-12 col-sm-6 col-md-4 mb-3">
                <div class="info-box bg-blue">
                    <span class="info-box-icon"><i class="fa fa-user-plus"></i></span>
                    <div class="info-box-content">
                        <span class="info-box-text">Total Nasabah</span>
                        <span class="info-box-number1"><?= $this->db->query('SELECT id FROM tb_user WHERE level="Nasabah"')->num_rows(); ?></span>
                        <a href="<?= base_url('admin/user') ?>" class="more-info">More info <i class="fa fa-arrow-circle-right"></i></a>
                    </div>
                </div>
            </div>

            <!-- Total Nasabah Laki-Laki -->
            <!--<div class="col-12 col-sm-6 col-md-4 mb-3">
                <div class="info-box bg-green">
                    <span class="info-box-icon"><i class="fa fa-male"></i></span>
                    <div class="info-box-content">
                        <span class="info-box-text">Total Nasabah Laki-Laki</span>
                        <span class="info-box-number1"><?= $this->db->query('SELECT id FROM tb_user WHERE jenisKelamin="Laki-Laki" AND level="Nasabah"')->num_rows(); ?></span>
                        <a href="<?= base_url('admin/user') ?>" class="more-info">More info <i class="fa fa-arrow-circle-right"></i></a>
                    </div>
                </div>
            </div>-->

            <!-- Total Nasabah Perempuan -->
            <!--<div class="col-12 col-sm-6 col-md-4 mb-3">
                <div class="info-box bg-yellow">
                    <span class="info-box-icon"><i class="fa fa-female"></i></span>
                    <div class="info-box-content">
                        <span class="info-box-text">Total Nasabah Perempuan</span>
                        <span class="info-box-number1"><?= $this->db->query('SELECT id FROM tb_user WHERE jenisKelamin="Perempuan" AND level="Nasabah"')->num_rows(); ?></span>
                        <a href="<?= base_url('admin/user') ?>" class="more-info">More info <i class="fa fa-arrow-circle-right"></i></a>
                    </div>
                </div>
            </div>-->

            <!-- Total Administrator -->
            <!--<div class="col-12 col-sm-6 col-md-4 mb-3">
                <div class="info-box bg-teal">
                    <span class="info-box-icon"><i class="fa fa-users"></i></span>
                    <div class="info-box-content">
                        <span class="info-box-text">Total Administrator</span>
                        <span class="info-box-number1"><?= $this->db->query('SELECT id FROM tb_user WHERE level="Administrator"')->num_rows(); ?></span>
                        <a href="<?= base_url('admin/user') ?>" class="more-info">More info <i class="fa fa-arrow-circle-right"></i></a>
                    </div>
                </div>
            </div>-->
        </div> <!-- end row -->

        <!-- Chart Section -->
        <div class="row">
            <!-- Grafik Transaksi -->
            <div class="col-lg-6 col-md-6 mb-3">
                <div class="card">
                    <h4>Grafik Transaksi</h4>
                    <canvas id="transaksiChart"></canvas>
                </div>
            </div>

            <!-- Grafik Nasabah -->
            <div class="col-lg-6 col-md-6 mb-3">
                <div class="card">
                    <h4>Grafik Nasabah</h4>
                    <canvas id="nasabahChart"></canvas>
                </div>
            </div>
        </div>

        <!-- Grafik Bulanan -->
        <div class="row">
            <div class="col-lg-12 col-md-12 mb-3">
                <div class="card">
                    <h4>Grafik Transaksi Bulanan (<?= date('Y') ?>)</h4>
                    <canvas id="bulananChart"></canvas>
                </div>
            </div>
        </div>


<?php } elseif($userLevel == 'nasabah') { ?>
        <!-- NASABAH -->
          <div class="row">
            <div class="col-12 col-sm-6 col-md-4 mb-3">
                <div class="info-box bg-red">
                    <span class="info-box-icon"><i class="fa fa-book"></i></span>
                    <div class="info-box-content">
                        <span class="info-box-text">Total Transaksi Saya</span>
                        <span class="info-box-number"><?= $this->db->query('SELECT id FROM tb_transaksi WHERE idNasabah="'.$this->session->userdata('id').'"')->num_rows(); ?></span>
                        <a href="<?= base_url('admin/transaksi') ?>" class="more-info" style="color:#fff; text-decoration: none;">More info <i class="fa fa-arrow-circle-right"></i></a>
                    </div>
                </div>
            </div>

            <div class="col-12 col-sm-6 col-md-4 mb-3">
                <div class="info-box bg-blue">
                    <span class="info-box-icon"><i class="fa fa-pencil"></i></span>
                    <div class="info-box-content">
                        <span class="info-box-text">Total Transfer Saya</span>
                        <span class="info-box-number"><?= $this->db->query('SELECT id FROM tb_transfer WHERE idPengirim="'.$this->session->userdata('id').'" OR idPenerima="'.$this->session->userdata('id').'"')->num_rows(); ?></span>
                        <a href="<?= base_url('admin/transfer') ?>" class="more-info" style="color:#fff; text-decoration: none;">More info <i class="fa fa-arrow-circle-right"></i></a>
                    </div>
                </div>
            </div>

            <div class="col-12 col-sm-6 col-md-4 mb-3">
                <div class="info-box bg-green">
                    <span class="info-box-icon"><i class="fa fa-money"></i></span>
                    <div class="info-box-content">
                        <span class="info-box-text">Sisa Saldo</span>
                        <span class="info-box-number">
                            <?php
                                foreach ($this->db->query('SELECT SUM(nominal) AS totalTabunganMasuk FROM tb_transaksi WHERE idNasabah="'.$this->session->userdata('id').'" AND jenis="Masuk"')->result() as $tbMsk) {}
                                foreach ($this->db->query('SELECT SUM(nominal) AS totalTransferMasuk FROM tb_transfer WHERE idPenerima="'.$this->session->userdata('id').'"')->result() as $tfMsk) {}
                                $totalMasuk = $tbMsk->totalTabunganMasuk + $tfMsk->totalTransferMasuk ;
                                foreach ($this->db->query('SELECT SUM(nominal) AS totalTabunganKeluar FROM tb_transaksi WHERE idNasabah="'.$this->session->userdata('id').'" AND jenis="Keluar"')->result() as $tbKlr) {}
                                foreach ($this->db->query('SELECT SUM(nominal) AS totalTransferKeluar FROM tb_transfer WHERE idPengirim="'.$this->session->userdata('id').'"')->result() as $tfKlr) {}
                                $totalKeluar = $tbKlr->totalTabunganKeluar + $tfKlr->totalTransferKeluar;
                                $sisaSaldo = $totalMasuk - $totalKeluar;
                                echo 'Rp. ' . number_format($sisaSaldo,0,',','.');
                            ?>
                        </span>
                        <a href="<?= base_url('admin/transaksi') ?>" class="more-info" style="color:#fff; text-decoration: none;">More info <i class="fa fa-arrow-circle-right"></i></a>
                    </div>
                </div>
            </div>
        </div> <!-- end row nasabah -->
        <?php } ?>
    </section>
</div>

<!-- Tambahkan Chart.js -->
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
    // Grafik Transaksi
    const ctx1 = document.getElementById('transaksiChart').getContext('2d');
    const transaksiChart = new Chart(ctx1, {
        type: 'bar',
        data: {
            labels: ['Total Masuk', 'Total Keluar', 'Sisa Saldo'],
            datasets: [{
                label: 'Jumlah (Rp)',
                data: [
                    <?= $saldo_detail['totalMasuk'] ?>,
                    <?= $saldo_detail['totalKeluar'] ?>,
                    <?= $saldo_detail['sisaSaldo'] ?>
                ],
                backgroundColor: [
                    'rgba(40, 167, 69, 0.7)',
                    'rgba(220, 53, 69, 0.7)',
                    'rgba(255, 193, 7, 0.7)'
                ],
                borderColor: [
                    'rgba(40, 167, 69, 1)',
                    'rgba(220, 53, 69, 1)',
                    'rgba(255, 193, 7, 1)'
                ],
                borderWidth: 1,
                borderRadius: 5, // sudut bar melengkung
                barPercentage: 1,
                categoryPercentage: 0.6
            }]
        },
        options: { 
            responsive: true, 
            maintainAspectRatio: false,
            plugins: { 
                legend: { display:false },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            let value = context.raw || 0;
                            return 'Rp ' + value.toLocaleString('id-ID');
                        }
                    }
                }
            }, 
            scales: { 
                y: { 
                    beginAtZero: true,
                    ticks: {
                        callback: function(value) {
                            return 'Rp ' + value.toLocaleString('id-ID');
                        }
                    }
                } 
            } 
        }
    });

        
    // Grafik Nasabah
        const ctx2 = document.getElementById('nasabahChart').getContext('2d');
        const nasabahChart = new Chart(ctx2, {
            type: 'doughnut',
            data: {
                labels: ['Laki-Laki', 'Perempuan'],
                datasets: [{
                    data: [
                        <?= $this->db->query('SELECT id FROM tb_user WHERE jenisKelamin="Laki-Laki" AND level="Nasabah"')->num_rows(); ?>,
                        <?= $this->db->query('SELECT id FROM tb_user WHERE jenisKelamin="Perempuan" AND level="Nasabah"')->num_rows(); ?>
                    ],
                    backgroundColor: [
                        'rgba(0, 123, 255, 0.7)',
                        'rgba(255, 193, 7, 0.7)'
                    ],
                    borderColor: [
                        'rgba(0, 123, 255, 1)',
                        'rgba(255, 193, 7, 1)'
                    ],
                    borderWidth: 1,
                    borderRadius: 5 // <<-- bikin potongan donut lebih "rounded"
                }]
            },
            options: { 
                responsive: true, 
                maintainAspectRatio: false,
                plugins: { legend: { position:'bottom' } } 
            }
        });


    // Grafik Bulanan
    const ctx3 = document.getElementById('bulananChart').getContext('2d');
    const bulananChart = new Chart(ctx3, {
        type: 'line',
        data: {
            labels: <?= $bulan ?>, // array bulan dari PHP
            datasets: [
                {
                    label: 'Total Masuk',
                    data: <?= $masuk ?>,
                    borderColor: 'rgba(40, 167, 69, 1)',
                    backgroundColor: 'rgba(40, 167, 69, 0.2)',
                    borderWidth: 2,
                    tension: 0.4,
                    pointBackgroundColor: 'rgba(40, 167, 69, 1)',
                    pointRadius: 4,
                    fill: true
                },
                {
                    label: 'Total Keluar',
                    data: <?= $keluar ?>,
                    borderColor: 'rgba(220, 53, 69, 1)',
                    backgroundColor: 'rgba(220, 53, 69, 0.2)',
                    borderWidth: 2,
                    tension: 0.4,
                    pointBackgroundColor: 'rgba(220, 53, 69, 1)',
                    pointRadius: 4,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
                mode: 'index',
                intersect: false
            },
            plugins: {
                legend: { position: 'bottom' },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            let value = context.raw || 0;
                            return context.dataset.label + ': Rp ' + value.toLocaleString('id-ID');
                        }
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        callback: function(value) {
                            return 'Rp ' + value.toLocaleString('id-ID');
                        }
                    }
                },
                x: {
                    grid: { display: false }
                }
            }
        }
    });
</script>