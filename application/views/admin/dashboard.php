<div class="content-wrapper">
    <section class="content-header">
        <h1>
            <?= html_escape($title) ?>
            <small><?= html_escape($subtitle) ?></small>
        </h1>

        <ol class="breadcrumb">
            <li class="active">
                <i class="fa fa-dashboard"></i> Dashboard
            </li>
        </ol>
    </section>

    <section class="content">
        <style>
            .dashboard-scope {
                background: #ffffff;
                border-left: 4px solid #3c8dbc;
                border-radius: 4px;
                padding: 12px 15px;
                margin-bottom: 20px;
                box-shadow: 0 1px 3px rgba(0, 0, 0, .08);
            }

            .dashboard-scope strong {
                color: #3c8dbc;
            }

            .info-box {
                border-radius: 5px;
                box-shadow: 0 4px 8px rgba(0, 0, 0, .1);
                transition: transform .2s, box-shadow .2s;
            }

            .info-box:hover {
                transform: translateY(-3px);
                box-shadow: 0 7px 14px rgba(0, 0, 0, .15);
            }

            .bg-green {
                background: linear-gradient(45deg, #28a745, #71dd8a);
            }

            .bg-red {
                background: linear-gradient(45deg, #dc3545, #ff7b7b);
            }

            .bg-orange {
                background: linear-gradient(45deg, #fd7e14, #ffb366);
            }

            .bg-blue {
                background: linear-gradient(45deg, #007bff, #66b0ff);
            }

            .bg-purple {
                background: linear-gradient(45deg, #6f42c1, #b18eff);
            }

            .dashboard-card {
                background: #ffffff;
                border-radius: 5px;
                padding: 20px;
                margin-bottom: 20px;
                box-shadow: 0 4px 10px rgba(0, 0, 0, .1);
            }

            .dashboard-card h4 {
                margin-top: 0;
                margin-bottom: 18px;
                font-weight: 600;
            }

            .dashboard-card canvas {
                width: 100% !important;
                height: 280px !important;
            }

            .info-box-number {
                white-space: normal;
            }
        </style>

        <div class="dashboard-scope">
            <i class="fa fa-building"></i>
            Data yang sedang ditampilkan:
            <strong><?= html_escape($nama_scope) ?></strong>
        </div>

        <?php if ($is_pengelola): ?>
            <div class="row">
                <div class="col-md-4 col-sm-6 col-xs-12">
                    <div class="info-box bg-green">
                        <span class="info-box-icon">
                            <i class="fa fa-level-down"></i>
                        </span>

                        <div class="info-box-content">
                            <span class="info-box-text">
                                Total Masuk
                            </span>

                            <span class="info-box-number">
                                Rp
                                <?= number_format(
                                    $saldo_detail['totalMasuk'],
                                    0,
                                    ',',
                                    '.'
                                ) ?>
                            </span>

                            <span class="progress-description">
                                Transaksi dan transfer masuk
                            </span>
                        </div>
                    </div>
                </div>

                <div class="col-md-4 col-sm-6 col-xs-12">
                    <div class="info-box bg-red">
                        <span class="info-box-icon">
                            <i class="fa fa-level-up"></i>
                        </span>

                        <div class="info-box-content">
                            <span class="info-box-text">
                                Total Keluar
                            </span>

                            <span class="info-box-number">
                                Rp
                                <?= number_format(
                                    $saldo_detail['totalKeluar'],
                                    0,
                                    ',',
                                    '.'
                                ) ?>
                            </span>

                            <span class="progress-description">
                                Transaksi dan transfer keluar
                            </span>
                        </div>
                    </div>
                </div>

                <div class="col-md-4 col-sm-6 col-xs-12">
                    <div class="info-box bg-orange">
                        <span class="info-box-icon">
                            <i class="fa fa-money"></i>
                        </span>

                        <div class="info-box-content">
                            <span class="info-box-text">
                                Saldo Kelolaan
                            </span>

                            <span class="info-box-number">
                                Rp
                                <?= number_format(
                                    $saldo_detail['sisaSaldo'],
                                    0,
                                    ',',
                                    '.'
                                ) ?>
                            </span>

                            <span class="progress-description">
                                Saldo termasuk celengan impian
                            </span>
                        </div>
                    </div>
                </div>

                <div class="col-md-4 col-sm-6 col-xs-12">
                    <div class="info-box bg-red">
                        <span class="info-box-icon">
                            <i class="fa fa-book"></i>
                        </span>

                        <div class="info-box-content">
                            <span class="info-box-text">
                                Total Transaksi
                            </span>

                            <span class="info-box-number">
                                <?= number_format($total_transaksi) ?>
                            </span>

                            <a
                                href="<?= base_url('admin/transaksi') ?>"
                                class="progress-description"
                                style="color:#fff;">
                                Lihat transaksi
                                <i class="fa fa-arrow-circle-right"></i>
                            </a>
                        </div>
                    </div>
                </div>

                <div class="col-md-4 col-sm-6 col-xs-12">
                    <div class="info-box bg-purple">
                        <span class="info-box-icon">
                            <i class="fa fa-send"></i>
                        </span>

                        <div class="info-box-content">
                            <span class="info-box-text">
                                Total Transfer
                            </span>

                            <span class="info-box-number">
                                <?= number_format($total_transfer) ?>
                            </span>

                            <a
                                href="<?= base_url('admin/transfer') ?>"
                                class="progress-description"
                                style="color:#fff;">
                                Lihat transfer
                                <i class="fa fa-arrow-circle-right"></i>
                            </a>
                        </div>
                    </div>
                </div>

                <div class="col-md-4 col-sm-6 col-xs-12">
                    <div class="info-box bg-blue">
                        <span class="info-box-icon">
                            <i class="fa fa-users"></i>
                        </span>

                        <div class="info-box-content">
                            <span class="info-box-text">
                                Total Nasabah
                            </span>

                            <span class="info-box-number">
                                <?= number_format($total_nasabah) ?>
                            </span>

                            <a
                                href="<?= base_url('admin/user') ?>"
                                class="progress-description"
                                style="color:#fff;">
                                Lihat nasabah
                                <i class="fa fa-arrow-circle-right"></i>
                            </a>
                        </div>
                    </div>
                </div>
            </div>

            <div class="row">
                <div class="col-md-6">
                    <div class="dashboard-card">
                        <h4>Ringkasan Keuangan</h4>
                        <canvas id="transaksiChart"></canvas>
                    </div>
                </div>

                <div class="col-md-6">
                    <div class="dashboard-card">
                        <h4>Komposisi Nasabah</h4>
                        <canvas id="nasabahChart"></canvas>
                    </div>
                </div>
            </div>

            <div class="dashboard-card">
                <h4>
                    Transaksi Bulanan Tahun <?= date('Y') ?>
                </h4>

                <canvas id="bulananChart"></canvas>
            </div>
        <?php else: ?>
            <div class="row">
                <div class="col-md-4 col-sm-6 col-xs-12">
                    <div class="info-box bg-red">
                        <span class="info-box-icon">
                            <i class="fa fa-book"></i>
                        </span>

                        <div class="info-box-content">
                            <span class="info-box-text">
                                Transaksi Saya
                            </span>

                            <span class="info-box-number">
                                <?= number_format(
                                    $total_transaksi_saya
                                ) ?>
                            </span>

                            <a
                                href="<?= base_url('admin/transaksi') ?>"
                                class="progress-description"
                                style="color:#fff;">
                                Lihat transaksi
                            </a>
                        </div>
                    </div>
                </div>

                <div class="col-md-4 col-sm-6 col-xs-12">
                    <div class="info-box bg-blue">
                        <span class="info-box-icon">
                            <i class="fa fa-send"></i>
                        </span>

                        <div class="info-box-content">
                            <span class="info-box-text">
                                Transfer Saya
                            </span>

                            <span class="info-box-number">
                                <?= number_format(
                                    $total_transfer_saya
                                ) ?>
                            </span>

                            <a
                                href="<?= base_url('admin/transfer') ?>"
                                class="progress-description"
                                style="color:#fff;">
                                Lihat transfer
                            </a>
                        </div>
                    </div>
                </div>

                <div class="col-md-4 col-sm-6 col-xs-12">
                    <div class="info-box bg-green">
                        <span class="info-box-icon">
                            <i class="fa fa-money"></i>
                        </span>

                        <div class="info-box-content">
                            <span class="info-box-text">
                                Sisa Saldo
                            </span>

                            <span class="info-box-number">
                                Rp
                                <?= number_format(
                                    $saldo_nasabah,
                                    0,
                                    ',',
                                    '.'
                                ) ?>
                            </span>

                            <a
                                href="<?= base_url('admin/transaksi') ?>"
                                class="progress-description"
                                style="color:#fff;">
                                Lihat rincian saldo
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        <?php endif; ?>
    </section>
</div>

<?php if ($is_pengelola): ?>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

    <script>
        const transaksiChart = new Chart(
            document.getElementById('transaksiChart'), {
                type: 'bar',
                data: {
                    labels: [
                        'Total Masuk',
                        'Total Keluar',
                        'Saldo Kelolaan'
                    ],
                    datasets: [{
                        data: [
                            <?= (float) $saldo_detail['totalMasuk'] ?>,
                            <?= (float) $saldo_detail['totalKeluar'] ?>,
                            <?= (float) $saldo_detail['sisaSaldo'] ?>
                        ],
                        backgroundColor: [
                            'rgba(40, 167, 69, .75)',
                            'rgba(220, 53, 69, .75)',
                            'rgba(253, 126, 20, .75)'
                        ],
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            display: false
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            }
        );

        const nasabahChart = new Chart(
            document.getElementById('nasabahChart'), {
                type: 'doughnut',
                data: {
                    labels: ['Laki-Laki', 'Perempuan'],
                    datasets: [{
                        data: [
                            <?= (int) $nasabah_laki ?>,
                            <?= (int) $nasabah_perempuan ?>
                        ],
                        backgroundColor: [
                            'rgba(0, 123, 255, .75)',
                            'rgba(255, 193, 7, .75)'
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom'
                        }
                    }
                }
            }
        );

        const bulananChart = new Chart(
            document.getElementById('bulananChart'), {
                type: 'line',
                data: {
                    labels: <?= $bulan ?>,
                    datasets: [{
                            label: 'Total Masuk',
                            data: <?= $masuk ?>,
                            borderColor: '#28a745',
                            backgroundColor: 'rgba(40,167,69,.15)',
                            fill: true,
                            tension: .35
                        },
                        {
                            label: 'Total Keluar',
                            data: <?= $keluar ?>,
                            borderColor: '#dc3545',
                            backgroundColor: 'rgba(220,53,69,.12)',
                            fill: true,
                            tension: .35
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
                        legend: {
                            position: 'bottom'
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            }
        );
    </script>
<?php endif; ?>