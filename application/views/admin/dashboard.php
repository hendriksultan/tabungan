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

            .dashboard-metrics {
                display: grid;
                grid-template-columns: repeat(3, minmax(0, 1fr));
                grid-auto-rows: 1fr;
                gap: 16px;
                margin: 0 0 20px;
            }

            .dashboard-metrics > div {
                width: auto;
                min-width: 0;
                padding: 0;
            }

            .dashboard-metric-card {
                position: relative;
                display: flex;
                box-sizing: border-box;
                min-height: 136px;
                height: 100%;
                padding: 16px;
                border-radius: 8px;
                color: #fff;
                box-shadow: 0 2px 6px rgba(24, 39, 58, .1);
            }

            .dashboard-metric-card.metric-green { background: linear-gradient(45deg, #168541, #4dce7a); }
            .dashboard-metric-card.metric-red { background: linear-gradient(45deg, #bd2d3d, #f26877); }
            .dashboard-metric-card.metric-orange { background: linear-gradient(45deg, #db7006, #f8ad50); }
            .dashboard-metric-card.metric-purple { background: linear-gradient(45deg, #6540a7, #ac82e3); }
            .dashboard-metric-card.metric-blue { background: linear-gradient(45deg, #226aa9, #59a9e3); }

            .dashboard-metric-icon {
                position: absolute;
                top: 50%;
                right: 20px;
                width: 56px;
                height: 56px;
                transform: translateY(-50%);
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 52px;
                color: rgba(255, 255, 255, .24);
                pointer-events: none;
            }

            .dashboard-metric-content {
                padding-right: 64px;
                display: flex;
                flex-direction: column;
                flex: 1;
                min-width: 0;
            }

            .dashboard-metric-label {
                display: block;
                font-size: 12px;
                font-weight: 700;
                line-height: 16px;
                text-transform: uppercase;
                color: #fff;
            }

            .dashboard-metric-value {
                display: block;
                margin: 4px 0 8px;
                font-size: 22px;
                font-weight: 700;
                line-height: 28px;
                overflow-wrap: anywhere;
            }

            .dashboard-metric-footer {
                display: flex;
                align-items: flex-end;
                min-height: 36px;
                margin-top: auto;
                font-size: 12px;
                line-height: 18px;
                color: #fff;
            }

            a.dashboard-metric-footer {
                align-self: flex-start;
                gap: 4px;
                text-decoration: none;
            }

            a.dashboard-metric-footer:hover,
            a.dashboard-metric-footer:focus {
                color: #fff;
                text-decoration: underline;
            }

            .dashboard-balance-details {
                display: grid;
                grid-template-columns: repeat(2, minmax(0, 1fr));
                gap: 12px;
                margin-top: auto;
                padding-top: 6px;
                border-top: 1px solid rgba(255, 255, 255, .3);
                font-size: 12px;
                line-height: 18px;
            }

            .dashboard-balance-details > div {
                min-width: 0;
            }

            .dashboard-balance-details span,
            .dashboard-balance-details strong {
                display: block;
                color: #fff;
                overflow-wrap: anywhere;
            }

            @media (max-width: 991px) {
                .dashboard-metrics {
                    grid-template-columns: repeat(2, minmax(0, 1fr));
                }
            }

            @media (max-width: 767px) {
                .dashboard-metrics {
                    grid-template-columns: minmax(0, 1fr);
                    gap: 12px;
                }
            }
        </style>

        <div class="dashboard-scope">
            <i class="fa fa-building"></i>
            Data yang sedang ditampilkan:
            <strong><?= html_escape($nama_scope) ?></strong>
        </div>

        <?php if ($is_pengelola): ?>
            <div class="dashboard-metrics">
                <div class="dashboard-metric-column">
                    <div class="dashboard-metric-card metric-green">
                        <span class="dashboard-metric-icon">
                            <i class="fa fa-level-down"></i>
                        </span>

                        <div class="dashboard-metric-content">
                            <span class="dashboard-metric-label">
                                Total Masuk
                            </span>

                            <span class="dashboard-metric-value">
                                Rp
                                <?= number_format(
                                    $saldo_detail['totalMasuk'],
                                    0,
                                    ',',
                                    '.'
                                ) ?>
                            </span>

                            <span class="dashboard-metric-footer">
                                Transaksi dan transfer masuk
                            </span>
                        </div>
                    </div>
                </div>

                <div class="dashboard-metric-column">
                    <div class="dashboard-metric-card metric-red">
                        <span class="dashboard-metric-icon">
                            <i class="fa fa-level-up"></i>
                        </span>

                        <div class="dashboard-metric-content">
                            <span class="dashboard-metric-label">
                                Total Keluar
                            </span>

                            <span class="dashboard-metric-value">
                                Rp
                                <?= number_format(
                                    $saldo_detail['totalKeluar'],
                                    0,
                                    ',',
                                    '.'
                                ) ?>
                            </span>

                            <span class="dashboard-metric-footer">
                                Transaksi dan transfer keluar
                            </span>
                        </div>
                    </div>
                </div>
                <div class="dashboard-metric-column">
                    <div class="dashboard-metric-card metric-orange">
                        <span class="dashboard-metric-icon">
                            <i class="fa fa-money"></i>
                        </span>

                        <div class="dashboard-metric-content">
                            <span class="dashboard-metric-label">
                                Saldo Kelolaan
                            </span>

                            <span class="dashboard-metric-value">
                                Rp
                                <?= number_format(
                                    $saldo_detail['sisaSaldo'],
                                    0,
                                    ',',
                                    '.'
                                ) ?>
                            </span>

                            <div class="dashboard-balance-details">
                                <div>
                                    <span>Tabungan</span>
                                    <strong>Rp <?= number_format($saldo_detail['saldoTabungan'], 0, ',', '.') ?></strong>
                                </div>
                                <div>
                                    <span>Celengan</span>
                                    <strong>Rp <?= number_format($saldo_detail['saldoCelengan'], 0, ',', '.') ?></strong>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="dashboard-metric-column">
                    <div class="dashboard-metric-card metric-red">
                        <span class="dashboard-metric-icon">
                            <i class="fa fa-book"></i>
                        </span>

                        <div class="dashboard-metric-content">
                            <span class="dashboard-metric-label">
                                Total Transaksi
                            </span>

                            <span class="dashboard-metric-value">
                                <?= number_format($total_transaksi) ?>
                            </span>

                            <a
                                href="<?= base_url('admin/transaksi') ?>"
                                class="dashboard-metric-footer">
                                Lihat transaksi
                                <i class="fa fa-arrow-circle-right"></i>
                            </a>
                        </div>
                    </div>
                </div>

                <div class="dashboard-metric-column">
                    <div class="dashboard-metric-card metric-purple">
                        <span class="dashboard-metric-icon">
                            <i class="fa fa-send"></i>
                        </span>

                        <div class="dashboard-metric-content">
                            <span class="dashboard-metric-label">
                                Total Transfer
                            </span>

                            <span class="dashboard-metric-value">
                                <?= number_format($total_transfer) ?>
                            </span>

                            <a
                                href="<?= base_url('admin/transfer') ?>"
                                class="dashboard-metric-footer">
                                Lihat transfer
                                <i class="fa fa-arrow-circle-right"></i>
                            </a>
                        </div>
                    </div>
                </div>

                <div class="dashboard-metric-column">
                    <div class="dashboard-metric-card metric-blue">
                        <span class="dashboard-metric-icon">
                            <i class="fa fa-users"></i>
                        </span>

                        <div class="dashboard-metric-content">
                            <span class="dashboard-metric-label">
                                Total Nasabah
                            </span>

                            <span class="dashboard-metric-value">
                                <?= number_format($total_nasabah) ?>
                            </span>

                            <?php if (!empty($is_koordinator)): ?>
                                <span class="dashboard-metric-footer">
                                    Dalam cakupan audit
                                </span>
                            <?php else: ?>
                                <a
                                    href="<?= base_url('admin/user') ?>"
                                    class="dashboard-metric-footer">
                                    Lihat nasabah
                                    <i class="fa fa-arrow-circle-right"></i>
                                </a>
                            <?php endif; ?>
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
