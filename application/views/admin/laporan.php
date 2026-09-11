<?php
$formatRupiah = function ($nominal) {
    return 'Rp ' . number_format((float) $nominal, 0, ',', '.');
};
?>

<div class="content-wrapper laporan-page">
    <section class="content-header no-print">
        <h1>
            <?= html_escape($title) ?>
            <small><?= html_escape($subtitle) ?></small>
        </h1>

        <ol class="breadcrumb">
            <li>
                <a href="<?= base_url('admin/dashboard') ?>">
                    <i class="fa fa-dashboard"></i> Dashboard
                </a>
            </li>
            <li class="active">Laporan</li>
        </ol>
    </section>

    <section class="content">
        <style>
            .laporan-scope {
                background: #fff;
                border-left: 4px solid #3c8dbc;
                border-radius: 4px;
                padding: 12px 15px;
                margin-bottom: 18px;
                box-shadow: 0 1px 3px rgba(0, 0, 0, .08);
            }

            .laporan-scope strong {
                color: #3c8dbc;
            }

            .laporan-filter {
                border-top: 3px solid #3c8dbc;
            }

            .laporan-card {
                color: #fff;
                border-radius: 6px;
                min-height: 118px;
                padding: 18px;
                margin-bottom: 20px;
                box-shadow: 0 4px 10px rgba(0, 0, 0, .12);
                position: relative;
                overflow: hidden;
            }

            .laporan-card.masuk {
                background: linear-gradient(45deg, #168a45, #54cf7b);
            }

            .laporan-card.keluar {
                background: linear-gradient(45deg, #be2f3e, #f36c78);
            }

            .laporan-card.saldo {
                background: linear-gradient(45deg, #d66b0a, #f6ad55);
            }

            .laporan-card.aktivitas {
                background: linear-gradient(45deg, #2367a5, #5aa9e6);
            }

            .laporan-card .card-title {
                text-transform: uppercase;
                font-size: 12px;
                font-weight: 700;
                letter-spacing: .4px;
                opacity: .92;
            }

            .laporan-card .card-value {
                font-size: 23px;
                line-height: 1.25;
                font-weight: 700;
                margin: 7px 0;
                padding-right: 45px;
            }

            .laporan-card .card-detail {
                font-size: 12px;
                opacity: .92;
            }

            .laporan-card .card-icon {
                position: absolute;
                right: 15px;
                top: 30px;
                font-size: 48px;
                opacity: .22;
            }

            .laporan-section-title {
                font-weight: 700;
                margin: 0;
            }

            .laporan-meta {
                margin: 0 0 18px;
                padding: 0;
                list-style: none;
            }

            .laporan-meta li {
                margin-bottom: 4px;
            }

            .table > thead > tr > th {
                white-space: nowrap;
            }

            .nilai-masuk {
                color: #168a45;
                font-weight: 700;
                white-space: nowrap;
            }

            .nilai-keluar {
                color: #be2f3e;
                font-weight: 700;
                white-space: nowrap;
            }

            .print-header {
                display: none;
            }

            @media (max-width: 767px) {
                .laporan-filter .btn {
                    display: block;
                    width: 100%;
                    margin: 6px 0 0;
                }

                .laporan-card .card-value {
                    font-size: 20px;
                }
            }

            @media print {
                @page {
                    size: A4 landscape;
                    margin: 10mm;
                }

                .main-header,
                .main-sidebar,
                .control-sidebar,
                .main-footer,
                .no-print,
                .dataTables_length,
                .dataTables_filter,
                .dataTables_info,
                .dataTables_paginate {
                    display: none !important;
                }

                .content-wrapper,
                .laporan-page {
                    margin-left: 0 !important;
                    min-height: 0 !important;
                    background: #fff !important;
                }

                .content {
                    padding: 0 !important;
                }

                .print-header {
                    display: block;
                    margin-bottom: 20px;
                }

                .box,
                .laporan-card,
                .laporan-scope {
                    box-shadow: none !important;
                    break-inside: avoid;
                }

                .laporan-card {
                    border: 1px solid #ddd;
                    color: #222 !important;
                    background: #fff !important;
                    min-height: 95px;
                }

                .laporan-card .card-icon {
                    display: none;
                }

                .table {
                    width: 100% !important;
                    max-width: 100% !important;
                    table-layout: fixed;
                    font-size: 8px;
                }

                .table-responsive,
                .dataTables_wrapper,
                .dataTables_scroll,
                .dataTables_scrollBody {
                    width: 100% !important;
                    max-width: 100% !important;
                    overflow: visible !important;
                }

                .table > thead > tr > th,
                .table > tbody > tr > td {
                    padding: 4px !important;
                    white-space: normal !important;
                    overflow-wrap: anywhere;
                    word-break: normal;
                }

                .laporan-table-transfer {
                    font-size: 7px;
                }

                .laporan-table-transfer th:nth-child(1),
                .laporan-table-transfer td:nth-child(1) {
                    width: 4%;
                }

                .laporan-table-transfer th:nth-child(2),
                .laporan-table-transfer td:nth-child(2) {
                    width: 10%;
                }

                .laporan-table-transfer th:nth-child(7),
                .laporan-table-transfer td:nth-child(7) {
                    width: 7%;
                }

                .laporan-table-transfer th:nth-child(8),
                .laporan-table-transfer td:nth-child(8),
                .laporan-table-transfer th:nth-child(9),
                .laporan-table-transfer td:nth-child(9) {
                    width: 8%;
                }

                a[href]:after {
                    content: none !important;
                }
            }
        </style>

        <div class="print-header">
            <h3><strong>LAPORAN KEUANGAN INTI</strong></h3>
            <ul class="laporan-meta">
                <li>
                    Periode:
                    <strong>
                        <?= date('d-m-Y', strtotime($filter['dari'])) ?>
                        s/d
                        <?= date('d-m-Y', strtotime($filter['sampai'])) ?>
                    </strong>
                </li>
                <li>
                    Cakupan:
                    <strong><?= html_escape($namaScope) ?></strong>
                </li>
                <li>
                    Dicetak oleh:
                    <strong>
                        <?= html_escape($this->session->userdata('nama')) ?>
                    </strong>
                    pada <?= date('d-m-Y H:i:s') ?>
                </li>
            </ul>
        </div>

        <div class="laporan-scope">
            <i class="fa fa-building"></i>
            Data yang sedang ditampilkan:
            <strong><?= html_escape($namaScope) ?></strong>
            &nbsp;•&nbsp;
            Periode
            <strong>
                <?= date('d-m-Y', strtotime($filter['dari'])) ?>
                s/d
                <?= date('d-m-Y', strtotime($filter['sampai'])) ?>
            </strong>
        </div>

        <div class="box laporan-filter no-print">
            <div class="box-header with-border">
                <h3 class="box-title">
                    <i class="fa fa-filter"></i> Filter Laporan
                </h3>
            </div>

            <form method="get" action="<?= base_url('admin/laporan') ?>">
                <div class="box-body">
                    <div class="row">
                        <div class="col-md-3 col-sm-6">
                            <div class="form-group">
                                <label>Dari tanggal</label>
                                <input
                                    type="date"
                                    name="dari"
                                    class="form-control"
                                    value="<?= html_escape($filter['dari']) ?>"
                                    required>
                            </div>
                        </div>

                        <div class="col-md-3 col-sm-6">
                            <div class="form-group">
                                <label>Sampai tanggal</label>
                                <input
                                    type="date"
                                    name="sampai"
                                    class="form-control"
                                    value="<?= html_escape($filter['sampai']) ?>"
                                    required>
                            </div>
                        </div>

                        <?php if ($isSuperAdmin): ?>
                            <div class="col-md-3 col-sm-6">
                                <div class="form-group">
                                    <label>Cabang</label>
                                    <select
                                        name="cabang_id"
                                        class="form-control select2"
                                        style="width:100%;">
                                        <option value="all">
                                            Seluruh Cabang
                                        </option>

                                        <?php foreach ($cabang as $item): ?>
                                            <option
                                                value="<?= (int) $item['id'] ?>"
                                                <?= (int) $filter['cabang_id'] ===
                                                    (int) $item['id']
                                                    ? 'selected'
                                                    : '' ?>>
                                                <?= html_escape(
                                                    $item['nama'] .
                                                    ' (' . $item['kode'] . ')' .
                                                    ($item['status'] === 'Aktif'
                                                        ? ''
                                                        : ' — Nonaktif')
                                                ) ?>
                                            </option>
                                        <?php endforeach; ?>
                                    </select>
                                </div>
                            </div>
                        <?php endif; ?>

                        <div class="col-md-3 col-sm-6">
                            <div class="form-group">
                                <label>&nbsp;</label>
                                <div>
                                    <button type="submit" class="btn btn-primary">
                                        <i class="fa fa-search"></i> Tampilkan
                                    </button>

                                    <a
                                        href="<?= base_url('admin/laporan') ?>"
                                        class="btn btn-default">
                                        <i class="fa fa-refresh"></i> Reset
                                    </a>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="box-footer">
                    <button
                        type="button"
                        class="btn btn-warning"
                        onclick="cetakLaporanLengkap()">
                        <i class="fa fa-print"></i> Cetak
                    </button>

                    <a
                        href="<?= base_url(
                            'admin/laporan/export_excel?' . $queryExport
                        ) ?>"
                        class="btn btn-success">
                        <i class="fa fa-file-excel-o"></i> Export Excel
                    </a>

                    <a
                        href="<?= base_url(
                            'admin/laporan/export_csv?' . $queryExport
                        ) ?>"
                        class="btn btn-info">
                        <i class="fa fa-file-text-o"></i> Export CSV
                    </a>
                </div>
            </form>
        </div>

        <div class="row">
            <div class="col-lg-3 col-sm-6 col-xs-12">
                <div class="laporan-card masuk">
                    <div class="card-title">Total Masuk</div>
                    <div class="card-value">
                        <?= $formatRupiah($ringkasan['total_masuk']) ?>
                    </div>
                    <div class="card-detail">
                        Transaksi <?= $formatRupiah(
                            $ringkasan['transaksi_masuk']
                        ) ?> • Transfer <?= $formatRupiah(
                            $ringkasan['transfer_masuk']
                        ) ?>
                    </div>
                    <i class="fa fa-arrow-down card-icon"></i>
                </div>
            </div>

            <div class="col-lg-3 col-sm-6 col-xs-12">
                <div class="laporan-card keluar">
                    <div class="card-title">Total Keluar</div>
                    <div class="card-value">
                        <?= $formatRupiah($ringkasan['total_keluar']) ?>
                    </div>
                    <div class="card-detail">
                        Transaksi <?= $formatRupiah(
                            $ringkasan['transaksi_keluar']
                        ) ?> • Transfer <?= $formatRupiah(
                            $ringkasan['transfer_keluar']
                        ) ?>
                    </div>
                    <i class="fa fa-arrow-up card-icon"></i>
                </div>
            </div>

            <div class="col-lg-3 col-sm-6 col-xs-12">
                <div class="laporan-card saldo">
                    <div class="card-title">Saldo Bersih Periode</div>
                    <div class="card-value">
                        <?= $formatRupiah($ringkasan['saldo_bersih']) ?>
                    </div>
                    <div class="card-detail">
                        Total masuk dikurangi total keluar
                    </div>
                    <i class="fa fa-money card-icon"></i>
                </div>
            </div>

            <div class="col-lg-3 col-sm-6 col-xs-12">
                <div class="laporan-card aktivitas">
                    <div class="card-title">Jumlah Aktivitas</div>
                    <div class="card-value">
                        <?= number_format($ringkasan['jumlah_aktivitas']) ?>
                    </div>
                    <div class="card-detail">
                        <?= number_format($ringkasan['jumlah_transaksi']) ?>
                        transaksi •
                        <?= number_format($ringkasan['jumlah_transfer']) ?>
                        transfer
                    </div>
                    <i class="fa fa-exchange card-icon"></i>
                </div>
            </div>
        </div>

        <div class="box box-primary">
            <div class="box-header with-border">
                <h3 class="box-title laporan-section-title">
                    <i class="fa fa-book"></i>
                    Rincian Transaksi Tabungan
                </h3>
            </div>

            <div class="box-body">
                <div class="table-responsive">
                    <table
                        class="table table-bordered table-striped table-hover dataTable laporan-table-transaksi">
                        <thead>
                            <tr>
                                <th>No.</th>
                                <th>Tanggal</th>
                                <th>Nasabah</th>
                                <th>Cabang</th>
                                <th>Masuk</th>
                                <th>Keluar</th>
                                <th>Keterangan</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($transaksi as $index => $row): ?>
                                <tr>
                                    <td><?= $index + 1 ?></td>
                                    <td>
                                        <?= date(
                                            'd-m-Y',
                                            strtotime($row['tanggal'])
                                        ) ?>
                                    </td>
                                    <td><?= html_escape($row['nama_nasabah']) ?></td>
                                    <td>
                                        <?= html_escape($row['nama_cabang']) ?>
                                        <br>
                                        <span class="label label-info">
                                            <?= html_escape($row['kode_cabang']) ?>
                                        </span>
                                    </td>
                                    <td class="nilai-masuk">
                                        <?= $row['jenis'] === 'Masuk'
                                            ? $formatRupiah($row['nominal'])
                                            : '' ?>
                                    </td>
                                    <td class="nilai-keluar">
                                        <?= $row['jenis'] === 'Keluar'
                                            ? $formatRupiah($row['nominal'])
                                            : '' ?>
                                    </td>
                                    <td><?= html_escape($row['keterangan']) ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <div class="box box-info">
            <div class="box-header with-border">
                <h3 class="box-title laporan-section-title">
                    <i class="fa fa-send"></i>
                    Rincian Transfer
                </h3>
            </div>

            <div class="box-body">
                <div class="table-responsive">
                    <table
                        class="table table-bordered table-striped table-hover dataTable laporan-table-transfer">
                        <thead>
                            <tr>
                                <th>No.</th>
                                <th>Waktu</th>
                                <th>Pengirim</th>
                                <th>Penerima</th>
                                <th>Cabang Asal</th>
                                <th>Cabang Tujuan</th>
                                <th>Arah</th>
                                <th>Masuk</th>
                                <th>Keluar</th>
                                <th>Keterangan</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($transfer as $index => $row): ?>
                                <tr>
                                    <td><?= $index + 1 ?></td>
                                    <td>
                                        <?= date(
                                            'd-m-Y H:i',
                                            strtotime($row['terdaftar'])
                                        ) ?>
                                    </td>
                                    <td><?= html_escape($row['nama_pengirim']) ?></td>
                                    <td><?= html_escape($row['nama_penerima']) ?></td>
                                    <td>
                                        <?= html_escape($row['nama_cabang_asal']) ?>
                                        <br>
                                        <span class="label label-default">
                                            <?= html_escape(
                                                $row['kode_cabang_asal']
                                            ) ?>
                                        </span>
                                    </td>
                                    <td>
                                        <?= html_escape($row['nama_cabang_tujuan']) ?>
                                        <br>
                                        <span class="label label-info">
                                            <?= html_escape(
                                                $row['kode_cabang_tujuan']
                                            ) ?>
                                        </span>
                                    </td>
                                    <td>
                                        <span class="label label-primary">
                                            <?= html_escape($row['arah_scope']) ?>
                                        </span>
                                    </td>
                                    <td class="nilai-masuk">
                                        <?= $row['masuk_scope']
                                            ? $formatRupiah($row['nominal'])
                                            : '' ?>
                                    </td>
                                    <td class="nilai-keluar">
                                        <?= $row['keluar_scope']
                                            ? $formatRupiah($row['nominal'])
                                            : '' ?>
                                    </td>
                                    <td><?= html_escape($row['keterangan']) ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </section>
</div>

<script>
    var panjangTabelSebelumCetak = [];

    function cetakLaporanLengkap() {
        panjangTabelSebelumCetak = [];

        $('.dataTable').each(function () {
            if ($.fn.DataTable.isDataTable(this)) {
                var tabel = $(this).DataTable();

                panjangTabelSebelumCetak.push({
                    tabel: tabel,
                    panjang: tabel.page.len()
                });

                tabel.page.len(-1).draw();
            }
        });

        window.setTimeout(function () {
            window.print();
        }, 200);
    }

    window.addEventListener('afterprint', function () {
        panjangTabelSebelumCetak.forEach(function (item) {
            item.tabel.page.len(item.panjang).draw();
        });

        panjangTabelSebelumCetak = [];
    });
</script>
