<?php
defined('BASEPATH') or exit('No direct script access allowed');

class Laporan extends CI_Controller
{
    private $userLevel;
    private $isSuperAdmin = false;
    private $isKoordinator = false;
    private $cabangId = 0;
    private $cabangIds = [];

    public function __construct()
    {
        parent::__construct();

        if (!$this->session->userdata('level')) {
            $this->session->set_flashdata(
                'pesan',
                'Anda harus masuk terlebih dahulu!'
            );

            redirect('home');
            exit;
        }

        $this->userLevel = strtolower(
            trim((string) $this->session->userdata('level'))
        );

        $this->isSuperAdmin = (
            $this->userLevel === 'super admin'
        );
        $this->isKoordinator = (
            $this->userLevel === 'koordinator'
        );

        if (!in_array(
            $this->userLevel,
            ['administrator', 'koordinator', 'super admin'],
            true
        )) {
            $this->session->set_flashdata(
                'pesanError',
                'Akses laporan hanya untuk pengelola yang berwenang!'
            );

            redirect('admin/dashboard');
            exit;
        }

        $this->cabangId = (int) $this->session->userdata(
            'cabang_id'
        );
        $this->cabangIds = $this->cabang_scope->cabangIds();

        if (
            (!$this->isSuperAdmin && !$this->isKoordinator && $this->cabangId <= 0) ||
            ($this->isKoordinator && empty($this->cabangIds))
        ) {
            $this->session->set_flashdata(
                'pesanError',
                'Akun belum terhubung dengan cakupan cabang aktif!'
            );

            redirect('home/logout');
            exit;
        }
    }

    public function index()
    {
        $filter = $this->ambilFilter();
        $transaksi = $this->ambilTransaksi($filter);
        $transfer = $this->ambilTransfer($filter);
        $ringkasan = $this->hitungRingkasan($transaksi, $transfer);

        $data = [
            'title' => 'Laporan Keuangan',
            'subtitle' => $this->isSuperAdmin
                ? 'Laporan transaksi dan transfer seluruh cabang'
                : ($this->isKoordinator
                    ? 'Laporan cabang yang ditugaskan'
                    : 'Laporan transaksi dan transfer cabang Anda'),
            'isSuperAdmin' => $this->isSuperAdmin,
            'canSelectBranch' => $this->isSuperAdmin || $this->isKoordinator,
            'filter' => $filter,
            'ringkasan' => $ringkasan,
            'transaksi' => $transaksi,
            'transfer' => $transfer,
            'cabang' => ($this->isSuperAdmin || $this->isKoordinator)
                ? $this->cabang_scope->cabangOptions()
                : [],
            'namaScope' => $filter['nama_cabang'],
            'queryExport' => http_build_query([
                'dari' => $filter['dari'],
                'sampai' => $filter['sampai'],
                'cabang_id' => $filter['cabang_id'] === null
                    ? 'all'
                    : $filter['cabang_id']
            ])
        ];

        $this->load->view('admin/templates/header', $data);
        $this->load->view('admin/templates/sidebar');
        $this->load->view('admin/laporan', $data);
        $this->load->view('admin/templates/footer');
    }

    public function export_csv()
    {
        $filter = $this->ambilFilter();
        $transaksi = $this->ambilTransaksi($filter);
        $transfer = $this->ambilTransfer($filter);
        $ringkasan = $this->hitungRingkasan($transaksi, $transfer);

        $scopeFile = $filter['cabang_id'] === null
            ? 'semua-cabang'
            : 'cabang-' . $filter['cabang_id'];

        $namaFile = sprintf(
            'laporan-keuangan-%s-%s-%s.csv',
            date('Ymd', strtotime($filter['dari'])),
            date('Ymd', strtotime($filter['sampai'])),
            $scopeFile
        );

        while (ob_get_level() > 0) {
            ob_end_clean();
        }

        header('Content-Type: text/csv; charset=UTF-8');
        header(
            'Content-Disposition: attachment; filename="' .
                $namaFile . '"'
        );
        header('Cache-Control: no-store, no-cache, must-revalidate');

        $output = fopen('php://output', 'w');

        // BOM UTF-8 agar karakter Indonesia terbaca baik di Excel.
        fwrite($output, "\xEF\xBB\xBF");
        fwrite($output, "sep=;\r\n");

        $this->tulisCsv($output, ['LAPORAN KEUANGAN INTI']);
        $this->tulisCsv($output, [
            'Periode',
            $filter['dari'] . ' s/d ' . $filter['sampai']
        ]);
        $this->tulisCsv($output, [
            'Cakupan',
            $filter['nama_cabang']
        ]);
        $this->tulisCsv($output, []);

        $this->tulisCsv($output, ['RINGKASAN']);
        $this->tulisCsv($output, [
            'Arus transaksi masuk',
            $ringkasan['transaksi_masuk']
        ]);
        $this->tulisCsv($output, [
            'Transfer masuk',
            $ringkasan['transfer_masuk']
        ]);
        $this->tulisCsv($output, [
            'Total masuk',
            $ringkasan['total_masuk']
        ]);
        $this->tulisCsv($output, [
            'Arus transaksi keluar',
            $ringkasan['transaksi_keluar']
        ]);
        $this->tulisCsv($output, [
            'Transfer keluar',
            $ringkasan['transfer_keluar']
        ]);
        $this->tulisCsv($output, [
            'Total keluar',
            $ringkasan['total_keluar']
        ]);
        $this->tulisCsv($output, [
            'Saldo bersih periode',
            $ringkasan['saldo_bersih']
        ]);
        $this->tulisCsv($output, [
            'Mutasi target ke saldo utama',
            $ringkasan['mutasi_target_masuk']
        ]);
        $this->tulisCsv($output, [
            'Mutasi saldo utama ke target',
            $ringkasan['mutasi_target_keluar']
        ]);
        $this->tulisCsv($output, [
            'Jumlah aktivitas',
            $ringkasan['jumlah_aktivitas']
        ]);
        $this->tulisCsv($output, []);

        $this->tulisCsv($output, ['RINGKASAN PER JENIS TRANSAKSI']);
        $this->tulisCsv($output, [
            'Kategori',
            'Sifat',
            'Jumlah aktivitas',
            'Masuk',
            'Keluar / Mutasi',
            'Dampak saldo bersih'
        ]);

        foreach ($ringkasan['kategori'] as $kategori) {
            if ($kategori['jumlah'] < 1) {
                continue;
            }

            $this->tulisCsv($output, [
                $kategori['label'],
                $kategori['sifat'],
                $kategori['jumlah'],
                $kategori['masuk'],
                $kategori['keluar'],
                $kategori['dampak_saldo']
            ]);
        }

        $this->tulisCsv($output, []);

        $this->tulisCsv($output, [
            'Sumber',
            'Referensi',
            'Tanggal',
            'Pihak/Nasabah',
            'Cabang Asal',
            'Cabang Tujuan',
            'Kategori',
            'Sifat',
            'Masuk',
            'Keluar',
            'Keterangan'
        ]);

        foreach ($transaksi as $row) {
            $masuk = $row['jenis'] === 'Masuk'
                ? (int) $row['nominal']
                : '';

            $keluar = $row['jenis'] === 'Keluar'
                ? (int) $row['nominal']
                : '';

            $this->tulisCsv($output, [
                'Transaksi tabungan',
                'TRX-' . $row['id'],
                $row['tanggal'],
                $row['nama_nasabah'],
                $row['nama_cabang'],
                $row['nama_cabang'],
                $row['kategori_label'],
                $row['sifat_label'],
                $masuk,
                $keluar,
                $row['keterangan']
            ]);
        }

        foreach ($transfer as $row) {
            $this->tulisCsv($output, [
                'Transfer',
                $row['kode_transfer'] ?: 'TF-' . $row['id'],
                $row['terdaftar'],
                $row['nama_pengirim'] . ' → ' . $row['nama_penerima'],
                $row['nama_cabang_asal'],
                $row['nama_cabang_tujuan'],
                'Transfer Antar Nasabah',
                'Mutasi internal',
                $row['masuk_scope'] ? (int) $row['nominal'] : '',
                $row['keluar_scope'] ? (int) $row['nominal'] : '',
                $row['keterangan']
            ]);
        }

        fclose($output);
        exit;
    }

    public function export_excel()
    {
        if (!class_exists('ZipArchive')) {
            $this->session->set_flashdata(
                'pesanError',
                'Ekstensi ZIP PHP belum aktif sehingga Excel tidak dapat dibuat.'
            );

            redirect('admin/laporan');
            exit;
        }

        $filter = $this->ambilFilter();
        $transaksi = $this->ambilTransaksi($filter);
        $transfer = $this->ambilTransfer($filter);
        $ringkasan = $this->hitungRingkasan($transaksi, $transfer);

        $scopeFile = $filter['cabang_id'] === null
            ? 'semua-cabang'
            : 'cabang-' . $filter['cabang_id'];

        $namaFile = sprintf(
            'laporan-keuangan-%s-%s-%s.xlsx',
            date('Ymd', strtotime($filter['dari'])),
            date('Ymd', strtotime($filter['sampai'])),
            $scopeFile
        );

        $rows = [];
        $rows[] = $this->barisExcel(1, [
            ['A', 'LAPORAN KEUANGAN INTI', 1]
        ], 28);
        $rows[] = $this->barisExcel(2, [
            ['A', 'Periode', 2],
            ['B', $filter['dari'] . ' s/d ' . $filter['sampai'], 0]
        ]);
        $rows[] = $this->barisExcel(3, [
            ['A', 'Cakupan', 2],
            ['B', $filter['nama_cabang'], 0]
        ]);
        $rows[] = $this->barisExcel(4, []);
        $rows[] = $this->barisExcel(5, [
            ['A', 'RINGKASAN', 3]
        ], 22);

        $ringkasanRows = [
            ['Arus transaksi masuk', $ringkasan['transaksi_masuk'], 9],
            ['Transfer masuk', $ringkasan['transfer_masuk'], 9],
            ['Total masuk', $ringkasan['total_masuk'], 9],
            ['Arus transaksi keluar', $ringkasan['transaksi_keluar'], 9],
            ['Transfer keluar', $ringkasan['transfer_keluar'], 9],
            ['Total keluar', $ringkasan['total_keluar'], 9],
            ['Saldo bersih periode', $ringkasan['saldo_bersih'], 9],
            ['Mutasi target ke saldo utama', $ringkasan['mutasi_target_masuk'], 9],
            ['Mutasi saldo utama ke target', $ringkasan['mutasi_target_keluar'], 9],
            ['Jumlah aktivitas', $ringkasan['jumlah_aktivitas'], 10]
        ];

        $nomorBaris = 6;

        foreach ($ringkasanRows as $item) {
            $rows[] = $this->barisExcel($nomorBaris, [
                ['A', $item[0], 8],
                ['B', $item[1], $item[2], true]
            ]);
            $nomorBaris++;
        }

        $rows[] = $this->barisExcel($nomorBaris, []);
        $nomorBaris++;

        $rows[] = $this->barisExcel($nomorBaris, [
            ['A', 'RINGKASAN PER JENIS TRANSAKSI', 3]
        ], 22);
        $nomorBaris++;

        $kategoriHeaders = [
            'A' => 'Kategori',
            'B' => 'Sifat',
            'C' => 'Jumlah Aktivitas',
            'D' => 'Masuk',
            'E' => 'Keluar / Mutasi',
            'F' => 'Dampak Saldo Bersih'
        ];
        $kategoriHeaderCells = [];

        foreach ($kategoriHeaders as $kolom => $label) {
            $kategoriHeaderCells[] = [$kolom, $label, 4];
        }

        $rows[] = $this->barisExcel(
            $nomorBaris,
            $kategoriHeaderCells,
            24
        );
        $nomorBaris++;

        foreach ($ringkasan['kategori'] as $kategori) {
            if ($kategori['jumlah'] < 1) {
                continue;
            }

            $rows[] = $this->barisExcel($nomorBaris, [
                ['A', $kategori['label'], 5],
                ['B', $kategori['sifat'], 5],
                ['C', $kategori['jumlah'], 6, true],
                ['D', $kategori['masuk'], 7, true],
                ['E', $kategori['keluar'], 7, true],
                [
                    'F',
                    $kategori['dampak_saldo'],
                    7,
                    true
                ]
            ]);
            $nomorBaris++;
        }

        $rows[] = $this->barisExcel($nomorBaris, []);
        $nomorBaris++;
        $barisHeader = $nomorBaris;

        $headers = [
            'A' => 'Sumber',
            'B' => 'Referensi',
            'C' => 'Tanggal',
            'D' => 'Pihak/Nasabah',
            'E' => 'Cabang Asal',
            'F' => 'Cabang Tujuan',
            'G' => 'Kategori',
            'H' => 'Sifat',
            'I' => 'Masuk',
            'J' => 'Keluar',
            'K' => 'Keterangan'
        ];

        $headerCells = [];

        foreach ($headers as $kolom => $label) {
            $headerCells[] = [$kolom, $label, 4];
        }

        $rows[] = $this->barisExcel(
            $nomorBaris,
            $headerCells,
            26
        );
        $nomorBaris++;

        foreach ($transaksi as $row) {
            $masuk = $row['jenis'] === 'Masuk'
                ? (int) $row['nominal']
                : null;

            $keluar = $row['jenis'] === 'Keluar'
                ? (int) $row['nominal']
                : null;

            $rows[] = $this->barisExcel($nomorBaris, [
                ['A', 'Transaksi tabungan', 5],
                ['B', 'TRX-' . $row['id'], 5],
                ['C', date('d/m/Y', strtotime($row['tanggal'])), 5],
                ['D', $row['nama_nasabah'], 5],
                ['E', $row['nama_cabang'], 5],
                ['F', $row['nama_cabang'], 5],
                ['G', $row['kategori_label'], 5],
                ['H', $row['sifat_label'], 5],
                ['I', $masuk, 7, true],
                ['J', $keluar, 7, true],
                ['K', $row['keterangan'], 5]
            ]);
            $nomorBaris++;
        }

        foreach ($transfer as $row) {
            $masuk = $row['masuk_scope']
                ? (int) $row['nominal']
                : null;

            $keluar = $row['keluar_scope']
                ? (int) $row['nominal']
                : null;

            $rows[] = $this->barisExcel($nomorBaris, [
                ['A', 'Transfer - ' . $row['arah_scope'], 5],
                [
                    'B',
                    $row['kode_transfer'] ?: 'TF-' . $row['id'],
                    5
                ],
                [
                    'C',
                    date('d/m/Y H:i', strtotime($row['terdaftar'])),
                    5
                ],
                [
                    'D',
                    $row['nama_pengirim'] . ' → ' . $row['nama_penerima'],
                    5
                ],
                ['E', $row['nama_cabang_asal'], 5],
                ['F', $row['nama_cabang_tujuan'], 5],
                ['G', 'Transfer Antar Nasabah', 5],
                ['H', 'Mutasi internal', 5],
                ['I', $masuk, 7, true],
                ['J', $keluar, 7, true],
                ['K', $row['keterangan'], 5]
            ]);
            $nomorBaris++;
        }

        $barisTerakhir = max($barisHeader, $nomorBaris - 1);
        $sheetXml = $this->buatSheetExcel(
            $rows,
            $barisHeader,
            $barisTerakhir
        );

        $tempFile = tempnam(sys_get_temp_dir(), 'laporan_xlsx_');
        $zip = new ZipArchive();
        $dibuka = $zip->open(
            $tempFile,
            ZipArchive::CREATE | ZipArchive::OVERWRITE
        );

        if ($dibuka !== true) {
            @unlink($tempFile);
            show_error('File Excel gagal dibuat.', 500);
            return;
        }

        $zip->addFromString(
            '[Content_Types].xml',
            $this->kontenTipeExcel()
        );
        $zip->addFromString('_rels/.rels', $this->relasiUtamaExcel());
        $zip->addFromString('docProps/app.xml', $this->appExcel());
        $zip->addFromString('docProps/core.xml', $this->coreExcel());
        $zip->addFromString('xl/workbook.xml', $this->workbookExcel());
        $zip->addFromString(
            'xl/_rels/workbook.xml.rels',
            $this->relasiWorkbookExcel()
        );
        $zip->addFromString('xl/styles.xml', $this->styleExcel());
        $zip->addFromString('xl/worksheets/sheet1.xml', $sheetXml);
        $zip->close();

        while (ob_get_level() > 0) {
            ob_end_clean();
        }

        header(
            'Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        );
        header(
            'Content-Disposition: attachment; filename="' .
                $namaFile . '"'
        );
        header('Content-Length: ' . filesize($tempFile));
        header('Cache-Control: no-store, no-cache, must-revalidate');

        readfile($tempFile);
        @unlink($tempFile);
        exit;
    }

    private function ambilFilter()
    {
        $dari = trim((string) $this->input->get('dari', true));
        $sampai = trim((string) $this->input->get('sampai', true));

        if ($dari === '') {
            $dari = date('Y-m-01');
        }

        if ($sampai === '') {
            $sampai = date('Y-m-t');
        }

        if (
            !$this->tanggalValid($dari) ||
            !$this->tanggalValid($sampai) ||
            $dari > $sampai
        ) {
            $this->filterTidakValid('Rentang tanggal tidak valid.');
        }

        $awal = new DateTime($dari);
        $akhir = new DateTime($sampai);

        if ($awal->diff($akhir)->days > 366) {
            $this->filterTidakValid(
                'Rentang laporan maksimal 366 hari.'
            );
        }

        $cabangId = null;
        $namaCabang = $this->isKoordinator
            ? 'Seluruh Cabang Ditugaskan'
            : 'Seluruh Cabang';

        if ($this->isSuperAdmin || $this->isKoordinator) {
            $cabangInput = trim(
                (string) $this->input->get('cabang_id', true)
            );

            if ($cabangInput !== '' && $cabangInput !== 'all') {
                $cabangValid = filter_var(
                    $cabangInput,
                    FILTER_VALIDATE_INT,
                    ['options' => ['min_range' => 1]]
                );

                if ($cabangValid === false) {
                    $this->filterTidakValid('Pilihan cabang tidak valid.');
                }

                if (!$this->cabang_scope->canAccess((int) $cabangValid)) {
                    $this->filterTidakValid(
                        'Cabang berada di luar cakupan penugasan Anda.'
                    );
                }

                $cabang = $this->db
                    ->get_where('tb_cabang', [
                        'id' => (int) $cabangValid
                    ])
                    ->row_array();

                if (!$cabang) {
                    $this->filterTidakValid('Cabang tidak ditemukan.');
                }

                $cabangId = (int) $cabang['id'];
                $namaCabang = $cabang['nama'] .
                    ' (' . $cabang['kode'] . ')';
            }
        } else {
            $cabang = $this->db
                ->get_where('tb_cabang', ['id' => $this->cabangId])
                ->row_array();

            if (!$cabang) {
                $this->filterTidakValid(
                    'Cabang Administrator tidak ditemukan.'
                );
            }

            $cabangId = $this->cabangId;
            $namaCabang = $cabang['nama'] .
                ' (' . $cabang['kode'] . ')';
        }

        return [
            'dari' => $dari,
            'sampai' => $sampai,
            'awal_waktu' => $dari . ' 00:00:00',
            'akhir_waktu' => $sampai . ' 23:59:59',
            'cabang_id' => $cabangId,
            'nama_cabang' => $namaCabang
        ];
    }

    private function hitungRingkasan(array $transaksi, array $transfer)
    {
        $kategori = $this->templateRingkasanKategori();
        $transaksiMasuk = 0;
        $transaksiKeluar = 0;
        $mutasiTargetMasuk = 0;
        $mutasiTargetKeluar = 0;

        foreach ($transaksi as $row) {
            $kategoriKey = $row['kategori_key'];
            $nominal = (float) $row['nominal'];
            $jenis = $row['jenis'];

            if (!isset($kategori[$kategoriKey])) {
                continue;
            }

            $kategori[$kategoriKey]['jumlah']++;

            if ($jenis === 'Masuk') {
                $kategori[$kategoriKey]['masuk'] += $nominal;
            } elseif ($jenis === 'Keluar') {
                $kategori[$kategoriKey]['keluar'] += $nominal;
            }

            if ($kategoriKey === 'target') {
                if ($jenis === 'Masuk') {
                    $mutasiTargetMasuk += $nominal;
                } elseif ($jenis === 'Keluar') {
                    $mutasiTargetKeluar += $nominal;
                }

                // Isi/refund target hanya memindahkan dana antara saldo utama
                // dan tabungan target. Nilainya tidak mengubah dana kelolaan.
                continue;
            }

            if ($jenis === 'Masuk') {
                $transaksiMasuk += $nominal;
            } elseif ($jenis === 'Keluar') {
                $transaksiKeluar += $nominal;
            }
        }

        $transferMasuk = 0;
        $transferKeluar = 0;

        foreach ($transfer as $row) {
            $nominal = (float) $row['nominal'];
            $kategori['transfer']['jumlah']++;

            if (!empty($row['masuk_scope'])) {
                $transferMasuk += $nominal;
                $kategori['transfer']['masuk'] += $nominal;
            }

            if (!empty($row['keluar_scope'])) {
                $transferKeluar += $nominal;
                $kategori['transfer']['keluar'] += $nominal;
            }
        }

        $jumlahTransfer = count($transfer);
        $totalMasuk = $transaksiMasuk + $transferMasuk;
        $totalKeluar = $transaksiKeluar + $transferKeluar;

        foreach ($kategori as $key => &$item) {
            // Tabungan target hanya memindahkan dana dari/ke saldo utama.
            // Nominal mutasinya tetap ditampilkan, tetapi tidak berdampak
            // pada saldo bersih laporan.
            $item['dampak_saldo'] = $key === 'target'
                ? 0
                : $item['masuk'] - $item['keluar'];
        }
        unset($item);

        return [
            'transaksi_masuk' => $transaksiMasuk,
            'transaksi_keluar' => $transaksiKeluar,
            'transfer_masuk' => $transferMasuk,
            'transfer_keluar' => $transferKeluar,
            'mutasi_target_masuk' => $mutasiTargetMasuk,
            'mutasi_target_keluar' => $mutasiTargetKeluar,
            'mutasi_target_total' => (
                $mutasiTargetMasuk + $mutasiTargetKeluar
            ),
            'jumlah_transaksi' => count($transaksi),
            'jumlah_transfer' => $jumlahTransfer,
            'jumlah_aktivitas' => (
                count($transaksi) + $jumlahTransfer
            ),
            'total_masuk' => $totalMasuk,
            'total_keluar' => $totalKeluar,
            'saldo_bersih' => $totalMasuk - $totalKeluar,
            'kategori' => $kategori
        ];
    }

    private function templateRingkasanKategori()
    {
        return [
            'setoran' => $this->buatRingkasanKategori(
                'Setoran Tabungan',
                'Arus dana'
            ),
            'penarikan' => $this->buatRingkasanKategori(
                'Penarikan Tunai',
                'Arus dana'
            ),
            'infaq' => $this->buatRingkasanKategori(
                'Infaq / Sedekah',
                'Arus dana'
            ),
            'target' => $this->buatRingkasanKategori(
                'Tabungan Target',
                'Mutasi internal'
            ),
            'transfer' => $this->buatRingkasanKategori(
                'Transfer Antar Nasabah',
                'Mutasi internal'
            ),
            'emas' => $this->buatRingkasanKategori(
                'Tabungan Emas',
                'Konversi aset'
            ),
            'marketplace' => $this->buatRingkasanKategori(
                'Marketplace',
                'Transaksi usaha'
            ),
            'lainnya' => $this->buatRingkasanKategori(
                'Transaksi Lainnya',
                'Arus dana'
            )
        ];
    }

    private function buatRingkasanKategori($label, $sifat)
    {
        return [
            'label' => $label,
            'sifat' => $sifat,
            'jumlah' => 0,
            'masuk' => 0,
            'keluar' => 0
        ];
    }

    private function ambilTransaksi($filter)
    {
        $this->db->select([
            'tb_transaksi.id',
            'tb_transaksi.tanggal',
            'tb_transaksi.nominal',
            'tb_transaksi.jenis',
            'tb_transaksi.keterangan',
            'tb_transaksi.referensi_tipe',
            'tb_transaksi.terdaftar',
            'tb_user.nama AS nama_nasabah',
            'tb_cabang.kode AS kode_cabang',
            'tb_cabang.nama AS nama_cabang'
        ]);

        $this->db->from('tb_transaksi');
        $this->db->join(
            'tb_user',
            'tb_user.id = tb_transaksi.idNasabah',
            'left'
        );
        $this->db->join(
            'tb_cabang',
            'tb_cabang.id = tb_transaksi.cabang_id',
            'left'
        );
        $this->db->where('tb_transaksi.status_konfirmasi', 'Sukses');
        $this->db->where('tb_transaksi.tanggal >=', $filter['dari']);
        $this->db->where('tb_transaksi.tanggal <=', $filter['sampai']);

        if ($filter['cabang_id'] !== null) {
            $this->db->where(
                'tb_transaksi.cabang_id',
                $filter['cabang_id']
            );
        } elseif ($this->isKoordinator) {
            $this->db->where_in(
                'tb_transaksi.cabang_id',
                $this->cabangIds
            );
        }

        $this->db->order_by('tb_transaksi.tanggal', 'DESC');
        $this->db->order_by('tb_transaksi.id', 'DESC');

        $rows = $this->db->get()->result_array();

        foreach ($rows as &$row) {
            $klasifikasi = $this->klasifikasikanTransaksi($row);
            $row['kategori_key'] = $klasifikasi['key'];
            $row['kategori_label'] = $klasifikasi['label'];
            $row['sifat_label'] = $klasifikasi['sifat'];
            $row['mutasi_internal'] = $klasifikasi['mutasi_internal'];
        }
        unset($row);

        return $rows;
    }

    private function klasifikasikanTransaksi(array $row)
    {
        $jenis = trim((string) ($row['jenis'] ?? ''));
        $referensi = strtolower(trim(
            (string) ($row['referensi_tipe'] ?? '')
        ));
        $keterangan = strtolower(trim(
            (string) ($row['keterangan'] ?? '')
        ));

        if (
            in_array($referensi, [
                'topuptarget',
                'refundtarget',
                'tabungantarget'
            ], true) ||
            $this->teksMengandung($keterangan, [
                'isi tabungan:',
                'isi tabungan target',
                'refund hapus target',
                'refund target',
                'celengan impian'
            ])
        ) {
            return $this->hasilKlasifikasi(
                'target',
                'Tabungan Target',
                'Mutasi internal',
                true
            );
        }

        if (
            in_array($referensi, [
                'pembelianemas',
                'pencairanemas'
            ], true) ||
            $this->teksMengandung($keterangan, [
                'nabung emas',
                'jual emas',
                'tabungan emas'
            ])
        ) {
            return $this->hasilKlasifikasi(
                'emas',
                'Tabungan Emas',
                'Konversi aset'
            );
        }

        if (
            in_array($referensi, [
                'pembayaranpesanan',
                'pencairanpesanan',
                'refundpesanan'
            ], true) ||
            $this->teksMengandung($keterangan, [
                'bayar pesanan',
                'pencairan dana penjualan',
                'refund pembatalan',
                'marketplace'
            ])
        ) {
            return $this->hasilKlasifikasi(
                'marketplace',
                'Marketplace',
                'Transaksi usaha'
            );
        }

        if ($this->teksMengandung($keterangan, ['infaq', 'sedekah'])) {
            return $this->hasilKlasifikasi(
                'infaq',
                'Infaq / Sedekah',
                'Arus dana'
            );
        }

        if ($jenis === 'Masuk') {
            return $this->hasilKlasifikasi(
                'setoran',
                'Setoran Tabungan',
                'Arus dana'
            );
        }

        if ($jenis === 'Keluar') {
            return $this->hasilKlasifikasi(
                'penarikan',
                'Penarikan Tunai',
                'Arus dana'
            );
        }

        return $this->hasilKlasifikasi(
            'lainnya',
            'Transaksi Lainnya',
            'Arus dana'
        );
    }

    private function hasilKlasifikasi(
        $key,
        $label,
        $sifat,
        $mutasiInternal = false
    ) {
        return [
            'key' => $key,
            'label' => $label,
            'sifat' => $sifat,
            'mutasi_internal' => (bool) $mutasiInternal
        ];
    }

    private function teksMengandung($teks, array $kataKunci)
    {
        foreach ($kataKunci as $kata) {
            if (strpos($teks, $kata) !== false) {
                return true;
            }
        }

        return false;
    }

    private function ambilTransfer($filter)
    {
        $this->db->select([
            'tb_transfer.id',
            'tb_transfer.kode_transfer',
            'tb_transfer.idPengirim',
            'tb_transfer.idPenerima',
            'tb_transfer.cabang_asal_id',
            'tb_transfer.cabang_tujuan_id',
            'tb_transfer.nominal',
            'tb_transfer.keterangan',
            'tb_transfer.terdaftar',
            'pengirim.nama AS nama_pengirim',
            'penerima.nama AS nama_penerima',
            'cabang_asal.kode AS kode_cabang_asal',
            'cabang_asal.nama AS nama_cabang_asal',
            'cabang_tujuan.kode AS kode_cabang_tujuan',
            'cabang_tujuan.nama AS nama_cabang_tujuan'
        ]);

        $this->db->from('tb_transfer');
        $this->db->join(
            'tb_user AS pengirim',
            'pengirim.id = tb_transfer.idPengirim',
            'left'
        );
        $this->db->join(
            'tb_user AS penerima',
            'penerima.id = tb_transfer.idPenerima',
            'left'
        );
        $this->db->join(
            'tb_cabang AS cabang_asal',
            'cabang_asal.id = tb_transfer.cabang_asal_id',
            'left'
        );
        $this->db->join(
            'tb_cabang AS cabang_tujuan',
            'cabang_tujuan.id = tb_transfer.cabang_tujuan_id',
            'left'
        );
        $this->db->where('tb_transfer.status_transfer', 'Sukses');
        $this->db->where(
            'tb_transfer.terdaftar >=',
            $filter['awal_waktu']
        );
        $this->db->where(
            'tb_transfer.terdaftar <=',
            $filter['akhir_waktu']
        );

        if ($filter['cabang_id'] !== null) {
            $this->db->group_start();
            $this->db->where(
                'tb_transfer.cabang_asal_id',
                $filter['cabang_id']
            );
            $this->db->or_where(
                'tb_transfer.cabang_tujuan_id',
                $filter['cabang_id']
            );
            $this->db->group_end();
        } elseif ($this->isKoordinator) {
            $this->db->group_start();
            $this->db->where_in(
                'tb_transfer.cabang_asal_id',
                $this->cabangIds
            );
            $this->db->or_where_in(
                'tb_transfer.cabang_tujuan_id',
                $this->cabangIds
            );
            $this->db->group_end();
        }

        $this->db->order_by('tb_transfer.terdaftar', 'DESC');
        $this->db->order_by('tb_transfer.id', 'DESC');

        $rows = $this->db->get()->result_array();

        foreach ($rows as &$row) {
            if ($filter['cabang_id'] === null && !$this->isKoordinator) {
                $row['masuk_scope'] = true;
                $row['keluar_scope'] = true;
                $row['arah_scope'] =
                    (int) $row['cabang_asal_id'] ===
                    (int) $row['cabang_tujuan_id']
                    ? 'Internal cabang'
                    : 'Antar cabang';
            } elseif ($filter['cabang_id'] === null) {
                $row['masuk_scope'] = in_array(
                    (int) $row['cabang_tujuan_id'],
                    $this->cabangIds,
                    true
                );
                $row['keluar_scope'] = in_array(
                    (int) $row['cabang_asal_id'],
                    $this->cabangIds,
                    true
                );

                if ($row['masuk_scope'] && $row['keluar_scope']) {
                    $row['arah_scope'] = 'Internal penugasan';
                } elseif ($row['masuk_scope']) {
                    $row['arah_scope'] = 'Masuk';
                } else {
                    $row['arah_scope'] = 'Keluar';
                }
            } else {
                $row['masuk_scope'] = (
                    (int) $row['cabang_tujuan_id'] ===
                    (int) $filter['cabang_id']
                );

                $row['keluar_scope'] = (
                    (int) $row['cabang_asal_id'] ===
                    (int) $filter['cabang_id']
                );

                if ($row['masuk_scope'] && $row['keluar_scope']) {
                    $row['arah_scope'] = 'Internal cabang';
                } elseif ($row['masuk_scope']) {
                    $row['arah_scope'] = 'Masuk';
                } else {
                    $row['arah_scope'] = 'Keluar';
                }
            }
        }
        unset($row);

        return $rows;
    }

    private function tulisCsv($output, array $row)
    {
        $aman = [];

        foreach ($row as $value) {
            $value = (string) $value;

            // Cegah formula injection saat CSV dibuka di spreadsheet.
            if (preg_match('/^[=+\-@]/', $value)) {
                $value = "'" . $value;
            }

            $aman[] = $value;
        }

        // Excel dengan regional Indonesia memakai titik koma sebagai pemisah.
        fputcsv($output, $aman, ';');
    }

    private function barisExcel($nomor, array $cells, $tinggi = null)
    {
        $atributTinggi = $tinggi !== null
            ? ' ht="' . (float) $tinggi . '" customHeight="1"'
            : '';

        $xml = '<row r="' . (int) $nomor . '"' .
            $atributTinggi . '>';

        foreach ($cells as $cell) {
            $xml .= $this->selExcel(
                $cell[0] . $nomor,
                $cell[1],
                $cell[2] ?? 0,
                $cell[3] ?? false
            );
        }

        return $xml . '</row>';
    }

    private function selExcel($referensi, $value, $style, $numeric)
    {
        $ref = $this->xmlExcel($referensi);
        $style = (int) $style;

        if ($value === null || $value === '') {
            return '<c r="' . $ref . '" s="' . $style . '"/>';
        }

        if ($numeric) {
            return '<c r="' . $ref . '" s="' . $style . '">' .
                '<v>' . (float) $value . '</v></c>';
        }

        return '<c r="' . $ref . '" t="inlineStr" s="' .
            $style . '"><is><t xml:space="preserve">' .
            $this->xmlExcel((string) $value) .
            '</t></is></c>';
    }

    private function buatSheetExcel(
        array $rows,
        $barisHeader,
        $barisTerakhir
    ) {
        return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' .
            '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">' .
            '<dimension ref="A1:K' . (int) $barisTerakhir . '"/>' .
            '<sheetViews><sheetView workbookViewId="0"/></sheetViews>' .
            '<sheetFormatPr defaultRowHeight="15"/>' .
            '<cols>' .
            '<col min="1" max="1" width="22" customWidth="1"/>' .
            '<col min="2" max="2" width="22" customWidth="1"/>' .
            '<col min="3" max="3" width="18" customWidth="1"/>' .
            '<col min="4" max="4" width="32" customWidth="1"/>' .
            '<col min="5" max="6" width="25" customWidth="1"/>' .
            '<col min="7" max="8" width="24" customWidth="1"/>' .
            '<col min="9" max="10" width="18" customWidth="1"/>' .
            '<col min="11" max="11" width="65" customWidth="1"/>' .
            '</cols>' .
            '<sheetData>' . implode('', $rows) . '</sheetData>' .
            '<autoFilter ref="A' . (int) $barisHeader . ':K' .
            (int) $barisTerakhir . '"/>' .
            '<mergeCells count="4">' .
            '<mergeCell ref="A1:K1"/>' .
            '<mergeCell ref="B2:K2"/>' .
            '<mergeCell ref="B3:K3"/>' .
            '<mergeCell ref="A5:K5"/>' .
            '</mergeCells>' .
            '<pageMargins left="0.25" right="0.25" top="0.5" bottom="0.5" header="0.2" footer="0.2"/>' .
            '<pageSetup orientation="landscape" fitToWidth="1" fitToHeight="0" paperSize="9"/>' .
            '</worksheet>';
    }

    private function styleExcel()
    {
        return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' .
            '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">' .
            '<numFmts count="1"><numFmt numFmtId="164" formatCode="&quot;Rp&quot; #,##0"/></numFmts>' .
            '<fonts count="4">' .
            '<font><sz val="11"/><name val="Calibri"/><family val="2"/></font>' .
            '<font><b/><sz val="16"/><color rgb="FF1F4E78"/><name val="Calibri"/></font>' .
            '<font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font>' .
            '<font><b/><sz val="11"/><color rgb="FF1F1F1F"/><name val="Calibri"/></font>' .
            '</fonts>' .
            '<fills count="5">' .
            '<fill><patternFill patternType="none"/></fill>' .
            '<fill><patternFill patternType="gray125"/></fill>' .
            '<fill><patternFill patternType="solid"><fgColor rgb="FF1F4E78"/><bgColor indexed="64"/></patternFill></fill>' .
            '<fill><patternFill patternType="solid"><fgColor rgb="FF70AD47"/><bgColor indexed="64"/></patternFill></fill>' .
            '<fill><patternFill patternType="solid"><fgColor rgb="FFD9EAF7"/><bgColor indexed="64"/></patternFill></fill>' .
            '</fills>' .
            '<borders count="2">' .
            '<border><left/><right/><top/><bottom/><diagonal/></border>' .
            '<border><left style="thin"><color rgb="FFB7B7B7"/></left>' .
            '<right style="thin"><color rgb="FFB7B7B7"/></right>' .
            '<top style="thin"><color rgb="FFB7B7B7"/></top>' .
            '<bottom style="thin"><color rgb="FFB7B7B7"/></bottom><diagonal/></border>' .
            '</borders>' .
            '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>' .
            '<cellXfs count="11">' .
            '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>' .
            '<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0"><alignment horizontal="center" vertical="center"/></xf>' .
            '<xf numFmtId="0" fontId="3" fillId="0" borderId="0" xfId="0"/>' .
            '<xf numFmtId="0" fontId="2" fillId="2" borderId="1" xfId="0"><alignment vertical="center"/></xf>' .
            '<xf numFmtId="0" fontId="2" fillId="3" borderId="1" xfId="0"><alignment horizontal="center" vertical="center" wrapText="1"/></xf>' .
            '<xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0"><alignment vertical="top" wrapText="1"/></xf>' .
            '<xf numFmtId="3" fontId="0" fillId="0" borderId="1" xfId="0" applyNumberFormat="1"/>' .
            '<xf numFmtId="164" fontId="0" fillId="0" borderId="1" xfId="0" applyNumberFormat="1"/>' .
            '<xf numFmtId="0" fontId="3" fillId="4" borderId="1" xfId="0"/>' .
            '<xf numFmtId="164" fontId="3" fillId="4" borderId="1" xfId="0" applyNumberFormat="1"/>' .
            '<xf numFmtId="3" fontId="3" fillId="4" borderId="1" xfId="0" applyNumberFormat="1"/>' .
            '</cellXfs>' .
            '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>' .
            '</styleSheet>';
    }

    private function kontenTipeExcel()
    {
        return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' .
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">' .
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>' .
            '<Default Extension="xml" ContentType="application/xml"/>' .
            '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>' .
            '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' .
            '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>' .
            '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>' .
            '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>' .
            '</Types>';
    }

    private function relasiUtamaExcel()
    {
        return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' .
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' .
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>' .
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>' .
            '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>' .
            '</Relationships>';
    }

    private function workbookExcel()
    {
        return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' .
            '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">' .
            '<sheets><sheet name="Laporan Keuangan" sheetId="1" r:id="rId1"/></sheets>' .
            '</workbook>';
    }

    private function relasiWorkbookExcel()
    {
        return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' .
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' .
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>' .
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>' .
            '</Relationships>';
    }

    private function appExcel()
    {
        return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' .
            '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">' .
            '<Application>Tabungan Makmur</Application>' .
            '</Properties>';
    }

    private function coreExcel()
    {
        $waktu = gmdate('Y-m-d\TH:i:s\Z');

        return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' .
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">' .
            '<dc:title>Laporan Keuangan Inti</dc:title>' .
            '<dc:creator>Tabungan Makmur</dc:creator>' .
            '<dcterms:created xsi:type="dcterms:W3CDTF">' .
            $waktu . '</dcterms:created>' .
            '</cp:coreProperties>';
    }

    private function xmlExcel($value)
    {
        return htmlspecialchars(
            (string) $value,
            ENT_QUOTES | ENT_XML1,
            'UTF-8'
        );
    }

    private function tanggalValid($tanggal)
    {
        $date = DateTime::createFromFormat('Y-m-d', $tanggal);

        return $date && $date->format('Y-m-d') === $tanggal;
    }

    private function filterTidakValid($pesan)
    {
        $this->session->set_flashdata('pesanError', $pesan);
        redirect('admin/laporan');
        exit;
    }
}
