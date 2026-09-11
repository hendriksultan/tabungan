<?php
defined('BASEPATH') or exit('No direct script access allowed');

class Laporan extends CI_Controller
{
    private $userLevel;
    private $isSuperAdmin = false;
    private $cabangId = 0;

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

        if (!in_array(
            $this->userLevel,
            ['administrator', 'super admin'],
            true
        )) {
            $this->session->set_flashdata(
                'pesanError',
                'Akses laporan hanya untuk Administrator dan Super Admin!'
            );

            redirect('admin/dashboard');
            exit;
        }

        $this->cabangId = (int) $this->session->userdata(
            'cabang_id'
        );

        if (!$this->isSuperAdmin && $this->cabangId <= 0) {
            $this->session->set_flashdata(
                'pesanError',
                'Administrator belum terhubung dengan cabang!'
            );

            redirect('home/logout');
            exit;
        }
    }

    public function index()
    {
        $filter = $this->ambilFilter();
        $ringkasan = $this->hitungRingkasan($filter);

        $data = [
            'title' => 'Laporan Keuangan',
            'subtitle' => $this->isSuperAdmin
                ? 'Laporan transaksi dan transfer seluruh cabang'
                : 'Laporan transaksi dan transfer cabang Anda',
            'isSuperAdmin' => $this->isSuperAdmin,
            'filter' => $filter,
            'ringkasan' => $ringkasan,
            'transaksi' => $this->ambilTransaksi($filter),
            'transfer' => $this->ambilTransfer($filter),
            'cabang' => $this->isSuperAdmin
                ? $this->db
                    ->order_by('nama', 'ASC')
                    ->get('tb_cabang')
                    ->result_array()
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
        $ringkasan = $this->hitungRingkasan($filter);
        $transaksi = $this->ambilTransaksi($filter);
        $transfer = $this->ambilTransfer($filter);

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
            'Transaksi masuk',
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
            'Transaksi keluar',
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
            'Jumlah aktivitas',
            $ringkasan['jumlah_aktivitas']
        ]);
        $this->tulisCsv($output, []);

        $this->tulisCsv($output, [
            'Sumber',
            'Referensi',
            'Tanggal',
            'Pihak/Nasabah',
            'Cabang Asal',
            'Cabang Tujuan',
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
        $ringkasan = $this->hitungRingkasan($filter);
        $transaksi = $this->ambilTransaksi($filter);
        $transfer = $this->ambilTransfer($filter);

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
            ['Transaksi masuk', $ringkasan['transaksi_masuk'], 9],
            ['Transfer masuk', $ringkasan['transfer_masuk'], 9],
            ['Total masuk', $ringkasan['total_masuk'], 9],
            ['Transaksi keluar', $ringkasan['transaksi_keluar'], 9],
            ['Transfer keluar', $ringkasan['transfer_keluar'], 9],
            ['Total keluar', $ringkasan['total_keluar'], 9],
            ['Saldo bersih periode', $ringkasan['saldo_bersih'], 9],
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
        $barisHeader = $nomorBaris;

        $headers = [
            'A' => 'Sumber',
            'B' => 'Referensi',
            'C' => 'Tanggal',
            'D' => 'Pihak/Nasabah',
            'E' => 'Cabang Asal',
            'F' => 'Cabang Tujuan',
            'G' => 'Masuk',
            'H' => 'Keluar',
            'I' => 'Keterangan'
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
                ['G', $masuk, 7, true],
                ['H', $keluar, 7, true],
                ['I', $row['keterangan'], 5]
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
                ['G', $masuk, 7, true],
                ['H', $keluar, 7, true],
                ['I', $row['keterangan'], 5]
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
        $namaCabang = 'Seluruh Cabang';

        if ($this->isSuperAdmin) {
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

    private function hitungRingkasan($filter)
    {
        $transaksiMasuk = $this->agregatTransaksi(
            $filter,
            'Masuk'
        );

        $transaksiKeluar = $this->agregatTransaksi(
            $filter,
            'Keluar'
        );

        $transferMasuk = $this->agregatTransfer(
            $filter,
            'masuk'
        );

        $transferKeluar = $this->agregatTransfer(
            $filter,
            'keluar'
        );

        $jumlahTransfer = $this->hitungJumlahTransferUnik($filter);
        $totalMasuk = $transaksiMasuk['nominal'] +
            $transferMasuk['nominal'];
        $totalKeluar = $transaksiKeluar['nominal'] +
            $transferKeluar['nominal'];

        return [
            'transaksi_masuk' => $transaksiMasuk['nominal'],
            'transaksi_keluar' => $transaksiKeluar['nominal'],
            'transfer_masuk' => $transferMasuk['nominal'],
            'transfer_keluar' => $transferKeluar['nominal'],
            'jumlah_transaksi' => (
                $transaksiMasuk['jumlah'] +
                $transaksiKeluar['jumlah']
            ),
            'jumlah_transfer' => $jumlahTransfer,
            'jumlah_aktivitas' => (
                $transaksiMasuk['jumlah'] +
                $transaksiKeluar['jumlah'] +
                $jumlahTransfer
            ),
            'total_masuk' => $totalMasuk,
            'total_keluar' => $totalKeluar,
            'saldo_bersih' => $totalMasuk - $totalKeluar
        ];
    }

    private function agregatTransaksi($filter, $jenis)
    {
        $this->db->select(
            'COUNT(*) AS jumlah, IFNULL(SUM(nominal), 0) AS nominal',
            false
        );

        $this->db->where('jenis', $jenis);
        $this->db->where('status_konfirmasi', 'Sukses');
        $this->db->where('tanggal >=', $filter['dari']);
        $this->db->where('tanggal <=', $filter['sampai']);

        if ($filter['cabang_id'] !== null) {
            $this->db->where('cabang_id', $filter['cabang_id']);
        }

        $row = $this->db->get('tb_transaksi')->row_array();

        return [
            'jumlah' => (int) ($row['jumlah'] ?? 0),
            'nominal' => (float) ($row['nominal'] ?? 0)
        ];
    }

    private function agregatTransfer($filter, $arah)
    {
        $this->db->select(
            'COUNT(*) AS jumlah, IFNULL(SUM(nominal), 0) AS nominal',
            false
        );

        $this->db->where('status_transfer', 'Sukses');
        $this->db->where('terdaftar >=', $filter['awal_waktu']);
        $this->db->where('terdaftar <=', $filter['akhir_waktu']);

        if ($filter['cabang_id'] !== null) {
            $kolom = $arah === 'masuk'
                ? 'cabang_tujuan_id'
                : 'cabang_asal_id';

            $this->db->where($kolom, $filter['cabang_id']);
        }

        $row = $this->db->get('tb_transfer')->row_array();

        return [
            'jumlah' => (int) ($row['jumlah'] ?? 0),
            'nominal' => (float) ($row['nominal'] ?? 0)
        ];
    }

    private function hitungJumlahTransferUnik($filter)
    {
        $this->db->where('status_transfer', 'Sukses');
        $this->db->where('terdaftar >=', $filter['awal_waktu']);
        $this->db->where('terdaftar <=', $filter['akhir_waktu']);

        if ($filter['cabang_id'] !== null) {
            $this->db->group_start();
            $this->db->where(
                'cabang_asal_id',
                $filter['cabang_id']
            );
            $this->db->or_where(
                'cabang_tujuan_id',
                $filter['cabang_id']
            );
            $this->db->group_end();
        }

        return $this->db->count_all_results('tb_transfer');
    }

    private function ambilTransaksi($filter)
    {
        $this->db->select([
            'tb_transaksi.id',
            'tb_transaksi.tanggal',
            'tb_transaksi.nominal',
            'tb_transaksi.jenis',
            'tb_transaksi.keterangan',
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
        }

        $this->db->order_by('tb_transaksi.tanggal', 'DESC');
        $this->db->order_by('tb_transaksi.id', 'DESC');

        return $this->db->get()->result_array();
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
        }

        $this->db->order_by('tb_transfer.terdaftar', 'DESC');
        $this->db->order_by('tb_transfer.id', 'DESC');

        $rows = $this->db->get()->result_array();

        foreach ($rows as &$row) {
            if ($filter['cabang_id'] === null) {
                $row['masuk_scope'] = true;
                $row['keluar_scope'] = true;
                $row['arah_scope'] =
                    (int) $row['cabang_asal_id'] ===
                    (int) $row['cabang_tujuan_id']
                        ? 'Internal cabang'
                        : 'Antar cabang';
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
            '<dimension ref="A1:I' . (int) $barisTerakhir . '"/>' .
            '<sheetViews><sheetView workbookViewId="0">' .
            '<pane ySplit="' . (int) $barisHeader .
            '" topLeftCell="A' . ((int) $barisHeader + 1) .
            '" activePane="bottomLeft" state="frozen"/>' .
            '</sheetView></sheetViews>' .
            '<sheetFormatPr defaultRowHeight="15"/>' .
            '<cols>' .
            '<col min="1" max="1" width="22" customWidth="1"/>' .
            '<col min="2" max="2" width="22" customWidth="1"/>' .
            '<col min="3" max="3" width="18" customWidth="1"/>' .
            '<col min="4" max="4" width="32" customWidth="1"/>' .
            '<col min="5" max="6" width="25" customWidth="1"/>' .
            '<col min="7" max="8" width="18" customWidth="1"/>' .
            '<col min="9" max="9" width="65" customWidth="1"/>' .
            '</cols>' .
            '<sheetData>' . implode('', $rows) . '</sheetData>' .
            '<autoFilter ref="A' . (int) $barisHeader . ':I' .
            (int) $barisTerakhir . '"/>' .
            '<mergeCells count="4">' .
            '<mergeCell ref="A1:I1"/>' .
            '<mergeCell ref="B2:I2"/>' .
            '<mergeCell ref="B3:I3"/>' .
            '<mergeCell ref="A5:I5"/>' .
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
