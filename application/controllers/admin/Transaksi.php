<?php
defined('BASEPATH') or exit('No direct script access allowed');

class Transaksi extends CI_Controller
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
            return;
        }

        $this->userLevel = strtolower(
            trim((string) $this->session->userdata('level'))
        );

        $this->isSuperAdmin = (
            $this->userLevel === 'super admin'
        );

        $this->cabangId = (int) $this->session->userdata(
            'cabang_id'
        );

        if (
            !$this->isSuperAdmin &&
            $this->userLevel !== 'nasabah' &&
            $this->cabangId <= 0
        ) {
            $this->session->set_flashdata(
                'pesanError',
                'Akun belum terhubung dengan cabang!'
            );

            redirect('admin/dashboard');
            return;
        }
    }

    public function index()
    {
        $data['title'] = 'Data Transaksi';

        $data['subtitle'] = $this->isSuperAdmin
            ? 'Menampilkan transaksi dari seluruh cabang'
            : 'Menampilkan transaksi pada cabang Anda';

        /*
         * Ambil transaksi beserta nasabah dan cabang.
         */
        $this->db->select([
            'tb_transaksi.*',
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

        if ($this->userLevel === 'nasabah') {
            $this->db->where(
                'tb_transaksi.idNasabah',
                (int) $this->session->userdata('id')
            );
        } elseif (!$this->isSuperAdmin) {
            $this->db->where(
                'tb_transaksi.cabang_id',
                $this->cabangId
            );
        }

        $this->db->order_by('tb_transaksi.id', 'DESC');

        $data['transaksi'] = $this->db->get();

        /*
         * Daftar nasabah pada form transaksi.
         */
        $this->db->select([
            'tb_user.id',
            'tb_user.nama',
            'tb_user.cabang_id',
            'tb_cabang.kode AS kode_cabang',
            'tb_cabang.nama AS nama_cabang'
        ]);

        $this->db->from('tb_user');

        $this->db->join(
            'tb_cabang',
            'tb_cabang.id = tb_user.cabang_id',
            'left'
        );

        $this->db->where('tb_user.level', 'Nasabah');

        if (!$this->isSuperAdmin) {
            if ($this->userLevel === 'administrator') {
                $this->db->where(
                    'tb_user.cabang_id',
                    $this->cabangId
                );
            } elseif ($this->userLevel === 'nasabah') {
                $this->db->where(
                    'tb_user.id',
                    (int) $this->session->userdata('id')
                );
            }
        }

        $this->db->order_by('tb_user.nama', 'ASC');

        $data['nasabah'] = $this->db->get();

        $this->load->view('admin/templates/header', $data);
        $this->load->view('admin/templates/sidebar');
        $this->load->view('admin/transaksi', $data);
        $this->load->view('admin/templates/footer');
    }

    public function insert()
    {
        $this->pastikanPengelola();
        $this->pastikanPost();

        date_default_timezone_set('Asia/Jakarta');

        $idNasabah = (int) $this->input->post('idNasabah');

        $tanggal = trim(
            (string) $this->input->post('tanggal', true)
        );

        $nominalInput = preg_replace(
            '/[^0-9]/',
            '',
            (string) $this->input->post('nominal')
        );

        $nominal = (int) $nominalInput;

        $jenis = trim(
            (string) $this->input->post('jenis', true)
        );

        $keterangan = trim(
            (string) $this->input->post('keterangan', true)
        );

        if ($idNasabah <= 0) {
            $this->gagal('Nasabah wajib dipilih!');
            return;
        }

        if (!$this->tanggalValid($tanggal)) {
            $this->gagal('Tanggal transaksi tidak valid!');
            return;
        }

        if ($nominal <= 0) {
            $this->gagal('Nominal transaksi tidak valid!');
            return;
        }

        if (!in_array($jenis, ['Masuk', 'Keluar'], true)) {
            $this->gagal('Jenis transaksi tidak valid!');
            return;
        }

        $nasabah = $this->db
            ->get_where('tb_user', [
                'id'    => $idNasabah,
                'level' => 'Nasabah'
            ])
            ->row_array();

        if (!$nasabah) {
            $this->gagal('Data nasabah tidak ditemukan!');
            return;
        }

        /*
         * Administrator hanya boleh memproses nasabah cabangnya.
         */
        if (
            !$this->isSuperAdmin &&
            (int) $nasabah['cabang_id'] !== $this->cabangId
        ) {
            $this->gagal(
                'Nasabah tersebut berasal dari cabang lain!'
            );
            return;
        }

        /*
         * Super Admin menggunakan cabang asal nasabah.
         * Administrator menggunakan cabang session.
         */
        $cabangTransaksi = $this->isSuperAdmin
            ? (int) $nasabah['cabang_id']
            : $this->cabangId;

        if ($cabangTransaksi <= 0) {
            $this->gagal(
                'Nasabah belum terhubung dengan cabang!'
            );
            return;
        }

        /*
         * Transaksi Setor wajib mempunyai rekening penampungan aktif.
         * Berlaku untuk Administrator maupun Super Admin pada web.
         */
        if ($jenis === 'Masuk') {
            if (!$this->db->table_exists('tb_rekening_penampungan')) {
                $this->gagal(
                    'Rekening penampungan belum dikonfigurasi!'
                );
                return;
            }

            $rekeningAktif = $this->db
                ->where('cabang_id', $cabangTransaksi)
                ->where('status', 'Aktif')
                ->count_all_results('tb_rekening_penampungan');

            if ($rekeningAktif < 1) {
                $this->gagal(
                    'Cabang nasabah belum memiliki rekening penampungan aktif!'
                );
                return;
            }
        }

        $this->db->trans_begin();

        if ($jenis === 'Keluar') {
            $saldo = $this->hitungSaldoNasabah($idNasabah);

            if ($nominal > $saldo) {
                $this->db->trans_rollback();

                $this->gagal(
                    'Saldo nasabah tidak cukup. Sisa saldo: Rp ' .
                        number_format($saldo, 0, ',', '.')
                );

                return;
            }
        }

        $data = [
            'cabang_id'         => $cabangTransaksi,
            'idAdmin'           => (int) $this->session->userdata('id'),
            'idNasabah'         => $idNasabah,
            'idPotongan'        => 0,
            'tanggal'           => $tanggal,
            'nominal'           => $nominal,
            'jenis'             => $jenis,
            'keterangan'        => $keterangan,
            'status_konfirmasi' => 'Sukses',
            'terdaftar'         => date('Y-m-d H:i:s')
        ];

        $this->db->insert('tb_transaksi', $data);

        if (
            $this->db->trans_status() === false ||
            $this->db->affected_rows() < 1
        ) {
            $this->db->trans_rollback();

            $this->gagal('Transaksi gagal disimpan!');
            return;
        }

        $this->db->trans_commit();

        $this->session->set_flashdata(
            'pesan',
            'Transaksi berhasil ditambahkan!'
        );

        redirect('admin/transaksi');
    }

    public function update($id)
    {
        $this->pastikanPengelola();
        $this->pastikanPost();

        $transaksi = $this->ambilTransaksiYangBolehDikelola($id);

        if (!$transaksi) {
            return;
        }

        $tanggal = trim(
            (string) $this->input->post('tanggal', true)
        );

        $nominal = (int) preg_replace(
            '/[^0-9]/',
            '',
            (string) $this->input->post('nominal')
        );

        $keterangan = trim(
            (string) $this->input->post('keterangan', true)
        );

        if (!$this->tanggalValid($tanggal)) {
            $this->gagal('Tanggal transaksi tidak valid!');
            return;
        }

        if ($nominal <= 0) {
            $this->gagal('Nominal transaksi tidak valid!');
            return;
        }

        $data = [
            'tanggal'    => $tanggal,
            'nominal'    => $nominal,
            'keterangan' => $keterangan
        ];

        $this->db->where('id', (int) $transaksi['id']);

        if ($this->db->update('tb_transaksi', $data)) {
            $this->session->set_flashdata(
                'pesan',
                'Data transaksi berhasil diubah!'
            );
        } else {
            $this->session->set_flashdata(
                'pesanError',
                'Data transaksi gagal diubah!'
            );
        }

        redirect('admin/transaksi');
    }

    public function delete($id)
    {
        $this->pastikanPengelola();

        $transaksi = $this->ambilTransaksiYangBolehDikelola($id);

        if (!$transaksi) {
            return;
        }

        $this->db->where('id', (int) $transaksi['id']);

        if ($this->db->delete('tb_transaksi')) {
            $this->session->set_flashdata(
                'pesan',
                'Data transaksi berhasil dihapus!'
            );
        } else {
            $this->session->set_flashdata(
                'pesanError',
                'Data transaksi gagal dihapus!'
            );
        }

        redirect('admin/transaksi');
    }

    public function carinasabah()
    {
        $this->pastikanPengelola();
        $this->pastikanPost();

        $idNasabah = (int) $this->input->post('idNasabah');

        redirect('admin/transaksi/ceksaldo/' . $idNasabah);
    }

    public function ceksaldo($idNasabah)
    {
        $this->pastikanPengelola();

        $nasabah = $this->ambilNasabahYangBolehDiakses($idNasabah);

        if (!$nasabah) {
            return;
        }

        $idNasabah = (int) $nasabah['id'];

        $data['title'] = 'Cek Saldo Nasabah';
        $data['subtitle'] = 'Riwayat transaksi dan transfer nasabah';
        $data['idNasabah'] = $idNasabah;

        $this->db->where('id', $idNasabah);
        $data['user'] = $this->db->get('tb_user');

        $this->db->where('idNasabah', $idNasabah);
        $this->db->order_by('id', 'DESC');
        $data['transaksi'] = $this->db->get('tb_transaksi');

        $this->db->group_start();
        $this->db->where('idPengirim', $idNasabah);
        $this->db->or_where('idPenerima', $idNasabah);
        $this->db->group_end();
        $this->db->order_by('id', 'DESC');

        $data['transfer'] = $this->db->get('tb_transfer');

        $totalMasukTransaksi = $this->db->query(
            "SELECT IFNULL(SUM(nominal), 0) AS total
             FROM tb_transaksi
             WHERE idNasabah = ?
               AND jenis = 'Masuk'
               AND status_konfirmasi = 'Sukses'",
            [$idNasabah]
        )->row()->total;

        $totalMasukTransfer = $this->db->query(
            "SELECT IFNULL(SUM(nominal), 0) AS total
            FROM tb_transfer
            WHERE idPenerima = ?
            AND status_transfer = 'Sukses'",
            [$idNasabah]
        )->row()->total;

        $totalKeluarTransaksi = $this->db->query(
            "SELECT IFNULL(SUM(nominal), 0) AS total
             FROM tb_transaksi
             WHERE idNasabah = ?
               AND jenis = 'Keluar'
               AND status_konfirmasi = 'Sukses'",
            [$idNasabah]
        )->row()->total;

        $totalKeluarTransfer = $this->db->query(
            "SELECT IFNULL(SUM(nominal), 0) AS total
                FROM tb_transfer
                WHERE idPengirim = ?
                AND status_transfer = 'Sukses'",
            [$idNasabah]
        )->row()->total;

        $data['totalMasuk'] =
            (float) $totalMasukTransaksi +
            (float) $totalMasukTransfer;

        $data['totalKeluar'] =
            (float) $totalKeluarTransaksi +
            (float) $totalKeluarTransfer;

        $data['sisaSaldo'] =
            $data['totalMasuk'] -
            $data['totalKeluar'];

        $this->load->view('admin/templates/header', $data);
        $this->load->view('admin/templates/sidebar');
        $this->load->view('admin/ceksaldo', $data);
        $this->load->view('admin/templates/footer');
    }

    public function rekap()
    {
        $this->pastikanPengelola();
        $this->pastikanPost();

        $dariTanggal = trim(
            (string) $this->input->post('dariTanggal', true)
        );

        $sampaiTanggal = trim(
            (string) $this->input->post('sampaiTanggal', true)
        );

        if (
            !$this->tanggalValid($dariTanggal) ||
            !$this->tanggalValid($sampaiTanggal) ||
            $dariTanggal > $sampaiTanggal
        ) {
            $this->gagal('Rentang tanggal tidak valid!');
            return;
        }

        $data['title'] = 'Rekap Data Transaksi';

        $this->db->select([
            'tb_transaksi.*',
            'tb_user.nama AS nama_nasabah',
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

        $this->db->where(
            'tb_transaksi.tanggal >=',
            $dariTanggal
        );

        $this->db->where(
            'tb_transaksi.tanggal <=',
            $sampaiTanggal
        );

        $this->db->where(
            'tb_transaksi.status_konfirmasi',
            'Sukses'
        );

        if (!$this->isSuperAdmin) {
            $this->db->where(
                'tb_transaksi.cabang_id',
                $this->cabangId
            );
        }

        $this->db->order_by('tb_transaksi.tanggal', 'ASC');

        $data['transaksi'] = $this->db->get();

        $data['jumlahMasuk'] = $this->queryJumlah(
            $dariTanggal,
            $sampaiTanggal,
            'Masuk'
        );

        $data['jumlahKeluar'] = $this->queryJumlah(
            $dariTanggal,
            $sampaiTanggal,
            'Keluar'
        );

        $data['dariTanggal'] = $dariTanggal;
        $data['sampaiTanggal'] = $sampaiTanggal;
        $data['namaCabang'] = $this->isSuperAdmin
            ? 'Seluruh Cabang'
            : $this->session->userdata('nama_cabang');

        $this->load->view('admin/rekaptransaksi', $data);
    }

    private function queryJumlah($dari, $sampai, $jenis)
    {
        $this->db->select_sum(
            'nominal',
            $jenis === 'Masuk'
                ? 'jumlahMasuk'
                : 'jumlahKeluar'
        );

        $this->db->where('tanggal >=', $dari);
        $this->db->where('tanggal <=', $sampai);
        $this->db->where('jenis', $jenis);
        $this->db->where('status_konfirmasi', 'Sukses');

        if (!$this->isSuperAdmin) {
            $this->db->where('cabang_id', $this->cabangId);
        }

        return $this->db->get('tb_transaksi');
    }

    private function hitungSaldoNasabah($idNasabah)
    {
        $masukTransaksi = $this->db->query(
            "SELECT IFNULL(SUM(nominal), 0) AS total
             FROM tb_transaksi
             WHERE idNasabah = ?
               AND jenis = 'Masuk'
               AND status_konfirmasi = 'Sukses'",
            [$idNasabah]
        )->row()->total;

        $masukTransfer = $this->db->query(
            "SELECT IFNULL(SUM(nominal), 0) AS total
            FROM tb_transfer
            WHERE idPenerima = ?
            AND status_transfer = 'Sukses'",
            [$idNasabah]
        )->row()->total;

        $keluarTransaksi = $this->db->query(
            "SELECT IFNULL(SUM(nominal), 0) AS total
             FROM tb_transaksi
             WHERE idNasabah = ?
               AND jenis = 'Keluar'
               AND status_konfirmasi = 'Sukses'",
            [$idNasabah]
        )->row()->total;

        $keluarTransfer = $this->db->query(
            "SELECT IFNULL(SUM(nominal), 0) AS total
            FROM tb_transfer
            WHERE idPengirim = ?
            AND status_transfer = 'Sukses'",
            [$idNasabah]
        )->row()->total;

        return
            (float) $masukTransaksi +
            (float) $masukTransfer -
            (float) $keluarTransaksi -
            (float) $keluarTransfer;
    }

    private function ambilNasabahYangBolehDiakses($idNasabah)
    {
        $nasabah = $this->db
            ->get_where('tb_user', [
                'id'    => (int) $idNasabah,
                'level' => 'Nasabah'
            ])
            ->row_array();

        if (!$nasabah) {
            $this->gagal('Nasabah tidak ditemukan!');
            return false;
        }

        if (
            !$this->isSuperAdmin &&
            (int) $nasabah['cabang_id'] !== $this->cabangId
        ) {
            $this->gagal(
                'Anda tidak dapat mengakses nasabah cabang lain!'
            );

            return false;
        }

        return $nasabah;
    }

    private function ambilTransaksiYangBolehDikelola($id)
    {
        $transaksi = $this->db
            ->get_where('tb_transaksi', ['id' => (int) $id])
            ->row_array();

        if (!$transaksi) {
            $this->gagal('Transaksi tidak ditemukan!');
            return false;
        }

        if (
            !$this->isSuperAdmin &&
            (int) $transaksi['cabang_id'] !== $this->cabangId
        ) {
            $this->gagal(
                'Anda tidak dapat mengelola transaksi cabang lain!'
            );

            return false;
        }

        return $transaksi;
    }

    private function pastikanPengelola()
    {
        if (
            !in_array(
                $this->userLevel,
                ['administrator', 'super admin'],
                true
            )
        ) {
            $this->session->set_flashdata(
                'pesanError',
                'Akses ditolak!'
            );

            redirect('admin/transaksi');
            exit;
        }
    }

    private function pastikanPost()
    {
        if ($this->input->method(true) !== 'POST') {
            show_error(
                'Metode permintaan tidak diizinkan.',
                405
            );

            exit;
        }
    }

    private function tanggalValid($tanggal)
    {
        $format = DateTime::createFromFormat('Y-m-d', $tanggal);

        return $format &&
            $format->format('Y-m-d') === $tanggal;
    }

    private function gagal($pesan)
    {
        $this->session->set_flashdata(
            'pesanError',
            $pesan
        );

        redirect('admin/transaksi');
    }
}
