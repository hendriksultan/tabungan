<?php
defined('BASEPATH') or exit('No direct script access allowed');

class Transfer extends CI_Controller
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
    }

    public function index()
    {
        $data['title'] = 'Data Transfer';

        if ($this->isSuperAdmin) {
            $data['subtitle'] = 'Transfer dari seluruh cabang';
        } elseif ($this->userLevel === 'administrator') {
            $data['subtitle'] = 'Transfer yang berkaitan dengan cabang Anda';
        } else {
            $data['subtitle'] = 'Riwayat transfer saldo Anda';
        }

        /*
         * Daftar penerima untuk nasabah.
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
        $this->db->where('tb_user.login', 'Ya');
        $this->db->where('tb_user.id !=', (int) $this->session->userdata('id'));
        $this->db->where('tb_cabang.status', 'Aktif');
        $this->db->order_by('tb_user.nama', 'ASC');

        $data['nasabah'] = $this->db->get();

        /*
         * Riwayat transfer beserta cabang asal dan tujuan.
         */
        $this->db->select([
            'tb_transfer.*',
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

        if ($this->userLevel === 'nasabah') {
            $userId = (int) $this->session->userdata('id');

            $this->db->group_start();
            $this->db->where('tb_transfer.idPengirim', $userId);
            $this->db->or_where('tb_transfer.idPenerima', $userId);
            $this->db->group_end();
        } elseif (!$this->isSuperAdmin) {
            if ($this->cabangId <= 0) {
                $this->db->where('1 = 0', null, false);
            } else {
                $this->db->group_start();
                $this->db->where(
                    'tb_transfer.cabang_asal_id',
                    $this->cabangId
                );
                $this->db->or_where(
                    'tb_transfer.cabang_tujuan_id',
                    $this->cabangId
                );
                $this->db->group_end();
            }
        }

        $this->db->order_by('tb_transfer.id', 'DESC');

        $data['transfer'] = $this->db->get();

        $this->load->view('admin/templates/header', $data);
        $this->load->view('admin/templates/sidebar');
        $this->load->view('admin/transfer', $data);
        $this->load->view('admin/templates/footer');
    }

    public function insert()
    {
        $this->pastikanPost();

        if ($this->userLevel !== 'nasabah') {
            $this->gagal(
                'Transfer hanya dapat dilakukan oleh nasabah!'
            );
            return;
        }

        date_default_timezone_set('Asia/Jakarta');

        $idPengirim = (int) $this->session->userdata('id');
        $idPenerima = (int) $this->input->post('idPenerima');

        $nominal = (int) preg_replace(
            '/[^0-9]/',
            '',
            (string) $this->input->post('nominal')
        );

        $keterangan = trim(
            (string) $this->input->post('keterangan', true)
        );

        $setuju = $this->input->post('setuju');

        if (!$setuju) {
            $this->gagal(
                'Anda harus menyetujui konfirmasi transfer!'
            );
            return;
        }

        if ($idPengirim <= 0 || $idPenerima <= 0) {
            $this->gagal('Data pengirim atau penerima tidak valid!');
            return;
        }

        if ($idPengirim === $idPenerima) {
            $this->gagal('Tidak dapat transfer ke rekening sendiri!');
            return;
        }

        if ($nominal <= 0) {
            $this->gagal('Nominal transfer tidak valid!');
            return;
        }

        $this->db->select([
            'tb_user.id',
            'tb_user.nama',
            'tb_user.cabang_id',
            'tb_user.level',
            'tb_user.login',
            'tb_cabang.status AS status_cabang'
        ]);

        $this->db->from('tb_user');

        $this->db->join(
            'tb_cabang',
            'tb_cabang.id = tb_user.cabang_id',
            'left'
        );

        $this->db->where('tb_user.id', $idPengirim);

        $pengirim = $this->db->get()->row_array();

        $this->db->select([
            'tb_user.id',
            'tb_user.nama',
            'tb_user.cabang_id',
            'tb_user.level',
            'tb_user.login',
            'tb_cabang.status AS status_cabang'
        ]);

        $this->db->from('tb_user');

        $this->db->join(
            'tb_cabang',
            'tb_cabang.id = tb_user.cabang_id',
            'left'
        );

        $this->db->where('tb_user.id', $idPenerima);

        $penerima = $this->db->get()->row_array();

        if (
            !$pengirim ||
            strtolower($pengirim['level']) !== 'nasabah' ||
            $pengirim['login'] !== 'Ya'
        ) {
            $this->gagal('Akun pengirim tidak valid atau tidak aktif!');
            return;
        }

        if (
            !$penerima ||
            strtolower($penerima['level']) !== 'nasabah' ||
            $penerima['login'] !== 'Ya'
        ) {
            $this->gagal('Akun penerima tidak valid atau tidak aktif!');
            return;
        }

        if (
            empty($pengirim['cabang_id']) ||
            strtolower($pengirim['status_cabang']) !== 'aktif'
        ) {
            $this->gagal('Cabang pengirim tidak aktif!');
            return;
        }

        if (
            empty($penerima['cabang_id']) ||
            strtolower($penerima['status_cabang']) !== 'aktif'
        ) {
            $this->gagal('Cabang penerima tidak aktif!');
            return;
        }

        /*
         * Mulai transaksi database dan kunci baris pengirim.
         */
        $this->db->trans_begin();

        $this->db->query(
            'SELECT id FROM tb_user WHERE id = ? FOR UPDATE',
            [$idPengirim]
        );

        $saldo = $this->hitungSaldoNasabah($idPengirim);

        if ($nominal > $saldo) {
            $this->db->trans_rollback();

            $this->gagal(
                'Saldo tidak cukup. Sisa saldo: Rp ' .
                    number_format($saldo, 0, ',', '.')
            );

            return;
        }

        $kodeTransfer = $this->buatKodeTransfer();

        $data = [
            'idPengirim'       => $idPengirim,
            'idPenerima'       => $idPenerima,
            'cabang_asal_id'   => (int) $pengirim['cabang_id'],
            'cabang_tujuan_id' => (int) $penerima['cabang_id'],
            'kode_transfer'    => $kodeTransfer,
            'nominal'          => $nominal,
            'keterangan'       => $keterangan,
            'status_transfer'  => 'Sukses',
            'terdaftar'        => date('Y-m-d H:i:s')
        ];

        $this->db->insert('tb_transfer', $data);
        $berhasilDisimpan = $this->db->affected_rows() === 1;

        if (
            !$berhasilDisimpan ||
            $this->db->trans_status() === false
        ) {
            $this->db->trans_rollback();

            $this->gagal('Transfer gagal diproses!');
            return;
        }

        $this->db->trans_commit();

        $this->session->set_flashdata(
            'pesan',
            'Transfer berhasil dengan kode ' . $kodeTransfer
        );

        redirect('admin/transfer');
    }

    private function hitungSaldoNasabah($idNasabah)
    {
        $transaksiMasuk = $this->db->query(
            "SELECT IFNULL(SUM(nominal), 0) AS total
             FROM tb_transaksi
             WHERE idNasabah = ?
               AND jenis = 'Masuk'
               AND status_konfirmasi = 'Sukses'",
            [$idNasabah]
        )->row()->total;

        $transferMasuk = $this->db->query(
            "SELECT IFNULL(SUM(nominal), 0) AS total
             FROM tb_transfer
             WHERE idPenerima = ?
               AND status_transfer = 'Sukses'",
            [$idNasabah]
        )->row()->total;

        $transaksiKeluar = $this->db->query(
            "SELECT IFNULL(SUM(nominal), 0) AS total
             FROM tb_transaksi
             WHERE idNasabah = ?
               AND jenis = 'Keluar'
               AND status_konfirmasi = 'Sukses'",
            [$idNasabah]
        )->row()->total;

        $transferKeluar = $this->db->query(
            "SELECT IFNULL(SUM(nominal), 0) AS total
             FROM tb_transfer
             WHERE idPengirim = ?
               AND status_transfer = 'Sukses'",
            [$idNasabah]
        )->row()->total;

        return
            (float) $transaksiMasuk +
            (float) $transferMasuk -
            (float) $transaksiKeluar -
            (float) $transferKeluar;
    }

    private function buatKodeTransfer()
    {
        do {
            try {
                $acak = strtoupper(bin2hex(random_bytes(3)));
            } catch (Exception $exception) {
                $acak = strtoupper(substr(uniqid(), -6));
            }

            $kode = 'TRF-' .
                date('Ymd-His') .
                '-' .
                $acak;

            $sudahAda = $this->db
                ->get_where(
                    'tb_transfer',
                    ['kode_transfer' => $kode]
                )
                ->num_rows() > 0;
        } while ($sudahAda);

        return $kode;
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

    private function gagal($pesan)
    {
        $this->session->set_flashdata(
            'pesanError',
            $pesan
        );

        redirect('admin/transfer');
    }
}
