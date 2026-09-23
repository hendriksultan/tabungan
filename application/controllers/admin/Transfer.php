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
            'pembatal.nama AS nama_pembatal',
            'pembatal.level AS level_pembatal',
            'cabang_asal.kode AS kode_cabang_asal',
            'cabang_asal.nama AS nama_cabang_asal',
            'cabang_tujuan.kode AS kode_cabang_tujuan',
            'cabang_tujuan.nama AS nama_cabang_tujuan',
            'cabang_pembatal.kode AS kode_cabang_pembatal',
            'cabang_pembatal.nama AS nama_cabang_pembatal'
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
            'tb_user AS pembatal',
            'pembatal.id = tb_transfer.dibatalkan_oleh',
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

        $this->db->join(
            'tb_cabang AS cabang_pembatal',
            'cabang_pembatal.id = pembatal.cabang_id',
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
            'dibuat_oleh'      => $idPengirim,
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

        $idTransfer = (int) $this->db->insert_id();

        if (
            !$berhasilDisimpan ||
            $this->db->trans_status() === false
        ) {
            $this->db->trans_rollback();

            $this->gagal('Transfer gagal diproses!');
            return;
        }

        if (
            (int) $pengirim['cabang_id'] !==
            (int) $penerima['cabang_id']
        ) {
            if (!$this->buatKewajibanAntarCabang(
                $idTransfer,
                $kodeTransfer,
                $nominal,
                (int) $pengirim['cabang_id'],
                (int) $penerima['cabang_id'],
                $idPengirim
            )) {
                $this->db->trans_rollback();

                $this->gagal(
                    'Transfer lintas cabang gagal mencatat kewajiban settlement!'
                );
                return;
            }
        }

        $this->db->trans_commit();

        $this->session->set_flashdata(
            'pesan',
            'Transfer berhasil dengan kode ' . $kodeTransfer
        );

        redirect('admin/transfer');
    }

    public function batalkan($id)
    {
        $this->pastikanPengelola();
        $this->pastikanPost();

        $alasan = trim(
            (string) $this->input->post('alasan_pembatalan', true)
        );

        if (strlen($alasan) < 10 || strlen($alasan) > 500) {
            $this->gagal(
                'Alasan pembatalan wajib diisi antara 10 sampai 500 karakter.'
            );
            return;
        }

        $this->db->trans_begin();

        $transfer = $this->db->query(
            'SELECT * FROM tb_transfer WHERE id = ? FOR UPDATE',
            [(int) $id]
        )->row_array();

        if (!$transfer) {
            $this->batalkanTransaksi('Transfer tidak ditemukan!');
            return;
        }

        if (
            !$this->isSuperAdmin &&
            (int) $transfer['cabang_asal_id'] !== $this->cabangId
        ) {
            $this->batalkanTransaksi(
                'Hanya Administrator cabang pengirim yang dapat membatalkan transfer!'
            );
            return;
        }

        if (
            $transfer['status_transfer'] !== 'Sukses' ||
            !empty($transfer['dibatalkan_pada'])
        ) {
            $this->batalkanTransaksi(
                'Transfer sudah dibatalkan atau tidak lagi berstatus sukses.'
            );
            return;
        }

        $idPengirim = (int) $transfer['idPengirim'];
        $idPenerima = (int) $transfer['idPenerima'];
        $nominal = (int) $transfer['nominal'];

        $this->kunciAkunTransfer($idPengirim, $idPenerima);

        $saldoPenerima = $this->hitungSaldoNasabah($idPenerima);

        if ($saldoPenerima < $nominal) {
            $this->batalkanTransaksi(
                'Pembatalan otomatis ditolak karena saldo penerima sudah tidak mencukupi. ' .
                    'Lakukan rekonsiliasi manual terlebih dahulu.'
            );
            return;
        }

        if (
            (int) $transfer['cabang_asal_id'] !==
            (int) $transfer['cabang_tujuan_id']
        ) {
            $kewajiban = $this->db->query(
                "SELECT * FROM tb_kewajiban_antar_cabang
                 WHERE jenis_sumber = 'TransferNasabah'
                   AND referensi_id = ?
                 FOR UPDATE",
                [(int) $transfer['id']]
            )->row_array();

            if (!$kewajiban) {
                $this->batalkanTransaksi(
                    'Kewajiban settlement transfer tidak ditemukan. ' .
                        'Pembatalan dihentikan untuk mencegah selisih antar cabang.'
                );
                return;
            }

            if ($kewajiban['status'] !== 'Terbuka') {
                $this->batalkanTransaksi(
                    'Transfer sudah masuk proses settlement. ' .
                        'Gunakan prosedur reversal settlement.'
                );
                return;
            }

            $this->db
                ->where('id_kewajiban', (int) $kewajiban['id_kewajiban'])
                ->where('status', 'Terbuka')
                ->update('tb_kewajiban_antar_cabang', [
                    'status'            => 'Dibatalkan',
                    'dibatalkan_pada'   => date('Y-m-d H:i:s'),
                    'catatan_status'    =>
                        'Dibatalkan bersama transfer ' .
                        $transfer['kode_transfer'] . ': ' . $alasan,
                    'diperbarui_pada'   => date('Y-m-d H:i:s')
                ]);

            if ($this->db->affected_rows() !== 1) {
                $this->batalkanTransaksi(
                    'Status kewajiban settlement berubah. Pembatalan dihentikan.'
                );
                return;
            }
        }

        $sekarang = date('Y-m-d H:i:s');

        $this->db
            ->where('id', (int) $transfer['id'])
            ->where('status_transfer', 'Sukses')
            ->where('dibatalkan_pada IS NULL', null, false)
            ->update('tb_transfer', [
                'status_transfer'   => 'Dibatalkan',
                'dibatalkan_oleh'   =>
                    (int) $this->session->userdata('id'),
                'dibatalkan_pada'   => $sekarang,
                'alasan_pembatalan' => $alasan
            ]);

        if (
            $this->db->affected_rows() !== 1 ||
            $this->db->trans_status() === false
        ) {
            $this->batalkanTransaksi(
                'Transfer gagal dibatalkan atau sudah diproses sebelumnya.'
            );
            return;
        }

        $this->db->trans_commit();

        $this->simpanNotifikasiPembatalan(
            $idPengirim,
            $idPenerima,
            $nominal,
            $transfer['kode_transfer'],
            $alasan
        );

        $this->session->set_flashdata(
            'pesan',
            'Transfer ' . $transfer['kode_transfer'] .
                ' berhasil dibatalkan dan saldo dikembalikan otomatis.'
        );

        redirect('admin/transfer');
    }

    private function buatKewajibanAntarCabang(
        $idTransfer,
        $kodeTransfer,
        $nominal,
        $cabangAsalId,
        $cabangTujuanId,
        $dibuatOleh
    ) {
        if (!$this->db->table_exists('tb_kewajiban_antar_cabang')) {
            return false;
        }

        $kodeKewajiban = 'KWA-TRF-' . str_pad(
            (string) $idTransfer,
            10,
            '0',
            STR_PAD_LEFT
        );

        $berhasil = $this->db->insert(
            'tb_kewajiban_antar_cabang',
            [
                'kode_kewajiban'   => $kodeKewajiban,
                'jenis_sumber'     => 'TransferNasabah',
                'referensi_id'     => (int) $idTransfer,
                'cabang_asal_id'   => (int) $cabangAsalId,
                'cabang_tujuan_id' => (int) $cabangTujuanId,
                'nominal'          => (int) $nominal,
                'status'           => 'Terbuka',
                'dibuat_oleh'      => (int) $dibuatOleh,
                'catatan_status'   =>
                    'Dibuat otomatis dari transfer web ' . $kodeTransfer
            ]
        );

        return $berhasil && $this->db->affected_rows() === 1;
    }

    private function kunciAkunTransfer($idPengirim, $idPenerima)
    {
        $ids = [(int) $idPengirim, (int) $idPenerima];
        sort($ids, SORT_NUMERIC);

        $this->db->query(
            'SELECT id FROM tb_user WHERE id IN (?, ?) ORDER BY id FOR UPDATE',
            $ids
        );
    }

    private function batalkanTransaksi($pesan)
    {
        $this->db->trans_rollback();
        $this->gagal($pesan);
    }

    private function simpanNotifikasiPembatalan(
        $idPengirim,
        $idPenerima,
        $nominal,
        $kodeTransfer,
        $alasan
    ) {
        if (!$this->db->table_exists('tb_notifikasi')) {
            return;
        }

        $nominalFormat = 'Rp ' . number_format($nominal, 0, ',', '.');
        $tanggal = date('Y-m-d H:i:s');
        $alasanSingkat = substr($alasan, 0, 150);

        $this->db->insert_batch('tb_notifikasi', [
            [
                'id_user' => (int) $idPengirim,
                'judul'   => 'Transfer Dibatalkan',
                'pesan'   => 'Transfer ' . $kodeTransfer . ' sebesar ' .
                    $nominalFormat . ' dibatalkan. Saldo telah dikembalikan. ' .
                    'Alasan: ' . $alasanSingkat,
                'tanggal' => $tanggal
            ],
            [
                'id_user' => (int) $idPenerima,
                'judul'   => 'Transfer Dibatalkan',
                'pesan'   => 'Transfer ' . $kodeTransfer . ' sebesar ' .
                    $nominalFormat . ' dibatalkan. Saldo penerimaan disesuaikan. ' .
                    'Alasan: ' . $alasanSingkat,
                'tanggal' => $tanggal
            ]
        ]);
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

    private function pastikanPengelola()
    {
        if (
            !in_array(
                $this->userLevel,
                ['administrator', 'super admin'],
                true
            )
        ) {
            $this->gagal('Akses pembatalan transfer ditolak!');
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

    private function gagal($pesan)
    {
        $this->session->set_flashdata(
            'pesanError',
            $pesan
        );

        redirect('admin/transfer');
    }
}
