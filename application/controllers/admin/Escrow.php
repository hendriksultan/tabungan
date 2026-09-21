<?php
defined('BASEPATH') or exit('No direct script access allowed');

class Escrow extends CI_Controller
{
    private $level = '';
    private $isSuperAdmin = false;
    private $cabangId = 0;
    private $userId = 0;

    public function __construct()
    {
        parent::__construct();
        date_default_timezone_set('Asia/Jakarta');

        if (!$this->session->userdata('level')) {
            redirect('home');
            return;
        }

        $this->level = strtolower(trim((string) $this->session->userdata('level')));
        $this->isSuperAdmin = $this->level === 'super admin';
        $this->cabangId = (int) $this->session->userdata('cabang_id');
        $this->userId = (int) $this->session->userdata('id');

        if (!in_array($this->level, ['administrator', 'super admin'], true)) {
            $this->gagal('Akses escrow hanya untuk Administrator.');
            return;
        }
        if (!$this->isSuperAdmin && $this->cabangId <= 0) {
            $this->gagal('Administrator belum terhubung dengan cabang.');
        }
    }

    public function index()
    {
        $data['title'] = 'Escrow Marketplace';
        $data['subtitle'] = $this->isSuperAdmin
            ? 'Pantau dan tangani dana marketplace seluruh cabang'
            : 'Pantau dana marketplace yang melibatkan cabang Anda';
        $data['isSuperAdmin'] = $this->isSuperAdmin;
        $data['escrow'] = $this->ambilEscrow();

        $this->load->view('admin/templates/header', $data);
        $this->load->view('admin/templates/sidebar');
        $this->load->view('admin/escrow', $data);
        $this->load->view('admin/templates/footer');
    }

    public function cairkan($idEscrow)
    {
        if (!$this->pastikanSuperAdmin()) {
            return;
        }
        $this->pastikanPost();
        $this->db->trans_begin();
        $row = $this->kunciEscrow((int) $idEscrow);

        if (!$row || $row['status'] !== 'Sengketa') {
            $this->batalkan('Escrow tidak ditemukan atau tidak dapat dicairkan.');
            return;
        }
        if ($row['status_pesanan'] !== 'Dikirim') {
            $this->batalkan('Dana hanya dapat dicairkan setelah pesanan dikirim.');
            return;
        }
        if (!$this->pembayaranValid($row)) {
            $this->batalkan('Transaksi pembayaran escrow tidak valid.');
            return;
        }

        $detail = $this->detailPesanan((int) $row['id_pesanan']);
        if (empty($detail)) {
            $this->batalkan('Detail pesanan tidak ditemukan.');
            return;
        }

        $sekarang = date('Y-m-d H:i:s');
        $ok = $this->db->insert('tb_transaksi', [
            'cabang_id' => (int) $row['cabang_penjual_id'],
            'idAdmin' => $this->userId,
            'idNasabah' => (int) $row['id_penjual'],
            'idPotongan' => 0,
            'tanggal' => date('Y-m-d'),
            'nominal' => (int) $row['total_dana'],
            'gram_emas' => null,
            'jenis' => 'Masuk',
            'keterangan' => 'Pencairan Escrow Admin: ' . $row['invoice_pesanan'],
            'status_konfirmasi' => 'Sukses',
            'bukti_transfer' => null,
            'referensi_tipe' => 'PencairanPesanan',
            'referensi_id' => (int) $row['id_pesanan'],
            'terdaftar' => $sekarang
        ]);
        $idPencairan = (int) $this->db->insert_id();

        if (!$ok || $idPencairan <= 0) {
            $this->batalkan('Transaksi pencairan gagal disimpan.');
            return;
        }

        $lintas = (int) $row['cabang_pembeli_id'] !==
            (int) $row['cabang_penjual_id'];
        $idKewajiban = null;
        $kodeKewajiban = null;

        if ($lintas) {
            $kodeKewajiban = 'KWA-MKT-' . str_pad(
                (string) $row['id_pesanan'], 10, '0', STR_PAD_LEFT
            );
            $ok = $this->db->insert('tb_kewajiban_antar_cabang', [
                'kode_kewajiban' => $kodeKewajiban,
                'jenis_sumber' => 'Marketplace',
                'referensi_id' => (int) $row['id_pesanan'],
                'cabang_asal_id' => (int) $row['cabang_pembeli_id'],
                'cabang_tujuan_id' => (int) $row['cabang_penjual_id'],
                'nominal' => (int) $row['total_dana'],
                'status' => 'Terbuka',
                'dibuat_oleh' => $this->userId,
                'catatan_status' => 'Dibuat dari pencairan escrow oleh Super Admin'
            ]);
            $idKewajiban = (int) $this->db->insert_id();
            if (!$ok || $idKewajiban <= 0) {
                $this->batalkan('Kewajiban antar-cabang gagal dibuat.');
                return;
            }
        }

        $statusEscrow = $lintas ? 'MenungguSettlement' : 'Cair';
        $this->db->where('id_escrow', (int) $row['id_escrow']);
        $this->db->where('status', 'Sengketa');
        $this->db->where('id_transaksi_pencairan IS NULL', null, false);
        $this->db->where('id_transaksi_refund IS NULL', null, false);
        $this->db->update('tb_escrow_marketplace', [
            'id_transaksi_pencairan' => $idPencairan,
            'id_kewajiban' => $idKewajiban,
            'status' => $statusEscrow,
            'dicairkan_pada' => $sekarang,
            'diselesaikan_oleh' => $this->userId,
            'diselesaikan_pada' => $sekarang,
            'catatan' => 'Dicairkan oleh Super Admin' .
                ($kodeKewajiban ? '; ' . $kodeKewajiban : '')
        ]);
        if ($this->db->affected_rows() !== 1) {
            $this->batalkan('Status escrow berubah. Pencairan dihentikan.');
            return;
        }

        $this->db->where('id_pesanan', (int) $row['id_pesanan']);
        $this->db->where('status_pesanan', 'Dikirim');
        $this->db->update('tb_pesanan', ['status_pesanan' => 'Selesai']);
        if ($this->db->affected_rows() !== 1) {
            $this->batalkan('Status pesanan berubah. Pencairan dihentikan.');
            return;
        }

        foreach ($detail as $item) {
            $this->db->set('terjual',
                'COALESCE(terjual, 0) + ' . (int) $item['jumlah'], false);
            $this->db->where('id_produk', (int) $item['id_produk']);
            $this->db->update('tb_produk');
            if ($this->db->affected_rows() !== 1) {
                $this->batalkan('Jumlah produk terjual gagal diperbarui.');
                return;
            }
        }

        $this->notifikasi((int) $row['id_penjual'], 'Dana Escrow Dicairkan',
            'Dana pesanan ' . $row['invoice_pesanan'] . ' sebesar Rp ' .
            number_format((int) $row['total_dana'], 0, ',', '.') .
            ' telah masuk ke saldo Anda.', $sekarang);

        if ($this->db->trans_status() === false) {
            $this->batalkan('Pencairan escrow gagal.');
            return;
        }
        $this->db->trans_commit();
        $this->sukses('Dana escrow berhasil dicairkan.');
    }

    public function refund($idEscrow)
    {
        if (!$this->pastikanSuperAdmin()) {
            return;
        }
        $this->pastikanPost();
        $alasan = trim((string) $this->input->post('alasan', true));
        if (mb_strlen($alasan) < 10 || mb_strlen($alasan) > 500) {
            $this->gagal('Alasan refund harus terdiri dari 10 sampai 500 karakter.');
            return;
        }

        $this->db->trans_begin();
        $row = $this->kunciEscrow((int) $idEscrow);
        if (!$row || $row['status'] !== 'Sengketa') {
            $this->batalkan('Escrow tidak ditemukan atau tidak dapat direfund.');
            return;
        }
        if (!in_array($row['status_pesanan'], ['Diproses', 'Dikirim'], true) ||
            !$this->pembayaranValid($row)) {
            $this->batalkan('Status pesanan atau pembayaran escrow tidak valid.');
            return;
        }

        $detail = $this->detailPesanan((int) $row['id_pesanan']);
        if (empty($detail)) {
            $this->batalkan('Detail pesanan tidak ditemukan.');
            return;
        }

        $sekarang = date('Y-m-d H:i:s');
        $ok = $this->db->insert('tb_transaksi', [
            'cabang_id' => (int) $row['cabang_pembeli_id'],
            'idAdmin' => $this->userId,
            'idNasabah' => (int) $row['id_pembeli'],
            'idPotongan' => 0,
            'tanggal' => date('Y-m-d'),
            'nominal' => (int) $row['total_dana'],
            'gram_emas' => null,
            'jenis' => 'Masuk',
            'keterangan' => 'Refund Escrow Admin: ' . $row['invoice_pesanan'],
            'status_konfirmasi' => 'Sukses',
            'bukti_transfer' => null,
            'referensi_tipe' => 'RefundPesanan',
            'referensi_id' => (int) $row['id_pesanan'],
            'terdaftar' => $sekarang
        ]);
        $idRefund = (int) $this->db->insert_id();
        if (!$ok || $idRefund <= 0) {
            $this->batalkan('Transaksi refund gagal disimpan.');
            return;
        }

        $this->db->where('id_escrow', (int) $row['id_escrow']);
        $this->db->where('status', 'Sengketa');
        $this->db->where('id_transaksi_pencairan IS NULL', null, false);
        $this->db->where('id_transaksi_refund IS NULL', null, false);
        $this->db->update('tb_escrow_marketplace', [
            'id_transaksi_refund' => $idRefund,
            'status' => 'Dikembalikan',
            'dikembalikan_pada' => $sekarang,
            'diselesaikan_oleh' => $this->userId,
            'diselesaikan_pada' => $sekarang,
            'catatan' => 'Refund oleh Super Admin: ' . $alasan
        ]);
        if ($this->db->affected_rows() !== 1) {
            $this->batalkan('Status escrow berubah. Refund dihentikan.');
            return;
        }

        $this->db->where('id_pesanan', (int) $row['id_pesanan']);
        $this->db->where_in('status_pesanan', ['Diproses', 'Dikirim']);
        $this->db->where('stok_dikembalikan', 0);
        $this->db->update('tb_pesanan', [
            'status_pesanan' => 'Dibatalkan',
            'stok_dikembalikan' => 1,
            'dibatalkan_oleh' => $this->userId,
            'dibatalkan_pada' => $sekarang,
            'alasan_pembatalan' => $alasan,
            'id_transaksi_refund' => $idRefund,
            'nominal_refund' => (int) $row['total_dana'],
            'refund_pada' => $sekarang
        ]);
        if ($this->db->affected_rows() !== 1) {
            $this->batalkan('Status pesanan berubah. Refund dihentikan.');
            return;
        }

        foreach ($detail as $item) {
            $this->db->set('stok', 'stok + ' . (int) $item['jumlah'], false);
            $this->db->set('status_produk',
                "CASE WHEN status_produk = 'Habis' THEN 'Tersedia' ELSE status_produk END",
                false);
            $this->db->where('id_produk', (int) $item['id_produk']);
            $this->db->update('tb_produk');
            if ($this->db->affected_rows() !== 1) {
                $this->batalkan('Stok produk gagal dikembalikan.');
                return;
            }
        }

        $this->notifikasi((int) $row['id_pembeli'], 'Dana Escrow Dikembalikan',
            'Dana pesanan ' . $row['invoice_pesanan'] . ' sebesar Rp ' .
            number_format((int) $row['total_dana'], 0, ',', '.') .
            ' telah dikembalikan. Alasan: ' . $alasan, $sekarang);

        if ($this->db->trans_status() === false) {
            $this->batalkan('Refund escrow gagal.');
            return;
        }
        $this->db->trans_commit();
        $this->sukses('Dana escrow berhasil dikembalikan kepada pembeli.');
    }

    private function ambilEscrow()
    {
        $this->db->select([
            'e.*', 'p.invoice_pesanan', 'p.status_pesanan', 'p.kurir',
            'p.resi', 'pembeli.nama AS nama_pembeli',
            'penjual.nama AS nama_penjual', 'toko.nama_toko',
            'asal.kode AS kode_cabang_pembeli',
            'asal.nama AS nama_cabang_pembeli',
            'tujuan.kode AS kode_cabang_penjual',
            'tujuan.nama AS nama_cabang_penjual',
            'k.kode_kewajiban', 'k.status AS status_kewajiban'
        ]);
        $this->db->from('tb_escrow_marketplace AS e');
        $this->db->join('tb_pesanan AS p', 'p.id_pesanan = e.id_pesanan');
        $this->db->join('tb_user AS pembeli', 'pembeli.id = e.id_pembeli');
        $this->db->join('tb_user AS penjual', 'penjual.id = e.id_penjual');
        $this->db->join('tb_toko AS toko', 'toko.id_user = e.id_penjual');
        $this->db->join('tb_cabang AS asal', 'asal.id = e.cabang_pembeli_id');
        $this->db->join('tb_cabang AS tujuan', 'tujuan.id = e.cabang_penjual_id');
        $this->db->join('tb_kewajiban_antar_cabang AS k',
            'k.id_kewajiban = e.id_kewajiban', 'left');

        if (!$this->isSuperAdmin) {
            $this->db->group_start();
            $this->db->where('e.cabang_pembeli_id', $this->cabangId);
            $this->db->or_where('e.cabang_penjual_id', $this->cabangId);
            $this->db->group_end();
        }
        $this->db->order_by('e.id_escrow', 'DESC');
        return $this->db->get();
    }

    private function kunciEscrow($idEscrow)
    {
        return $this->db->query(
            "SELECT e.*, p.invoice_pesanan, p.status_pesanan,
                    p.stok_dikembalikan,
                    p.id_transaksi_pembayaran AS pesanan_transaksi_pembayaran,
                    p.nominal_dibayar, p.pembayaran_oleh
             FROM tb_escrow_marketplace AS e
             INNER JOIN tb_pesanan AS p ON p.id_pesanan = e.id_pesanan
             WHERE e.id_escrow = ? LIMIT 1 FOR UPDATE",
            [$idEscrow]
        )->row_array();
    }

    private function pembayaranValid(array $row)
    {
        if (!empty($row['id_transaksi_pencairan']) ||
            !empty($row['id_transaksi_refund']) ||
            (int) $row['pesanan_transaksi_pembayaran'] !==
                (int) $row['id_transaksi_pembayaran'] ||
            (int) $row['nominal_dibayar'] !== (int) $row['total_dana'] ||
            (int) $row['pembayaran_oleh'] !== (int) $row['id_pembeli']) {
            return false;
        }

        $trx = $this->db->query(
            "SELECT * FROM tb_transaksi WHERE id = ? LIMIT 1 FOR UPDATE",
            [(int) $row['id_transaksi_pembayaran']]
        )->row_array();

        return $trx &&
            (int) $trx['idNasabah'] === (int) $row['id_pembeli'] &&
            (int) $trx['nominal'] === (int) $row['total_dana'] &&
            $trx['jenis'] === 'Keluar' &&
            $trx['status_konfirmasi'] === 'Sukses' &&
            $trx['referensi_tipe'] === 'PembayaranPesanan' &&
            (int) $trx['referensi_id'] === (int) $row['id_pesanan'];
    }

    private function detailPesanan($idPesanan)
    {
        return $this->db->select(['id_produk', 'jumlah'])
            ->from('tb_pesanan_detail')->where('id_pesanan', $idPesanan)
            ->order_by('id_produk', 'ASC')->get()->result_array();
    }

    private function notifikasi($idUser, $judul, $pesan, $tanggal)
    {
        $this->db->insert('tb_notifikasi', [
            'id_user' => $idUser, 'judul' => $judul, 'pesan' => $pesan,
            'is_read' => 0, 'tanggal' => $tanggal
        ]);
    }

    private function pastikanSuperAdmin()
    {
        if (!$this->isSuperAdmin) {
            $this->gagal('Penyelesaian sengketa hanya dapat dilakukan Super Admin.');
            return false;
        }
        return true;
    }

    private function pastikanPost()
    {
        if ($this->input->method(true) !== 'POST') {
            show_error('Metode request tidak diizinkan.', 405);
        }
    }

    private function batalkan($pesan)
    {
        $this->db->trans_rollback();
        $this->gagal($pesan);
    }

    private function gagal($pesan)
    {
        $this->session->set_flashdata('pesan', $pesan);
        $this->session->set_flashdata('tipe', 'error');
        redirect('admin/escrow');
    }

    private function sukses($pesan)
    {
        $this->session->set_flashdata('pesan', $pesan);
        $this->session->set_flashdata('tipe', 'success');
        redirect('admin/escrow');
    }
}
