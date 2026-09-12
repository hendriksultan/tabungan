<?php
defined('BASEPATH') or exit('No direct script access allowed');

class Rekening extends CI_Controller
{
    private $userLevel = '';
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

        $this->userLevel = strtolower(trim(
            (string) $this->session->userdata('level')
        ));
        $this->isSuperAdmin = $this->userLevel === 'super admin';
        $this->cabangId = (int) $this->session->userdata('cabang_id');

        if (!in_array(
            $this->userLevel,
            ['administrator', 'super admin'],
            true
        )) {
            $this->session->set_flashdata(
                'pesanError',
                'Akses ditolak!'
            );
            redirect('admin/dashboard');
            return;
        }

        if (!$this->isSuperAdmin && $this->cabangId <= 0) {
            $this->session->set_flashdata(
                'pesanError',
                'Administrator belum terhubung dengan cabang!'
            );
            redirect('admin/dashboard');
            return;
        }
    }

    public function index()
    {
        $data['title'] = 'Rekening Penampungan';
        $data['subtitle'] = $this->isSuperAdmin
            ? 'Pantau rekening penampungan seluruh cabang'
            : 'Kelola rekening penampungan cabang Anda';
        $data['isSuperAdmin'] = $this->isSuperAdmin;

        $this->db->select([
            'r.*',
            'c.kode AS kode_cabang',
            'c.nama AS nama_cabang'
        ]);
        $this->db->from('tb_rekening_penampungan AS r');
        $this->db->join('tb_cabang AS c', 'c.id = r.cabang_id', 'inner');

        if (!$this->isSuperAdmin) {
            $this->db->where('r.cabang_id', $this->cabangId);
        }

        $this->db->order_by('c.is_pusat', 'DESC');
        $this->db->order_by('c.nama', 'ASC');
        $this->db->order_by('r.urutan', 'ASC');
        $this->db->order_by('r.id', 'ASC');
        $data['rekening'] = $this->db->get();

        $this->load->view('admin/templates/header', $data);
        $this->load->view('admin/templates/sidebar');
        $this->load->view('admin/rekening', $data);
        $this->load->view('admin/templates/footer');
    }

    public function insert()
    {
        if (!$this->pastikan_administrator()) {
            return;
        }

        $data = $this->validasi_input();
        if ($data === null) {
            return;
        }

        $data['cabang_id'] = $this->cabangId;
        $data['created_by'] = (int) $this->session->userdata('id');
        $data['updated_by'] = (int) $this->session->userdata('id');
        $data['created_at'] = date('Y-m-d H:i:s');
        $data['updated_at'] = date('Y-m-d H:i:s');

        if ($this->rekening_sudah_ada($data['nomor_rekening'])) {
            $this->gagal('Nomor rekening sudah terdaftar pada cabang Anda.');
            return;
        }

        if ($this->db->insert('tb_rekening_penampungan', $data)) {
            $this->session->set_flashdata(
                'pesan',
                'Rekening penampungan berhasil ditambahkan!'
            );
        } else {
            $this->session->set_flashdata(
                'pesanError',
                'Rekening penampungan gagal ditambahkan!'
            );
        }

        redirect('admin/rekening');
    }

    public function update($id)
    {
        if (!$this->pastikan_administrator()) {
            return;
        }

        $rekening = $this->rekening_cabang($id);
        if (!$rekening) {
            $this->gagal('Rekening tidak ditemukan pada cabang Anda.');
            return;
        }

        $data = $this->validasi_input();
        if ($data === null) {
            return;
        }

        if ($this->rekening_sudah_ada(
            $data['nomor_rekening'],
            (int) $rekening['id']
        )) {
            $this->gagal('Nomor rekening sudah terdaftar pada cabang Anda.');
            return;
        }

        $data['updated_by'] = (int) $this->session->userdata('id');
        $data['updated_at'] = date('Y-m-d H:i:s');

        $this->db->where('id', (int) $rekening['id']);
        $this->db->where('cabang_id', $this->cabangId);

        if ($this->db->update('tb_rekening_penampungan', $data)) {
            $this->session->set_flashdata(
                'pesan',
                'Rekening penampungan berhasil diperbarui!'
            );
        } else {
            $this->session->set_flashdata(
                'pesanError',
                'Rekening penampungan gagal diperbarui!'
            );
        }

        redirect('admin/rekening');
    }

    public function toggle_status($id)
    {
        if (!$this->pastikan_administrator()) {
            return;
        }

        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            $this->gagal('Gunakan metode POST.');
            return;
        }

        $rekening = $this->rekening_cabang($id);
        if (!$rekening) {
            $this->gagal('Rekening tidak ditemukan pada cabang Anda.');
            return;
        }

        $status = $rekening['status'] === 'Aktif'
            ? 'Nonaktif'
            : 'Aktif';

        $this->db->where('id', (int) $rekening['id']);
        $this->db->where('cabang_id', $this->cabangId);

        $berhasil = $this->db->update('tb_rekening_penampungan', [
            'status'     => $status,
            'updated_by' => (int) $this->session->userdata('id'),
            'updated_at' => date('Y-m-d H:i:s')
        ]);

        $this->session->set_flashdata(
            $berhasil ? 'pesan' : 'pesanError',
            $berhasil
                ? 'Status rekening berhasil diperbarui!'
                : 'Status rekening gagal diperbarui!'
        );
        redirect('admin/rekening');
    }

    private function validasi_input()
    {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            $this->gagal('Gunakan metode POST.');
            return null;
        }

        $jenis = trim((string) $this->input->post('jenis', true));
        $namaBank = trim((string) $this->input->post('nama_bank', true));
        $nomor = preg_replace(
            '/\s+/',
            '',
            trim((string) $this->input->post('nomor_rekening', true))
        );
        $atasNama = trim((string) $this->input->post('atas_nama', true));
        $urutan = (int) $this->input->post('urutan', true);

        if (!in_array($jenis, ['Bank', 'E-Wallet', 'Lainnya'], true)) {
            $this->gagal('Jenis rekening tidak valid.');
            return null;
        }

        if ($namaBank === '' || $nomor === '' || $atasNama === '') {
            $this->gagal('Nama layanan, nomor rekening, dan atas nama wajib diisi.');
            return null;
        }

        if (
            strlen($namaBank) > 100 ||
            strlen($nomor) > 50 ||
            strlen($atasNama) > 150
        ) {
            $this->gagal('Data rekening melebihi batas karakter.');
            return null;
        }

        if (!preg_match('/^[0-9A-Za-z.\-+]+$/', $nomor)) {
            $this->gagal('Nomor rekening mengandung karakter yang tidak valid.');
            return null;
        }

        return [
            'jenis'          => $jenis,
            'nama_bank'      => $namaBank,
            'nomor_rekening' => $nomor,
            'atas_nama'      => $atasNama,
            'icon'           => $jenis === 'E-Wallet' ? 'wallet' : 'card',
            'urutan'         => max(0, min($urutan, 9999))
        ];
    }

    private function rekening_cabang($id)
    {
        return $this->db->get_where('tb_rekening_penampungan', [
            'id'        => (int) $id,
            'cabang_id' => $this->cabangId
        ])->row_array();
    }

    private function rekening_sudah_ada($nomor, $kecualiId = 0)
    {
        $this->db->where('cabang_id', $this->cabangId);
        $this->db->where('nomor_rekening', $nomor);

        if ($kecualiId > 0) {
            $this->db->where('id !=', $kecualiId);
        }

        return $this->db
            ->get('tb_rekening_penampungan')
            ->num_rows() > 0;
    }

    private function pastikan_administrator()
    {
        if ($this->isSuperAdmin) {
            $this->gagal(
                'Super Admin hanya dapat memantau rekening seluruh cabang.'
            );
            return false;
        }

        return $this->userLevel === 'administrator';
    }

    private function gagal($pesan)
    {
        $this->session->set_flashdata('pesanError', $pesan);
        redirect('admin/rekening');
    }
}
