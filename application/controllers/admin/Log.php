<?php
defined('BASEPATH') or exit('No direct script access allowed');

class Log extends CI_Controller
{
    private $userLevel = '';
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
            return;
        }

        $this->userLevel = strtolower(trim(
            (string) $this->session->userdata('level')
        ));
        $this->isSuperAdmin = $this->userLevel === 'super admin';
        $this->isKoordinator = $this->userLevel === 'koordinator';
        $this->cabangId = (int) $this->session->userdata('cabang_id');
        $this->cabangIds = $this->cabang_scope->cabangIds();

        if (!in_array(
            $this->userLevel,
            ['administrator', 'koordinator', 'super admin'],
            true
        )) {
            redirect('home');
            return;
        }

        if (
            (!$this->isSuperAdmin && !$this->isKoordinator && $this->cabangId <= 0) ||
            ($this->isKoordinator && empty($this->cabangIds))
        ) {
            $this->session->set_flashdata(
                'pesanError',
                'Akun belum terhubung dengan cakupan cabang aktif!'
            );
            redirect('admin/dashboard');
            return;
        }
    }

    public function index()
    {
        $data['title'] = 'Audit Aktivitas';
        $data['subtitle'] = $this->isSuperAdmin
            ? 'Aktivitas pengguna dari seluruh cabang'
            : ($this->isKoordinator
                ? 'Aktivitas pengguna pada cabang yang ditugaskan'
                : 'Aktivitas pengguna pada cabang Anda');
        $data['isKoordinator'] = $this->isKoordinator;

        $this->db->select([
            'l.*',
            'u.nama AS nama_user',
            'u.level AS level_user',
            'u.cabang_id',
            'c.kode AS kode_cabang',
            'c.nama AS nama_cabang'
        ]);
        $this->db->from('tb_log AS l');
        $this->db->join('tb_user AS u', 'u.id = l.idUser', 'left');
        $this->db->join('tb_cabang AS c', 'c.id = u.cabang_id', 'left');

        if ($this->isKoordinator) {
            $this->db->where_in('u.cabang_id', $this->cabangIds);
        } elseif (!$this->isSuperAdmin) {
            $this->db->where('u.cabang_id', $this->cabangId);
        }

        $this->db->order_by('l.id', 'DESC');
        $data['log'] = $this->db->get();

        $this->load->view('admin/templates/header', $data);
        $this->load->view('admin/templates/sidebar');
        $this->load->view('admin/log', $data);
        $this->load->view('admin/templates/footer');
    }

    public function delete($id)
    {
        if ($this->isKoordinator) {
            $this->session->set_flashdata(
                'pesanError',
                'Koordinator tidak dapat menghapus log audit!'
            );
            redirect('admin/log');
            return;
        }

        $this->db->select('l.id, u.cabang_id');
        $this->db->from('tb_log AS l');
        $this->db->join('tb_user AS u', 'u.id = l.idUser', 'left');
        $this->db->where('l.id', (int) $id);
        $log = $this->db->get()->row_array();

        if (!$log) {
            $this->session->set_flashdata('pesanError', 'Log tidak ditemukan!');
            redirect('admin/log');
            return;
        }

        if (
            !$this->isSuperAdmin &&
            (int) $log['cabang_id'] !== $this->cabangId
        ) {
            $this->session->set_flashdata(
                'pesanError',
                'Anda tidak dapat menghapus log cabang lain!'
            );
            redirect('admin/log');
            return;
        }

        $this->m_model->delete(['id' => (int) $id], 'tb_log');
        $this->session->set_flashdata('pesan', 'Data berhasil dihapus!');
        redirect('admin/log');
    }
}
