<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Potongan extends CI_Controller {

	public function __construct()
	{
		parent::__construct();
		if(!$this->session->userdata('level')){
			$this->session->set_flashdata('pesan', 'Anda harus masuk terlebih dahulu!');
			redirect('home');
		}

        // PERBAIKAN 1: Amankan seluruh Controller hanya untuk Admin & Super Admin
        $userLevel = strtolower($this->session->userdata('level'));
        if($userLevel != 'administrator' && $userLevel != 'super admin') {
            $this->session->set_flashdata('pesan', 'Akses Ditolak!');
            redirect('admin/dashboard');
        }
	}

	public function index()
	{
		$data['title']		= 'Data Potongan';
		$data['subtitle']	= 'Semua data potongan akan ditampilkan disini';
		
        $data['potongan']   = $this->m_model->get_desc('tb_potongan');

		$this->load->view('admin/templates/header', $data);
		$this->load->view('admin/templates/sidebar');
		$this->load->view('admin/potongan');
		$this->load->view('admin/templates/footer');
    }
    
    public function delete($id)
    {
        $where = array('id' => $id );

        $this->m_model->delete($where, 'tb_potongan');
        $this->session->set_flashdata('pesan','Data berhasil dihapus!');
        redirect('admin/potongan');
    }

    public function insert()
    {
        date_default_timezone_set('Asia/Jakarta');

        $idAdmin        = $this->session->userdata('id');
        // PERBAIKAN 2: Gunakan Security Input Class bawaan CodeIgniter
        $nominal        = $this->input->post('nominal');
        $keterangan     = $this->input->post('keterangan');
        $terdaftar      = date('Y-m-d H:i:s');

        $data = array(
            'idAdmin'       => $idAdmin,
            'nominal'       => $nominal,
            'keterangan'    => $keterangan,
            'terdaftar'     => $terdaftar,
        );

        $this->m_model->insert($data, 'tb_potongan');

        foreach ($this->m_model->get_where($data, 'tb_potongan')->result() as $dPot) {
            $this->db->where('level', 'Nasabah');
            foreach ($this->db->get('tb_user')->result() as $dNsbh) {
                $dataInsert = array(
                    'idNasabah'     => $dNsbh->id,
                    'idPotongan'    => $dPot->id,
                    'idAdmin'       => $idAdmin,
                    'nominal'       => $nominal,
                    'jenis'         => 'keluar', // Atau Keluar jika di database kapital
                    'keterangan'    => $keterangan,
                    'terdaftar'     => $terdaftar,
                    'tanggal'       => date('Y-m-d'),
                );

                $this->m_model->insert($dataInsert, 'tb_transaksi');
            }
        }

        $this->session->set_flashdata('pesan','Data berhasil ditambahkan!');
        redirect('admin/potongan');
    }
}