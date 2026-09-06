<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Transfer extends CI_Controller {

	public function __construct()
	{
		parent::__construct();
		if(!$this->session->userdata('level')){
			$this->session->set_flashdata('pesan', 'Anda harus masuk terlebih dahulu!');
			redirect('home');
		}
	}

	public function index()
	{
		$data['title']		= 'Data Transfer';
		$data['subtitle']	= 'Menampilkan semua data transfer';

        $this->db->where('level', 'Nasabah');
        $this->db->where('id !=', $this->session->userdata('id'));
        $data['nasabah']    = $this->m_model->get_desc('tb_user');
        
        // PERBAIKAN 1: Gabungkan akses query untuk Super Admin
        $userLevel = strtolower($this->session->userdata('level'));
        if($userLevel == 'administrator' || $userLevel == 'super admin') {
            $data['transfer']   = $this->m_model->get_desc('tb_transfer');   
        } else {
            $data['transfer']   = $this->db->query('SELECT * FROM tb_transfer WHERE idPengirim="'.$this->session->userdata('id').'" OR idPenerima="'.$this->session->userdata('id').'" ORDER BY id DESC');
        }
		
		$this->load->view('admin/templates/header', $data);
		$this->load->view('admin/templates/sidebar');
		$this->load->view('admin/transfer');
		$this->load->view('admin/templates/footer');
    }
    
     public function delete($id)
    {
        // PERBAIKAN 2: Amankan fungsi delete hanya untuk pengurus
        $userLevel = strtolower($this->session->userdata('level'));
        if($userLevel != 'administrator' && $userLevel != 'super admin') {
            $this->session->set_flashdata('pesan', 'Akses Ditolak: Anda tidak memiliki izin untuk menghapus data!');
            redirect('admin/transfer');
        }

        $where = array('id' => $id );

        $this->m_model->delete($where, 'tb_transfer');
        $this->session->set_flashdata('pesan','Data berhasil dihapus!');
        redirect('admin/transfer');
    }

    public function insert()
    {
        date_default_timezone_set('Asia/Jakarta');

        $idPengirim     = $this->session->userdata('id');
        // PERBAIKAN 3: Gunakan input library CI untuk keamanan XSS
        $idPenerima     = $this->input->post('idPenerima');
        $nominal        = $this->input->post('nominal');
        $keterangan     = $this->input->post('keterangan');
        $terdaftar      = date('Y-m-d H:i:s');

        $idNasabah      = $idPengirim;

        foreach ($this->db->query('SELECT SUM(nominal) AS totalTabunganMasuk FROM tb_transaksi WHERE idNasabah="'.$idNasabah.'" AND jenis="Masuk"')->result() as $tbMsk) {}
        foreach ($this->db->query('SELECT SUM(nominal) AS totalTransferMasuk FROM tb_transfer WHERE idPenerima="'.$idNasabah.'"')->result() as $tfMsk) {}

        $totalMasuk = $tbMsk->totalTabunganMasuk + $tfMsk->totalTransferMasuk ;

        foreach ($this->db->query('SELECT SUM(nominal) AS totalTabunganKeluar FROM tb_transaksi WHERE idNasabah="'.$idNasabah.'" AND jenis="Keluar"')->result() as $tbKlr) {}
        foreach ($this->db->query('SELECT SUM(nominal) AS totalTransferKeluar FROM tb_transfer WHERE idPengirim="'.$idNasabah.'"')->result() as $tfKlr) {}

        $totalKeluar = $tbKlr->totalTabunganKeluar + $tfKlr->totalTransferKeluar ;

        $sisaSaldo  = $totalMasuk - $totalKeluar;

        if($nominal > 0) {
            if($sisaSaldo >= $nominal) {
                $data = array(
                    'idPengirim'    => $idPengirim,
                    'idPenerima'    => $idPenerima,
                    'nominal'       => $nominal,
                    'keterangan'    => $keterangan,
                    'terdaftar'     => $terdaftar,
                );
    
                $this->m_model->insert($data, 'tb_transfer');
                $this->session->set_flashdata('pesan','Data berhasil ditambahkan!');
            } else {
                $this->session->set_flashdata('pesan','Saldo anda tidak cukup!');
            }
        } else {
            $this->session->set_flashdata('pesan','Nominal tidak valid');
        }

        redirect('admin/transfer');
    }
}