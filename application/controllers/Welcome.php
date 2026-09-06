<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Welcome extends CI_Controller {

	public function index()
	{
		$data['title']		= 'Beranda';

		$data['aplikasi']	= $this->m_model->get_desc('tb_aplikasi');

		$this->load->view('beranda', $data);
	}

	public function cariproduk()
	{
		$data['title']		= 'Pencarian : ' . $_GET['nama'];
		$data['subtitle']	= 'Ditampilkan berdasarkan nama pencarian produk';

		$data['aplikasi']	= $this->m_model->get_desc('tb_aplikasi');

		$data['produk']	= $this->db->query('SELECT * FROM tb_produk WHERE nama LIKE "%'.$_GET['nama'].'%"');
		
		$this->load->view('resultberanda', $data);
    }
}
