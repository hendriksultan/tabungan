<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Log extends CI_Controller {

	public function __construct()
	{
		parent::__construct();
		if(!$this->session->userdata('level')){
			$this->session->set_flashdata('pesan', 'Anda harus masuk terlebih dahulu!');
			redirect('home');
		} 
        
        // PERBAIKAN: Izinkan Administrator DAN Super Admin
        $userLevel = strtolower($this->session->userdata('level'));
        if($userLevel != 'administrator' && $userLevel != 'super admin') {
			redirect('home');
        }
	}

	public function index()
	{
		$data['title']		= 'Data Log';
		$data['subtitle']	= 'Semua log akan muncul disini';

		$data['log']		= $this->m_model->get_desc('tb_log');
		
		$this->load->view('admin/templates/header', $data);
		$this->load->view('admin/templates/sidebar');
		$this->load->view('admin/log');
		$this->load->view('admin/templates/footer');
	}
	
	public function delete($id)
    {
        $where = array('id' => $id );

        $this->m_model->delete($where, 'tb_log');
        $this->session->set_flashdata('pesan','Data berhasil dihapus!');
        redirect('admin/log');
    }
	
}