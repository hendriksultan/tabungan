<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Backupdatabase extends CI_Controller {

	public function __construct()
	{
		parent::__construct();
		if(!$this->session->userdata('level')){
			$this->session->set_flashdata('pesan', 'Anda harus masuk terlebih dahulu!');
			redirect('home');
		} 
        
        // PERBAIKAN: Izinkan Administrator DAN Super Admin
        $userLevel = strtolower($this->session->userdata('level'));
        if ($userLevel != 'administrator' && $userLevel != 'super admin') {
			redirect('home');
        }
	}

	public function index()
	{
        $data['title']      = 'Backup Database';
        $data['subtitle']   = 'Halaman ini untuk backup database';

        $data['backupdb']   = $this->m_model->get_desc('tb_backupdb');
		
		$this->load->view('admin/templates/header', $data);
		$this->load->view('admin/templates/sidebar');
		$this->load->view('admin/backupdatabase');
		$this->load->view('admin/templates/footer');
    }
    
    public function backup_database() {
        
        date_default_timezone_set('Asia/Jakarta');

        $this->load->dbutil();
        $conf = [
            'format'    => 'zip',
            'filename'  => 'Tabungan - backup_db.sql'
        ];
        
        $backup = $this->dbutil->backup($conf);
        $db_name = 'Tabungan - Backup Database.zip';

        $this->load->helper('file');
        write_file('./assets/database_backup/' . $db_name, $backup);

        $data = array(
            'idUser'    => $this->session->userdata('id'),
            'database'  => $db_name,
            'terdaftar' => date('Y-m-d H:i:s'),
        );

        $this->m_model->insert($data, 'tb_backupdb');

        $this->load->helper('download');
        force_download($db_name, $backup);
    }
    
     public function delete($id)
    {
        $where = array('id' => $id );

        $this->m_model->delete($where, 'tb_backupdb');
        $this->session->set_flashdata('pesan','Data berhasil dihapus!');
        redirect('admin/backupdatabase');
    }
}