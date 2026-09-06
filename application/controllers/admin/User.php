<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class User extends CI_Controller {

	public function __construct()
	{
		parent::__construct();
		if(!$this->session->userdata('level')){
			$this->session->set_flashdata('pesan', 'Anda harus masuk terlebih dahulu!');
			redirect('home');
		} 
        
        // PERBAIKAN: Mengizinkan Administrator dan Super Admin
        $userLevel = strtolower($this->session->userdata('level'));
        if($userLevel != 'administrator' && $userLevel != 'super admin') {
			redirect('home');
        }
	}

	public function index()
	{
		$data['title']		= 'Manajemen User';
		$data['subtitle']	= 'Semua user akan muncul disini';
		
		$data['user']       = $this->m_model->get_desc('tb_user');
		
		$this->load->view('admin/templates/header', $data);
		$this->load->view('admin/templates/sidebar');
		$this->load->view('admin/user');
		$this->load->view('admin/templates/footer');
    }

    public function delete($id)
	{
		// 1. CEK LEVEL USER SEBELUM DIHAPUS
		$where = array('id' => $id);
		$cekUser = $this->m_model->get_where($where, 'tb_user')->row_array();
		
		if(strtolower($cekUser['level']) == 'super admin') {
			$this->session->set_flashdata('pesan', 'Akses Ditolak: Anda tidak diizinkan menghapus akun Super Admin!');
			redirect('admin/user');
		}

		// Jika bukan Super Admin, lanjutkan hapus
		$this->m_model->delete($where, 'tb_user');
		$this->session->set_flashdata('pesan', 'Account berhasil dihapus');
		redirect('admin/user');
	}

	public function insert()
	{
		date_default_timezone_set('Asia/Jakarta');

		$nama			= $this->input->post('nama');
		$jenisKelamin	= $this->input->post('jenisKelamin');
		$telp			= $this->input->post('telp');
		$email			= $this->input->post('email');
		$login			= $this->input->post('login');
		$alamat			= $this->input->post('alamat');
		$username		= $this->input->post('username');
		$password		= $this->input->post('password');
		$foto			= 'no-image.png';
		$skin			= 'blue';
		$level			= $this->input->post('level');
		$terdaftar		= date('Y-m-d H:i:s');

		$where = array('username' => $username);
		$cekUsername	= $this->m_model->get_where($where, 'tb_user');
		
		if(empty($cekUsername->num_rows())) {
			$options = [
				'cost' => 10,
			];
	
			$enkripPassword = password_hash($password, PASSWORD_BCRYPT, $options);
	
			$data = array(
				'nama' 			=> $nama,
				'jenisKelamin'	=> $jenisKelamin,
				'telp' 			=> $telp,
				'email' 		=> $email,
				'login' 		=> $login,
				'alamat' 		=> $alamat,
				'username'		=> $username,
				'password'		=> $enkripPassword,
				'foto'			=> $foto,
				'skin'			=> $skin,
				'level'			=> $level,
				'terdaftar'		=> $terdaftar,
			);
	
			$this->m_model->insert($data, 'tb_user');
			$this->session->set_flashdata('pesan', 'Account berhasil dibuat!');
			redirect('admin/user');
		} else {
			$this->session->set_flashdata('pesan', 'Username sudah ada!');
			redirect('admin/user');
		}
	}

	public function resetpassword($id)
	{
		// 2. CEK LEVEL USER SEBELUM RESET PASSWORD
		$where = array('id' => $id);
		$cekUser = $this->m_model->get_where($where, 'tb_user')->row_array();
		
		if(strtolower($cekUser['level']) == 'super admin') {
			$this->session->set_flashdata('pesan', 'Akses Ditolak: Anda tidak diizinkan mereset password Super Admin!');
			redirect('admin/user');
		}

		$password	= $this->input->post('password');

		$options = [
			'cost' => 10,
		];

		$enkripPassword = password_hash($password, PASSWORD_BCRYPT, $options);

		$data = array(
			'password'	=> $enkripPassword,
		);

		$this->m_model->update($where, $data, 'tb_user');
		$this->session->set_flashdata('pesan', 'Reset password berhasil!');
		redirect('admin/user');
	}

	public function update($id)
	{
		// 3. CEK LEVEL USER SEBELUM DIUPDATE
		$where = array('id' => $id);
		$cekUser = $this->m_model->get_where($where, 'tb_user')->row_array();
		
		if(strtolower($cekUser['level']) == 'super admin') {
			$this->session->set_flashdata('pesan', 'Akses Ditolak: Anda tidak diizinkan mengubah data Super Admin!');
			redirect('admin/user');
		}

		$nama			= $this->input->post('nama');
		$jenisKelamin	= $this->input->post('jenisKelamin');
		$telp			= $this->input->post('telp');
		$username		= $this->input->post('username');
		$email			= $this->input->post('email');
		$login			= $this->input->post('login');
		$alamat			= $this->input->post('alamat');

		$data = array(
			'nama' 			=> $nama,
			'jenisKelamin'	=> $jenisKelamin,
			'telp' 			=> $telp,
			'username'		=> $username,
			'email' 		=> $email,
			'login' 		=> $login,
			'alamat' 		=> $alamat
		);

		$this->m_model->update($where, $data, 'tb_user');
		$this->session->set_flashdata('pesan', 'Account berhasil diubah!');
		redirect('admin/user');
	}
}