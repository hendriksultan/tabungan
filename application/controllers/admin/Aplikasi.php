<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Aplikasi extends CI_Controller {

	public function __construct()
	{
		parent::__construct();
		if(!$this->session->userdata('level')){
			$this->session->set_flashdata('pesan', 'Anda harus masuk terlebih dahulu!');
			redirect('home');
		} 
        
        // PERBAIKAN 1: Izinkan Administrator DAN Super Admin
        $userLevel = strtolower($this->session->userdata('level'));
        if ($userLevel != 'administrator' && $userLevel != 'super admin') {
			redirect('home');
        }
	}

	public function index()
	{
        $data['title']      = 'Tentang Aplikasi';
        $data['subtitle']   = 'Atur aplikasi anda disini';

        $data['aplikasi']   = $this->m_model->get_desc('tb_aplikasi');
		
		$this->load->view('admin/templates/header', $data);
		$this->load->view('admin/templates/sidebar');
		$this->load->view('admin/aplikasi');
		$this->load->view('admin/templates/footer');
    }
    
    public function update($id)
    {
        // PERBAIKAN 2: Gunakan $this->input->post() untuk keamanan XSS
        $nama           = $this->input->post('nama');
        $email          = $this->input->post('email');
        $telp           = $this->input->post('telp');
        $alamat         = $this->input->post('alamat');
        $logo           = $_FILES['logo']['name'] ? $_FILES['logo'] : ''; // Penyesuaian agar tidak error jika tidak ada file

        $where = array('id' => $id);

        if(!empty($logo['name'])){
            $config['upload_path'] = './assets/logo/';
            $config['allowed_types'] = 'png|jpg|jpeg';
            $config['file_name'] = 'Logo-' . time();
            $config['max_size'] = 5120;

            $this->load->library('upload', $config);

            if(!$this->upload->do_upload('logo')){
                $logo_name = '';
            } else {
                $logo_name = $this->upload->data('file_name');
            }
        } else {
            $logo_name = '';
        }

        if($logo_name == '') {
            $data = array(
                'nama'          => $nama,
                'email'         => $email,
                'telp'          => $telp,
                'alamat'        => $alamat,
            );
        } else {
            $data = array(
                'nama'          => $nama,
                'email'         => $email,
                'telp'          => $telp,
                'alamat'        => $alamat,
                'logo'          => $logo_name,
            );
        }
        
        $this->m_model->update($where, $data, 'tb_aplikasi');
        $this->session->set_flashdata('pesan', 'Pengaturan aplikasi berhasil diubah!');
        redirect('admin/aplikasi');
    }

    public function delete_logo($id)
    {
        $where = array ('id' => $id);
        $data = array ('logo' => '');

        $this->m_model->update($where, $data, 'tb_aplikasi');
        $this->session->set_flashdata('pesan', 'Logo berhasil dihapus!');
        redirect('admin/aplikasi');
    }
}