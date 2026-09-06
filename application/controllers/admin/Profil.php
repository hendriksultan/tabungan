<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Profil extends CI_Controller {

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
        $data['title']      = 'Profil';
        $data['subtitle']   = 'Atur profil anda disini';

        $this->db->limit('20');
        $this->db->where('idUser', $this->session->userdata('id'));
        $this->db->order_by('id', 'DESC');
        $data['log']		= $this->db->get('tb_log');
		
		$this->load->view('admin/templates/header', $data);
		$this->load->view('admin/templates/sidebar');
		$this->load->view('admin/profil');
		$this->load->view('admin/templates/footer');
    }
    
    public function update($id)
    {
        $nama           = $_POST['nama'];
        $jenisKelamin   = $_POST['jenisKelamin'];
        $telp           = $_POST['telp'];
        $email          = $_POST['email'];
        $alamat         = $_POST['alamat'];
        $username       = $_POST['username'];
        $password       = $_POST['password'];
        $skin           = $_POST['skin'];
        $foto           = $_FILES['foto'];

        if($foto != ''){
            $config['upload_path'] = './assets/profil/';
            $config['allowed_types'] = '*';
            $config['file_name'] = 'Profil-' . time();

            $this->load->library('upload', $config);

            if(!$this->upload->do_upload('foto')){
                $foto = '';
            } else {
                $foto = $this->upload->data('file_name');
            }
        }

        $cekUsername    = $this->db->query('SELECT username FROM tb_user WHERE id="'.$this->session->userdata('id').'" ');
        foreach ($cekUsername->result() as $usr) {
            if($username == $usr->username) {

                $where = array('id' => $id);

                if($password == '' AND $foto == '') {
                    $data = array(
                        'nama'          => $nama,
                        'jenisKelamin'  => $jenisKelamin,
                        'alamat'        => $alamat,
                        'telp'          => $telp,
                        'email'         => $email,
                        'username'      => $username,
                        'skin'          => $skin,
                    );
                } elseif($password != '' AND $foto == '') {

                    $options = [
                        'cost' => 10,
                    ];
            
                    $enkripPassword = password_hash($password, PASSWORD_BCRYPT, $options);

                    $data = array(
                        'nama'          => $nama,
                        'jenisKelamin'  => $jenisKelamin,
                        'alamat'        => $alamat,
                        'telp'          => $telp,
                        'email'         => $email,
                        'username'      => $username,
                        'skin'          => $skin,
                        'password'      => $enkripPassword,
                    );
                } elseif($password != '' AND $foto != '') {

                    $options = [
                        'cost' => 10,
                    ];
            
                    $enkripPassword = password_hash($password, PASSWORD_BCRYPT, $options);

                    $data = array(
                        'nama'          => $nama,
                        'jenisKelamin'  => $jenisKelamin,
                        'alamat'        => $alamat,
                        'telp'          => $telp,
                        'email'         => $email,
                        'username'      => $username,
                        'skin'          => $skin,
                        'foto'          => $foto,
                        'password'      => $enkripPassword,
                    );
                } elseif($password == '' AND $foto != '') {

                    $options = [
                        'cost' => 10,
                    ];
            
                    $enkripPassword = password_hash($password, PASSWORD_BCRYPT, $options);

                    $data = array(
                        'nama'          => $nama,
                        'jenisKelamin'  => $jenisKelamin,
                        'alamat'        => $alamat,
                        'telp'          => $telp,
                        'email'         => $email,
                        'username'      => $username,
                        'skin'          => $skin,
                        'foto'          => $foto,
                    );
                }
                
                $this->m_model->update($where, $data, 'tb_user');
                $this->session->set_userdata($data);
                $this->session->set_flashdata('pesan', 'Profil berhasil diubah!');
                redirect('admin/profil');

            } else {
                $cekUsernameTersedia = $this->db->query('SELECT username FROM tb_user WHERE username="'.$username.'" ')->num_rows();

                if($cekUsernameTersedia == '0') {
                    $where = array('id' => $id);

                    if($password == '' AND $foto == '') {
                        $data = array(
                            'nama'          => $nama,
                            'jenisKelamin'  => $jenisKelamin,
                            'alamat'        => $alamat,
                            'telp'          => $telp,
                            'email'         => $email,
                            'username'      => $username,
                            'skin'          => $skin,
                        );
                    } elseif($password != '' AND $foto == '') {
    
                        $options = [
                            'cost' => 10,
                        ];
                
                        $enkripPassword = password_hash($password, PASSWORD_BCRYPT, $options);
    
                        $data = array(
                            'nama'          => $nama,
                            'jenisKelamin'  => $jenisKelamin,
                            'alamat'        => $alamat,
                            'telp'          => $telp,
                            'email'         => $email,
                            'username'      => $username,
                            'skin'          => $skin,
                            'password'      => $enkripPassword,
                        );
                    } elseif($password != '' AND $foto != '') {
    
                        $options = [
                            'cost' => 10,
                        ];
                
                        $enkripPassword = password_hash($password, PASSWORD_BCRYPT, $options);
    
                        $data = array(
                            'nama'          => $nama,
                            'jenisKelamin'  => $jenisKelamin,
                            'alamat'        => $alamat,
                            'telp'          => $telp,
                            'email'         => $email,
                            'username'      => $username,
                            'skin'          => $skin,
                            'foto'          => $foto,
                            'password'      => $enkripPassword,
                        );
                    } elseif($password == '' AND $foto != '') {
    
                        $options = [
                            'cost' => 10,
                        ];
                
                        $enkripPassword = password_hash($password, PASSWORD_BCRYPT, $options);
    
                        $data = array(
                            'nama'          => $nama,
                            'jenisKelamin'  => $jenisKelamin,
                            'alamat'        => $alamat,
                            'telp'          => $telp,
                            'email'         => $email,
                            'username'      => $username,
                            'skin'          => $skin,
                            'foto'          => $foto,
                        );
                    }
                    
                    $this->m_model->update($where, $data, 'tb_user');
                    $this->session->set_userdata($data);
                    $this->session->set_flashdata('pesan', 'Profil berhasil diubah!');
                    redirect('admin/profil');
                } else {
                    $this->session->set_flashdata('pesanError', 'Username tidak tersedia!');
                    redirect('admin/profil');
                }
            }
        }
    }
}