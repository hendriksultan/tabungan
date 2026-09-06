<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Home extends CI_Controller {

    public function index()
    {
        // PERBAIKAN 1: Tambahkan Super Admin pada pengecekan sesi aktif
        $level = strtolower($this->session->userdata('level'));
        if ($level == 'administrator' || $level == 'nasabah' || $level == 'super admin') {
            redirect('admin/dashboard');
        } else {
            $data['title']  = 'Login';
            $digit1 = mt_rand(1, 20);
            $digit2 = mt_rand(1, 20);
            
            $captcha = array('captcha' => $digit1+$digit2);

            $this->session->set_userdata($captcha);
            $data['captcha'] = "$digit1 + $digit2 = ?";

            $data['aplikasi'] = $this->m_model->get_desc('tb_aplikasi');
            $this->load->view('login', $data);
        }
    }
    
    public function auth()
    {
        date_default_timezone_set('Asia/Jakarta');

        $username   = $this->input->post('username');
        $password   = $this->input->post('password');
        $jawaban    = $this->input->post('jawaban');

        if(!empty($jawaban)) {
            if($jawaban == $this->session->userdata('captcha')) {
       
                $where = array( 'username' => $username );

                $cek = $this->m_model->get_where($where, 'tb_user');
    
                if ($cek->num_rows() > 0) {
                    foreach ($cek->result_array() as $row) {

                        if(password_verify($password, $row['password'])) {

                            if($row['login'] == 'Ya') {
                                $datauser = array(
                                    'id'            => $row['id'], 
                                    'nama'          => $row['nama'],  
                                    'jenisKelamin'  => $row['jenisKelamin'],  
                                    'telp'          => $row['telp'],   
                                    'email'         => $row['email'],
                                    'login'         => $row['login'],
                                    'alamat'        => $row['alamat'],
                                    'username'      => $row['username'],
                                    'skin'          => $row['skin'],
                                    'level'         => $row['level'],
                                    'foto'          => $row['foto'],
                                    'terdaftar'     => $row['terdaftar']
                                );
    
                                $this->session->set_userdata($datauser);
    
                                // === PENANGKAP IP ADDRESS AKURAT UNTUK LOGIN ===
                                $ip_address = '';
                                if (isset($_SERVER["HTTP_CF_CONNECTING_IP"])) {
                                    $ip_address = $_SERVER["HTTP_CF_CONNECTING_IP"];
                                } elseif (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
                                    $ip_address = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0];
                                } elseif (isset($_SERVER['HTTP_CLIENT_IP'])) {
                                    $ip_address = $_SERVER['HTTP_CLIENT_IP'];
                                } else {
                                    $ip_address = $this->input->ip_address();
                                }
                                
                                // Cegah value kosong jika localhost bermasalah
                                if(empty($ip_address)) { $ip_address = 'Unknown'; }

                                $insertLog = array(
                                    'idUser'    => $row['id'],
                                    'status'    => 'Login',
                                    'ipAddress' => $ip_address,
                                    'device'    => substr($this->input->user_agent(), 0, 250), // Potong agar tidak error di database
                                    'terdaftar' => date('Y-m-d H:i:s'),
                                );
    
                                $this->m_model->insert($insertLog, 'tb_log');
                                
                                // PERBAIKAN 2: Arah redirect untuk Super Admin
                                $userLevel = strtolower($row['level']);
                                if($userLevel == 'administrator' || $userLevel == 'nasabah' || $userLevel == 'super admin') {
                                    redirect('admin/dashboard');
                                } else {
                                    redirect('home'); 
                                }
                            } else {
                                $this->session->set_flashdata('pesan', 'Tidak ada akses login, silahkan hubungi administrator!');
                                redirect('home');
                            }
                            
                        } else {
                            $this->session->set_flashdata('pesan', 'Password anda salah!');
                            redirect('home');
                        }
                    }
                } else {
                    $this->session->set_flashdata('pesan', 'Username tidak ditemukan!');
                    redirect('home');
                }
            } else {
                $this->session->set_flashdata('pesan', 'Hitung dengan benar!');
                redirect('home');
            }
        } else {
            $this->session->set_flashdata('pesan', 'Captcha harap diisi!');
            redirect('home');
        }
    }

    public function logout()
    {
        date_default_timezone_set('Asia/Jakarta');

        // === PENANGKAP IP ADDRESS AKURAT UNTUK LOGOUT ===
        $ip_address = '';
        if (isset($_SERVER["HTTP_CF_CONNECTING_IP"])) {
            $ip_address = $_SERVER["HTTP_CF_CONNECTING_IP"];
        } elseif (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ip_address = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0];
        } elseif (isset($_SERVER['HTTP_CLIENT_IP'])) {
            $ip_address = $_SERVER['HTTP_CLIENT_IP'];
        } else {
            $ip_address = $this->input->ip_address();
        }
        
        // Cegah value kosong jika localhost bermasalah
        if(empty($ip_address)) { $ip_address = 'Unknown'; }

        $insertLog = array(
            'idUser'    => $this->session->userdata('id'),
            'status'    => 'Logout',
            'ipAddress' => $ip_address,
            'device'    => substr($this->input->user_agent(), 0, 250), // Potong agar tidak error di database
            'terdaftar' => date('Y-m-d H:i:s'),
        );

        $this->m_model->insert($insertLog, 'tb_log');

        $this->session->sess_destroy();
        redirect('home');
    }
}