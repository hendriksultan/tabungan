<?php
defined('BASEPATH') or exit('No direct script access allowed');

class Home extends CI_Controller
{

    public function index()
    {
        $level = strtolower((string) $this->session->userdata('level'));

        if (
            $level === 'administrator' ||
            $level === 'nasabah' ||
            $level === 'super admin'
        ) {
            redirect('admin/dashboard');
            return;
        }

        $data['title'] = 'Login';

        $digit1 = mt_rand(1, 20);
        $digit2 = mt_rand(1, 20);

        $this->session->set_userdata(
            'captcha',
            $digit1 + $digit2
        );

        $data['captcha'] = "{$digit1} + {$digit2} = ?";
        $data['aplikasi'] = $this->m_model->get_desc('tb_aplikasi');

        $this->load->view('login', $data);
    }

    public function auth()
    {
        date_default_timezone_set('Asia/Jakarta');

        $username = trim((string) $this->input->post('username', true));
        $password = (string) $this->input->post('password');
        $jawaban  = trim((string) $this->input->post('jawaban', true));

        /*
         * Validasi captcha
         */
        if ($jawaban === '') {
            $this->session->set_flashdata(
                'pesan',
                'Captcha harap diisi!'
            );

            redirect('home');
            return;
        }

        if ((string) $jawaban !== (string) $this->session->userdata('captcha')) {
            $this->session->set_flashdata(
                'pesan',
                'Hitung dengan benar!'
            );

            redirect('home');
            return;
        }

        /*
         * Validasi input login
         */
        if ($username === '' || $password === '') {
            $this->session->set_flashdata(
                'pesan',
                'Username dan password harus diisi!'
            );

            redirect('home');
            return;
        }

        /*
         * Ambil data user beserta cabangnya.
         */
        $this->db->select([
            'tb_user.*',
            'tb_cabang.kode AS kode_cabang',
            'tb_cabang.nama AS nama_cabang',
            'tb_cabang.status AS status_cabang'
        ]);

        $this->db->from('tb_user');

        $this->db->join(
            'tb_cabang',
            'tb_cabang.id = tb_user.cabang_id',
            'left'
        );

        $this->db->where('tb_user.username', $username);
        $this->db->limit(1);

        $user = $this->db->get()->row_array();

        if (!$user) {
            $this->session->set_flashdata(
                'pesan',
                'Username tidak ditemukan!'
            );

            redirect('home');
            return;
        }

        /*
         * Validasi password
         */
        if (!password_verify($password, $user['password'])) {
            $this->session->set_flashdata(
                'pesan',
                'Password anda salah!'
            );

            redirect('home');
            return;
        }

        /*
         * Periksa status akses login user.
         */
        if (strtolower((string) $user['login']) !== 'ya') {
            $this->session->set_flashdata(
                'pesan',
                'Tidak ada akses login, silakan hubungi administrator!'
            );

            redirect('home');
            return;
        }

        $userLevel = strtolower(trim((string) $user['level']));

        $allowedLevels = [
            'administrator',
            'nasabah',
            'super admin'
        ];

        if (!in_array($userLevel, $allowedLevels, true)) {
            $this->session->set_flashdata(
                'pesan',
                'Level pengguna tidak memiliki akses!'
            );

            redirect('home');
            return;
        }

        /*
         * Selain Super Admin, user harus mempunyai cabang aktif.
         */
        if ($userLevel !== 'super admin') {
            if (empty($user['cabang_id'])) {
                $this->session->set_flashdata(
                    'pesan',
                    'Akun belum terhubung dengan cabang!'
                );

                redirect('home');
                return;
            }

            if (
                empty($user['status_cabang']) ||
                strtolower($user['status_cabang']) !== 'aktif'
            ) {
                $this->session->set_flashdata(
                    'pesan',
                    'Cabang akun Anda sedang tidak aktif!'
                );

                redirect('home');
                return;
            }
        }

        /*
         * Regenerasi session ID untuk mencegah session fixation.
         */
        $this->session->sess_regenerate(true);

        /*
         * Simpan data user dan cabang ke dalam session.
         */
        $dataUser = [
            'id'            => $user['id'],
            'nama'          => $user['nama'],
            'jenisKelamin'  => $user['jenisKelamin'],
            'telp'          => $user['telp'],
            'email'         => $user['email'],
            'login'         => $user['login'],
            'alamat'        => $user['alamat'],
            'username'      => $user['username'],
            'skin'          => $user['skin'],
            'level'         => $user['level'],
            'foto'          => $user['foto'],
            'terdaftar'     => $user['terdaftar'],

            /*
             * Konteks cabang
             */
            'cabang_id'     => $user['cabang_id'],
            'kode_cabang'   => $user['kode_cabang'] ?? null,
            'nama_cabang'   => $user['nama_cabang'] ?? null
        ];

        $this->session->set_userdata($dataUser);
        $this->session->unset_userdata('captcha');

        /*
         * Ambil alamat IP.
         */
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            $ipAddress = $_SERVER['HTTP_CF_CONNECTING_IP'];
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $forwardedIps = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            $ipAddress = trim($forwardedIps[0]);
        } elseif (!empty($_SERVER['HTTP_CLIENT_IP'])) {
            $ipAddress = $_SERVER['HTTP_CLIENT_IP'];
        } else {
            $ipAddress = $this->input->ip_address();
        }

        if (empty($ipAddress)) {
            $ipAddress = 'Unknown';
        }

        /*
         * Simpan log login.
         */
        $insertLog = [
            'idUser'    => $user['id'],
            'status'    => 'Login',
            'ipAddress' => substr($ipAddress, 0, 32),
            'device'    => substr(
                (string) $this->input->user_agent(),
                0,
                250
            ),
            'terdaftar' => date('Y-m-d H:i:s')
        ];

        $this->m_model->insert($insertLog, 'tb_log');

        redirect('admin/dashboard');
    }

    public function logout()
    {
        date_default_timezone_set('Asia/Jakarta');

        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            $ipAddress = $_SERVER['HTTP_CF_CONNECTING_IP'];
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $forwardedIps = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            $ipAddress = trim($forwardedIps[0]);
        } elseif (!empty($_SERVER['HTTP_CLIENT_IP'])) {
            $ipAddress = $_SERVER['HTTP_CLIENT_IP'];
        } else {
            $ipAddress = $this->input->ip_address();
        }

        if (empty($ipAddress)) {
            $ipAddress = 'Unknown';
        }

        /*
         * Simpan log hanya jika user masih memiliki session login.
         */
        if ($this->session->userdata('id')) {
            $insertLog = [
                'idUser'    => $this->session->userdata('id'),
                'status'    => 'Logout',
                'ipAddress' => substr($ipAddress, 0, 32),
                'device'    => substr(
                    (string) $this->input->user_agent(),
                    0,
                    250
                ),
                'terdaftar' => date('Y-m-d H:i:s')
            ];

            $this->m_model->insert($insertLog, 'tb_log');
        }

        $this->session->sess_destroy();

        redirect('home');
    }
}
