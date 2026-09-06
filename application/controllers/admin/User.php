<?php
defined('BASEPATH') or exit('No direct script access allowed');

class User extends CI_Controller
{

	private $isSuperAdmin = false;
	private $cabangId = null;

	public function __construct()
	{
		parent::__construct();

		if (!$this->session->userdata('level')) {
			$this->session->set_flashdata(
				'pesan',
				'Anda harus masuk terlebih dahulu!'
			);

			redirect('home');
			return;
		}

		$level = strtolower(
			trim((string) $this->session->userdata('level'))
		);

		if (!in_array($level, ['administrator', 'super admin'], true)) {
			$this->session->set_flashdata(
				'pesanError',
				'Akses ditolak!'
			);

			redirect('home');
			return;
		}

		$this->isSuperAdmin = ($level === 'super admin');
		$this->cabangId = (int) $this->session->userdata('cabang_id');

		if (!$this->isSuperAdmin && $this->cabangId <= 0) {
			$this->session->set_flashdata(
				'pesanError',
				'Administrator belum terhubung dengan cabang!'
			);

			redirect('admin/dashboard');
			return;
		}
	}

	public function index()
	{
		$data['title'] = 'Manajemen User';
		$data['subtitle'] = $this->isSuperAdmin
			? 'Kelola pengguna dari seluruh cabang'
			: 'Kelola nasabah pada cabang Anda';

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

		if (!$this->isSuperAdmin) {
			$this->db->where(
				'tb_user.cabang_id',
				$this->cabangId
			);

			$this->db->where(
				'LOWER(tb_user.level) !=',
				'super admin'
			);
		}

		$this->db->order_by('tb_user.id', 'DESC');

		$data['user'] = $this->db->get();

		$this->db->where('status', 'Aktif');
		$this->db->order_by('is_pusat', 'DESC');
		$this->db->order_by('nama', 'ASC');

		$data['cabang'] = $this->db
			->get('tb_cabang')
			->result_array();

		$data['is_super_admin'] = $this->isSuperAdmin;

		$this->load->view('admin/templates/header', $data);
		$this->load->view('admin/templates/sidebar');
		$this->load->view('admin/user', $data);
		$this->load->view('admin/templates/footer');
	}

	public function insert()
	{
		$this->pastikanPost();

		date_default_timezone_set('Asia/Jakarta');

		$nama = trim(
			(string) $this->input->post('nama', true)
		);

		$jenisKelamin = trim(
			(string) $this->input->post('jenisKelamin', true)
		);

		$telp = trim(
			(string) $this->input->post('telp', true)
		);

		$email = trim(
			(string) $this->input->post('email', true)
		);

		$login = trim(
			(string) $this->input->post('login', true)
		);

		$alamat = trim(
			(string) $this->input->post('alamat', true)
		);

		$username = trim(
			(string) $this->input->post('username', true)
		);

		$password = (string) $this->input->post('password');

		if (
			$nama === '' ||
			$jenisKelamin === '' ||
			$username === '' ||
			$password === ''
		) {
			$this->gagal('Data user belum lengkap!');
			return;
		}

		if (!in_array(
			$jenisKelamin,
			['Laki-Laki', 'Perempuan'],
			true
		)) {
			$this->gagal('Jenis kelamin tidak valid!');
			return;
		}

		if (!in_array($login, ['Ya', 'Tidak'], true)) {
			$this->gagal('Status login tidak valid!');
			return;
		}

		if (strlen($password) < 6) {
			$this->gagal('Password minimal 6 karakter!');
			return;
		}

		if (
			$email !== '' &&
			!filter_var($email, FILTER_VALIDATE_EMAIL)
		) {
			$this->gagal('Format email tidak valid!');
			return;
		}

		$cekUsername = $this->db
			->get_where('tb_user', ['username' => $username])
			->num_rows();

		if ($cekUsername > 0) {
			$this->gagal('Username sudah digunakan!');
			return;
		}

		if ($this->isSuperAdmin) {
			$level = trim(
				(string) $this->input->post('level', true)
			);

			$cabangId = (int) $this->input->post('cabang_id');

			if (!in_array(
				$level,
				['Administrator', 'Nasabah'],
				true
			)) {
				$this->gagal('Level user tidak valid!');
				return;
			}
		} else {
			$level = 'Nasabah';
			$cabangId = $this->cabangId;
		}

		if (!$this->cabangAktif($cabangId)) {
			$this->gagal('Cabang yang dipilih tidak valid atau nonaktif!');
			return;
		}

		$data = [
			'cabang_id'     => $cabangId,
			'nama'          => $nama,
			'jenisKelamin'  => $jenisKelamin,
			'telp'          => $telp,
			'email'         => $email,
			'login'         => $login,
			'alamat'        => $alamat,
			'username'      => $username,
			'password'      => password_hash(
				$password,
				PASSWORD_BCRYPT,
				['cost' => 10]
			),
			'foto'          => 'no-image.png',
			'skin'          => 'blue',
			'level'         => $level,
			'terdaftar'     => date('Y-m-d H:i:s')
		];

		if ($this->db->insert('tb_user', $data)) {
			$this->session->set_flashdata(
				'pesan',
				'Account berhasil dibuat!'
			);
		} else {
			$this->session->set_flashdata(
				'pesanError',
				'Account gagal dibuat!'
			);
		}

		redirect('admin/user');
	}

	public function update($id)
	{
		$this->pastikanPost();

		$target = $this->ambilUserYangBolehDikelola($id);

		if (!$target) {
			return;
		}

		$nama = trim(
			(string) $this->input->post('nama', true)
		);

		$jenisKelamin = trim(
			(string) $this->input->post('jenisKelamin', true)
		);

		$telp = trim(
			(string) $this->input->post('telp', true)
		);

		$username = trim(
			(string) $this->input->post('username', true)
		);

		$email = trim(
			(string) $this->input->post('email', true)
		);

		$login = trim(
			(string) $this->input->post('login', true)
		);

		$alamat = trim(
			(string) $this->input->post('alamat', true)
		);

		if ($nama === '' || $username === '') {
			$this->gagal('Nama dan username wajib diisi!');
			return;
		}

		if (!in_array(
			$jenisKelamin,
			['Laki-Laki', 'Perempuan'],
			true
		)) {
			$this->gagal('Jenis kelamin tidak valid!');
			return;
		}

		if (!in_array($login, ['Ya', 'Tidak'], true)) {
			$this->gagal('Status login tidak valid!');
			return;
		}

		if (
			$email !== '' &&
			!filter_var($email, FILTER_VALIDATE_EMAIL)
		) {
			$this->gagal('Format email tidak valid!');
			return;
		}

		$this->db->where('username', $username);
		$this->db->where('id !=', (int) $target['id']);

		if ($this->db->get('tb_user')->num_rows() > 0) {
			$this->gagal('Username sudah digunakan user lain!');
			return;
		}

		$cabangId = (int) $target['cabang_id'];

		if ($this->isSuperAdmin) {
			$cabangId = (int) $this->input->post('cabang_id');

			if (!$this->cabangAktif($cabangId)) {
				$this->gagal(
					'Cabang yang dipilih tidak valid atau nonaktif!'
				);
				return;
			}
		}

		$data = [
			'cabang_id'     => $cabangId,
			'nama'          => $nama,
			'jenisKelamin'  => $jenisKelamin,
			'telp'          => $telp,
			'username'      => $username,
			'email'         => $email,
			'login'         => $login,
			'alamat'        => $alamat
		];

		$this->db->where('id', (int) $target['id']);

		if ($this->db->update('tb_user', $data)) {
			$this->session->set_flashdata(
				'pesan',
				'Account berhasil diubah!'
			);
		} else {
			$this->session->set_flashdata(
				'pesanError',
				'Account gagal diubah!'
			);
		}

		redirect('admin/user');
	}

	public function resetpassword($id)
	{
		$this->pastikanPost();

		$target = $this->ambilUserYangBolehDikelola($id);

		if (!$target) {
			return;
		}

		$password = (string) $this->input->post('password');

		if (strlen($password) < 6) {
			$this->gagal('Password baru minimal 6 karakter!');
			return;
		}

		$data = [
			'password' => password_hash(
				$password,
				PASSWORD_BCRYPT,
				['cost' => 10]
			)
		];

		$this->db->where('id', (int) $target['id']);

		if ($this->db->update('tb_user', $data)) {
			$this->session->set_flashdata(
				'pesan',
				'Reset password berhasil!'
			);
		} else {
			$this->session->set_flashdata(
				'pesanError',
				'Reset password gagal!'
			);
		}

		redirect('admin/user');
	}

	private function ambilUserYangBolehDikelola($id)
	{
		$id = (int) $id;

		$target = $this->db
			->get_where('tb_user', ['id' => $id])
			->row_array();

		if (!$target) {
			$this->gagal('User tidak ditemukan!');
			return false;
		}

		if (strtolower($target['level']) === 'super admin') {
			$this->gagal('Akun Super Admin tidak dapat diubah di sini!');
			return false;
		}

		if (
			!$this->isSuperAdmin &&
			(int) $target['cabang_id'] !== $this->cabangId
		) {
			$this->gagal(
				'Anda tidak dapat mengelola user dari cabang lain!'
			);
			return false;
		}

		return $target;
	}

	private function cabangAktif($id)
	{
		return $this->db
			->get_where('tb_cabang', [
				'id'     => (int) $id,
				'status' => 'Aktif'
			])
			->num_rows() > 0;
	}

	private function pastikanPost()
	{
		if ($this->input->method(true) !== 'POST') {
			show_error(
				'Metode permintaan tidak diizinkan.',
				405
			);

			exit;
		}
	}

	private function gagal($pesan)
	{
		$this->session->set_flashdata(
			'pesanError',
			$pesan
		);

		redirect('admin/user');
	}
}
