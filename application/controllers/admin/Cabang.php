<?php
defined('BASEPATH') or exit('No direct script access allowed');

class Cabang extends CI_Controller
{

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

    $userLevel = strtolower(
      trim((string) $this->session->userdata('level'))
    );

    if ($userLevel !== 'super admin') {
      $this->session->set_flashdata(
        'pesanError',
        'Akses ditolak! Manajemen cabang hanya dapat diakses Super Admin.'
      );

      redirect('admin/dashboard');
      return;
    }
  }

  public function index()
  {
    $data['title'] = 'Manajemen Cabang';
    $data['subtitle'] = 'Kelola kantor pusat dan seluruh cabang';

    $this->db->order_by('is_pusat', 'DESC');
    $this->db->order_by('nama', 'ASC');

    $data['cabang'] = $this->db->get('tb_cabang');

    $this->load->view('admin/templates/header', $data);
    $this->load->view('admin/templates/sidebar');
    $this->load->view('admin/cabang', $data);
    $this->load->view('admin/templates/footer');
  }

  public function insert()
  {
    $this->pastikan_post();

    $kode = strtoupper(
      trim((string) $this->input->post('kode', true))
    );

    $nama = trim(
      (string) $this->input->post('nama', true)
    );

    $alamat = trim(
      (string) $this->input->post('alamat', true)
    );

    $telp = trim(
      (string) $this->input->post('telp', true)
    );

    $email = trim(
      (string) $this->input->post('email', true)
    );

    if ($kode === '' || $nama === '') {
      $this->session->set_flashdata(
        'pesanError',
        'Kode dan nama cabang wajib diisi!'
      );

      redirect('admin/cabang');
      return;
    }

    if (!preg_match('/^[A-Z0-9\-]+$/', $kode)) {
      $this->session->set_flashdata(
        'pesanError',
        'Kode cabang hanya boleh berisi huruf, angka, dan tanda hubung!'
      );

      redirect('admin/cabang');
      return;
    }

    if (strlen($kode) > 20 || strlen($nama) > 150) {
      $this->session->set_flashdata(
        'pesanError',
        'Kode atau nama cabang terlalu panjang!'
      );

      redirect('admin/cabang');
      return;
    }

    if ($email !== '' && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
      $this->session->set_flashdata(
        'pesanError',
        'Format email cabang tidak valid!'
      );

      redirect('admin/cabang');
      return;
    }

    $cabangSudahAda = $this->db
      ->get_where('tb_cabang', ['kode' => $kode])
      ->num_rows();

    if ($cabangSudahAda > 0) {
      $this->session->set_flashdata(
        'pesanError',
        'Kode cabang sudah digunakan!'
      );

      redirect('admin/cabang');
      return;
    }

    $data = [
      'kode'      => $kode,
      'nama'      => $nama,
      'alamat'    => $alamat,
      'telp'      => $telp,
      'email'     => $email,
      'status'    => 'Aktif',
      'is_pusat'  => 0,
      'terdaftar' => date('Y-m-d H:i:s')
    ];

    if ($this->db->insert('tb_cabang', $data)) {
      $this->session->set_flashdata(
        'pesan',
        'Cabang berhasil ditambahkan!'
      );
    } else {
      $this->session->set_flashdata(
        'pesanError',
        'Cabang gagal ditambahkan!'
      );
    }

    redirect('admin/cabang');
  }

  public function update($id)
  {
    $this->pastikan_post();

    $id = (int) $id;

    $cabang = $this->db
      ->get_where('tb_cabang', ['id' => $id])
      ->row_array();

    if (!$cabang) {
      $this->session->set_flashdata(
        'pesanError',
        'Data cabang tidak ditemukan!'
      );

      redirect('admin/cabang');
      return;
    }

    $nama = trim(
      (string) $this->input->post('nama', true)
    );

    $alamat = trim(
      (string) $this->input->post('alamat', true)
    );

    $telp = trim(
      (string) $this->input->post('telp', true)
    );

    $email = trim(
      (string) $this->input->post('email', true)
    );

    if ($nama === '') {
      $this->session->set_flashdata(
        'pesanError',
        'Nama cabang wajib diisi!'
      );

      redirect('admin/cabang');
      return;
    }

    if (strlen($nama) > 150) {
      $this->session->set_flashdata(
        'pesanError',
        'Nama cabang terlalu panjang!'
      );

      redirect('admin/cabang');
      return;
    }

    if ($email !== '' && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
      $this->session->set_flashdata(
        'pesanError',
        'Format email cabang tidak valid!'
      );

      redirect('admin/cabang');
      return;
    }

    $data = [
      'nama'   => $nama,
      'alamat' => $alamat,
      'telp'   => $telp,
      'email'  => $email
    ];

    $this->db->where('id', $id);

    if ($this->db->update('tb_cabang', $data)) {
      $this->session->set_flashdata(
        'pesan',
        'Data cabang berhasil diperbarui!'
      );
    } else {
      $this->session->set_flashdata(
        'pesanError',
        'Data cabang gagal diperbarui!'
      );
    }

    redirect('admin/cabang');
  }

  public function toggle_status($id)
  {
    $this->pastikan_post();

    $id = (int) $id;

    $cabang = $this->db
      ->get_where('tb_cabang', ['id' => $id])
      ->row_array();

    if (!$cabang) {
      $this->session->set_flashdata(
        'pesanError',
        'Data cabang tidak ditemukan!'
      );

      redirect('admin/cabang');
      return;
    }

    if ((int) $cabang['is_pusat'] === 1) {
      $this->session->set_flashdata(
        'pesanError',
        'Kantor pusat tidak dapat dinonaktifkan!'
      );

      redirect('admin/cabang');
      return;
    }

    $statusBaru = (
      strtolower($cabang['status']) === 'aktif'
    ) ? 'Nonaktif' : 'Aktif';

    $this->db->where('id', $id);

    if ($this->db->update(
      'tb_cabang',
      ['status' => $statusBaru]
    )) {
      $this->session->set_flashdata(
        'pesan',
        'Status cabang berhasil diperbarui!'
      );
    } else {
      $this->session->set_flashdata(
        'pesanError',
        'Status cabang gagal diperbarui!'
      );
    }

    redirect('admin/cabang');
  }

  private function pastikan_post()
  {
    if (strtoupper($this->input->method()) !== 'POST') {
      show_error(
        'Metode permintaan tidak diizinkan.',
        405
      );

      exit;
    }
  }
}
