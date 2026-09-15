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

    $this->db->where('kode', $kode);
    $this->db->where('id !=', $id);

    if ($this->db->get('tb_cabang')->num_rows() > 0) {
      $this->session->set_flashdata(
        'pesanError',
        'Kode cabang sudah digunakan cabang lain!'
      );

      redirect('admin/cabang');
      return;
    }

    $data = [
      'kode'   => $kode,
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

  public function delete($id)
  {
    $this->pastikan_post();

    $id = (int) $id;

    $cabang = $this->db
      ->get_where('tb_cabang', ['id' => $id])
      ->row_array();

    if (!$cabang) {
      $this->gagal('Data cabang tidak ditemukan!');
      return;
    }

    if ((int) $cabang['is_pusat'] === 1) {
      $this->gagal('Kantor pusat tidak dapat dihapus!');
      return;
    }

    if (strtolower($cabang['status']) === 'aktif') {
      $this->gagal('Nonaktifkan cabang terlebih dahulu sebelum menghapusnya!');
      return;
    }

    $ketergantungan = $this->cariDataTerkaitCabang($id);

    if ($ketergantungan !== '') {
      $this->gagal(
        'Cabang tidak dapat dihapus karena masih memiliki data ' .
        $ketergantungan . '. Biarkan cabang dalam status Nonaktif agar histori tetap aman.'
      );
      return;
    }

    $this->db->where('id', $id);

    $this->db->delete('tb_cabang');

    if ($this->db->affected_rows() === 1) {
      $this->session->set_flashdata(
        'pesan',
        'Cabang ' . $cabang['nama'] . ' berhasil dihapus!'
      );
    } else {
      $this->session->set_flashdata(
        'pesanError',
        'Cabang gagal dihapus. Kemungkinan masih terdapat data yang terhubung.'
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

  private function cariDataTerkaitCabang($id)
  {
    $referensi = [
      'tb_user' => [
        'label' => 'user',
        'kolom' => ['cabang_id']
      ],
      'tb_transaksi' => [
        'label' => 'transaksi',
        'kolom' => ['cabang_id']
      ],
      'tb_transfer' => [
        'label' => 'transfer',
        'kolom' => ['cabang_asal_id', 'cabang_tujuan_id']
      ],
      'tb_rekening_penampungan' => [
        'label' => 'rekening penampungan',
        'kolom' => ['cabang_id']
      ],
      'tb_pesanan' => [
        'label' => 'pesanan',
        'kolom' => ['cabang_id', 'cabang_pembeli_id', 'cabang_penjual_id']
      ],
      'tb_kunci_emas' => [
        'label' => 'tabungan emas',
        'kolom' => ['cabang_id']
      ],
      'tb_reset_pin_log' => [
        'label' => 'audit reset PIN',
        'kolom' => ['cabang_id']
      ]
    ];

    foreach ($referensi as $tabel => $aturan) {
      if (!$this->db->table_exists($tabel)) {
        continue;
      }

      foreach ($aturan['kolom'] as $kolom) {
        if (!$this->db->field_exists($kolom, $tabel)) {
          continue;
        }

        $this->db->where($kolom, $id);

        if ($this->db->count_all_results($tabel) > 0) {
          return $aturan['label'];
        }
      }
    }

    $kolomCabang = [
      'cabang_id', 'id_cabang', 'cabang_asal_id',
      'cabang_tujuan_id', 'cabang_pembeli_id',
      'cabang_penjual_id'
    ];

    foreach ($this->db->list_tables() as $tabel) {
      if (
        $tabel === 'tb_cabang' ||
        array_key_exists($tabel, $referensi) ||
        stripos($tabel, 'backup') !== false
      ) {
        continue;
      }

      foreach ($kolomCabang as $kolom) {
        if (!$this->db->field_exists($kolom, $tabel)) {
          continue;
        }

        $this->db->where($kolom, $id);

        if ($this->db->count_all_results($tabel) > 0) {
          return 'terkait pada ' . $tabel;
        }
      }
    }

    return '';
  }

  private function gagal($pesan)
  {
    $this->session->set_flashdata('pesanError', $pesan);
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
