<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Dashboard extends CI_Controller {

	public function __construct()
	{
		parent::__construct();
		if(!$this->session->userdata('level')){
			$this->session->set_flashdata('pesan', 'Anda harus masuk terlebih dahulu!');
			redirect('home');
		}
		$this->load->model('M_model'); // ✅ load model
	}

	public function index()
	{
		$data['title']      = 'Dashboard';
		$data['subtitle']   = 'Control Panel';

		// ✅ Ambil saldo detail
		$data['saldo_detail'] = $this->M_model->get_saldo_detail_all();

		// ✅ Query transaksi per bulan khusus tahun berjalan (Hanya yang Sukses)
		$query = $this->db->query("
			SELECT MONTH(tanggal) AS bulan, 
				   SUM(CASE WHEN jenis='Masuk' THEN nominal ELSE 0 END) AS totalMasuk,
				   SUM(CASE WHEN jenis='Keluar' THEN nominal ELSE 0 END) AS totalKeluar
			FROM tb_transaksi
			WHERE YEAR(tanggal) = YEAR(CURDATE()) AND status_konfirmasi = 'Sukses'
			GROUP BY MONTH(tanggal)
			ORDER BY MONTH(tanggal)
		")->result_array();

		// ✅ Siapkan array 12 bulan (Januari s/d Desember) default 0
		$bulanNama = [
			1 => 'Januari', 2 => 'Februari', 3 => 'Maret',
			4 => 'April', 5 => 'Mei', 6 => 'Juni',
			7 => 'Juli', 8 => 'Agustus', 9 => 'September',
			10 => 'Oktober', 11 => 'November', 12 => 'Desember'
		];

		$masuk  = array_fill(1, 12, 0);
		$keluar = array_fill(1, 12, 0);

		// ✅ Masukkan data hasil query ke array
		foreach ($query as $row) {
			$bulanIndex = (int)$row['bulan'];
			$masuk[$bulanIndex]  = (int)$row['totalMasuk'];
			$keluar[$bulanIndex] = (int)$row['totalKeluar'];
		}

		// ✅ Kirim data ke view
		$data['bulan']  = json_encode(array_values($bulanNama));
		$data['masuk']  = json_encode(array_values($masuk));
		$data['keluar'] = json_encode(array_values($keluar));

		$this->load->view('admin/templates/header', $data);
		$this->load->view('admin/templates/sidebar');
		$this->load->view('admin/dashboard', $data);
		$this->load->view('admin/templates/footer');
	}
}
