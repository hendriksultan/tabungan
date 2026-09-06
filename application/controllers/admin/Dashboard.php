<?php
defined('BASEPATH') or exit('No direct script access allowed');

class Dashboard extends CI_Controller
{

	private $userLevel;
	private $isSuperAdmin = false;
	private $cabangId = 0;

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

		$this->userLevel = strtolower(
			trim((string) $this->session->userdata('level'))
		);

		$this->isSuperAdmin = (
			$this->userLevel === 'super admin'
		);

		$this->cabangId = (int) $this->session->userdata(
			'cabang_id'
		);
	}

	public function index()
	{
		$data['title'] = 'Dashboard';
		$data['is_pengelola'] = in_array(
			$this->userLevel,
			['administrator', 'super admin'],
			true
		);

		$data['nama_scope'] = $this->isSuperAdmin
			? 'Seluruh Cabang'
			: (
				$this->session->userdata('nama_cabang')
				?: 'Cabang belum ditentukan'
			);

		if ($data['is_pengelola']) {
			$this->siapkanDashboardPengelola($data);
		} else {
			$this->siapkanDashboardNasabah($data);
		}

		$this->load->view('admin/templates/header', $data);
		$this->load->view('admin/templates/sidebar');
		$this->load->view('admin/dashboard', $data);
		$this->load->view('admin/templates/footer');
	}

	private function siapkanDashboardPengelola(&$data)
	{
		if (!$this->isSuperAdmin && $this->cabangId <= 0) {
			$this->session->set_flashdata(
				'pesanError',
				'Administrator belum terhubung dengan cabang!'
			);

			redirect('home/logout');
			exit;
		}

		$transaksiMasuk = $this->jumlahTransaksi('Masuk');
		$transaksiKeluar = $this->jumlahTransaksi('Keluar');

		$transferMasuk = $this->jumlahTransfer(
			'cabang_tujuan_id'
		);

		$transferKeluar = $this->jumlahTransfer(
			'cabang_asal_id'
		);

		$totalTarget = $this->jumlahTarget();

		$data['saldo_detail'] = [
			'totalMasuk' => $transaksiMasuk + $transferMasuk,
			'totalKeluar' => $transaksiKeluar + $transferKeluar,
			'sisaSaldo' => (
				$transaksiMasuk +
				$transferMasuk -
				$transaksiKeluar -
				$transferKeluar +
				$totalTarget
			)
		];

		$data['total_transaksi'] = $this->hitungTotalTransaksi();
		$data['total_transfer'] = $this->hitungTotalTransfer();
		$data['total_nasabah'] = $this->hitungTotalNasabah();
		$data['nasabah_laki'] = $this->hitungNasabahGender(
			'Laki-Laki'
		);
		$data['nasabah_perempuan'] = $this->hitungNasabahGender(
			'Perempuan'
		);

		$grafik = $this->grafikTransaksiBulanan();

		$data['bulan'] = json_encode($grafik['bulan']);
		$data['masuk'] = json_encode($grafik['masuk']);
		$data['keluar'] = json_encode($grafik['keluar']);

		$data['subtitle'] = $this->isSuperAdmin
			? 'Ringkasan keuangan seluruh cabang'
			: 'Ringkasan keuangan cabang';
	}

	private function siapkanDashboardNasabah(&$data)
	{
		$idNasabah = (int) $this->session->userdata('id');

		$masukTransaksi = $this->db->query(
			"SELECT IFNULL(SUM(nominal), 0) AS total
             FROM tb_transaksi
             WHERE idNasabah = ?
               AND jenis = 'Masuk'
               AND status_konfirmasi = 'Sukses'",
			[$idNasabah]
		)->row()->total;

		$keluarTransaksi = $this->db->query(
			"SELECT IFNULL(SUM(nominal), 0) AS total
             FROM tb_transaksi
             WHERE idNasabah = ?
               AND jenis = 'Keluar'
               AND status_konfirmasi = 'Sukses'",
			[$idNasabah]
		)->row()->total;

		$masukTransfer = $this->db->query(
			"SELECT IFNULL(SUM(nominal), 0) AS total
             FROM tb_transfer
             WHERE idPenerima = ?
               AND status_transfer = 'Sukses'",
			[$idNasabah]
		)->row()->total;

		$keluarTransfer = $this->db->query(
			"SELECT IFNULL(SUM(nominal), 0) AS total
             FROM tb_transfer
             WHERE idPengirim = ?
               AND status_transfer = 'Sukses'",
			[$idNasabah]
		)->row()->total;

		$data['saldo_nasabah'] =
			(float) $masukTransaksi +
			(float) $masukTransfer -
			(float) $keluarTransaksi -
			(float) $keluarTransfer;

		$data['total_transaksi_saya'] = $this->db
			->where('idNasabah', $idNasabah)
			->count_all_results('tb_transaksi');

		$this->db->where('status_transfer', 'Sukses');
		$this->db->group_start();
		$this->db->where('idPengirim', $idNasabah);
		$this->db->or_where('idPenerima', $idNasabah);
		$this->db->group_end();

		$data['total_transfer_saya'] = $this->db
			->count_all_results('tb_transfer');

		$data['subtitle'] = 'Ringkasan rekening Anda';
	}

	private function jumlahTransaksi($jenis)
	{
		$this->db->select(
			'IFNULL(SUM(nominal), 0) AS total',
			false
		);

		$this->db->where('jenis', $jenis);
		$this->db->where('status_konfirmasi', 'Sukses');

		if (!$this->isSuperAdmin) {
			$this->db->where('cabang_id', $this->cabangId);
		}

		return (float) $this->db
			->get('tb_transaksi')
			->row()
			->total;
	}

	private function jumlahTransfer($kolomCabang)
	{
		$this->db->select(
			'IFNULL(SUM(nominal), 0) AS total',
			false
		);

		$this->db->where('status_transfer', 'Sukses');

		if (!$this->isSuperAdmin) {
			$this->db->where(
				$kolomCabang,
				$this->cabangId
			);
		}

		return (float) $this->db
			->get('tb_transfer')
			->row()
			->total;
	}

	private function jumlahTarget()
	{
		$this->db->select(
			'IFNULL(SUM(tb_target.terkumpul), 0) AS total',
			false
		);

		$this->db->from('tb_target');

		$this->db->join(
			'tb_user',
			'tb_user.id = tb_target.id_nasabah',
			'left'
		);

		if (!$this->isSuperAdmin) {
			$this->db->where(
				'tb_user.cabang_id',
				$this->cabangId
			);
		}

		return (float) $this->db
			->get()
			->row()
			->total;
	}

	private function hitungTotalTransaksi()
	{
		$this->db->where('status_konfirmasi', 'Sukses');

		if (!$this->isSuperAdmin) {
			$this->db->where('cabang_id', $this->cabangId);
		}

		return $this->db->count_all_results('tb_transaksi');
	}

	private function hitungTotalTransfer()
	{
		$this->db->where('status_transfer', 'Sukses');

		if (!$this->isSuperAdmin) {
			$this->db->group_start();
			$this->db->where(
				'cabang_asal_id',
				$this->cabangId
			);
			$this->db->or_where(
				'cabang_tujuan_id',
				$this->cabangId
			);
			$this->db->group_end();
		}

		return $this->db->count_all_results('tb_transfer');
	}

	private function hitungTotalNasabah()
	{
		$this->db->where('level', 'Nasabah');

		if (!$this->isSuperAdmin) {
			$this->db->where('cabang_id', $this->cabangId);
		}

		return $this->db->count_all_results('tb_user');
	}

	private function hitungNasabahGender($gender)
	{
		$this->db->where('level', 'Nasabah');
		$this->db->where('jenisKelamin', $gender);

		if (!$this->isSuperAdmin) {
			$this->db->where('cabang_id', $this->cabangId);
		}

		return $this->db->count_all_results('tb_user');
	}

	private function grafikTransaksiBulanan()
	{
		$namaBulan = [
			1 => 'Januari',
			2 => 'Februari',
			3 => 'Maret',
			4 => 'April',
			5 => 'Mei',
			6 => 'Juni',
			7 => 'Juli',
			8 => 'Agustus',
			9 => 'September',
			10 => 'Oktober',
			11 => 'November',
			12 => 'Desember'
		];

		$masuk = array_fill(1, 12, 0);
		$keluar = array_fill(1, 12, 0);

		$this->db->select(
			"MONTH(tanggal) AS bulan,
             SUM(
                CASE WHEN jenis = 'Masuk'
                THEN nominal ELSE 0 END
             ) AS totalMasuk,
             SUM(
                CASE WHEN jenis = 'Keluar'
                THEN nominal ELSE 0 END
             ) AS totalKeluar",
			false
		);

		$this->db->from('tb_transaksi');
		$this->db->where('YEAR(tanggal)', date('Y'));
		$this->db->where('status_konfirmasi', 'Sukses');

		if (!$this->isSuperAdmin) {
			$this->db->where('cabang_id', $this->cabangId);
		}

		$this->db->group_by('MONTH(tanggal)');
		$this->db->order_by('MONTH(tanggal)', 'ASC');

		$hasil = $this->db->get()->result_array();

		foreach ($hasil as $row) {
			$nomorBulan = (int) $row['bulan'];

			$masuk[$nomorBulan] = (float) $row['totalMasuk'];
			$keluar[$nomorBulan] = (float) $row['totalKeluar'];
		}

		return [
			'bulan' => array_values($namaBulan),
			'masuk' => array_values($masuk),
			'keluar' => array_values($keluar)
		];
	}
}
