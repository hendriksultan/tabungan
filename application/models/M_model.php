<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class M_model extends CI_Model {

	public function get_where($where, $table)
	{
		return $this->db->get_where($table, $where);
	}

	public function insert($data, $table)
	{
		$this->db->insert($table, $data);
	}

	public function get_desc($table)
	{
		$this->db->ORDER_BY('id', 'desc');
		return $this->db->get($table);
	}

	public function delete($where, $table)
	{
		$this->db->delete($table, $where);
	}

	public function update($where, $data, $table)
	{
		$this->db->where($where);
		$this->db->update($table, $data);
	}

	// ================================
	// FUNGSI SALDO KESELURUHAN (HANYA HITUNG YANG SUKSES)
	// ================================
	public function get_saldo_detail_all()
	{
		$sql = "
			SELECT 
				-- Total Masuk
				(IFNULL((SELECT SUM(nominal) FROM tb_transaksi WHERE jenis='Masuk' AND status_konfirmasi='Sukses'),0) 
				 + IFNULL((SELECT SUM(nominal) FROM tb_transfer),0)) AS totalMasuk,

				-- Total Keluar
				(IFNULL((SELECT SUM(nominal) FROM tb_transaksi WHERE jenis='Keluar' AND status_konfirmasi='Sukses'),0) 
				 + IFNULL((SELECT SUM(nominal) FROM tb_transfer),0)) AS totalKeluar,

				-- Sisa Saldo = (Masuk Asli - Keluar Asli) + Uang yang Mengendap di Celengan Impian
				((IFNULL((SELECT SUM(nominal) FROM tb_transaksi WHERE jenis='Masuk' AND status_konfirmasi='Sukses'),0) 
				 - IFNULL((SELECT SUM(nominal) FROM tb_transaksi WHERE jenis='Keluar' AND status_konfirmasi='Sukses'),0))
				 + IFNULL((SELECT SUM(terkumpul) FROM tb_target),0)) AS sisaSaldo
		";

		return $this->db->query($sql)->row_array();
	}

}