<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Transaksi extends CI_Controller {

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
		$data['title']		= 'Data Transaksi';
		$data['subtitle']	= 'Menampilkan semua data transaksi';

        $userLevel = strtolower($this->session->userdata('level'));
        
        // PERBAIKAN 1: Pengecekan Level
        if($userLevel == 'nasabah'){
            $this->db->where('idNasabah', $this->session->userdata('id'));
        }
        
        $data['transaksi'] = $this->m_model->get_desc('tb_transaksi');
        $this->db->where('level', 'Nasabah');
        $data['nasabah'] = $this->m_model->get_desc('tb_user');
		
		$this->load->view('admin/templates/header', $data);
		$this->load->view('admin/templates/sidebar');
		$this->load->view('admin/transaksi');
		$this->load->view('admin/templates/footer');
    }

    public function delete($id)
    {
        // PERBAIKAN 2: Batasi akses delete hanya untuk admin dan super admin
        $userLevel = strtolower($this->session->userdata('level'));
        if($userLevel != 'administrator' && $userLevel != 'super admin') {
            $this->session->set_flashdata('pesan', 'Akses Ditolak!');
            redirect('admin/transaksi');
        }

        $where = array('id' => $id );

        $this->m_model->delete($where, 'tb_transaksi');
        $this->session->set_flashdata('pesan','Data berhasil dihapus!');
        redirect('admin/transaksi');
    }
    
    
    public function insert()
    {
        // PERBAIKAN 3: Batasi akses insert hanya untuk admin dan super admin
        $userLevel = strtolower($this->session->userdata('level'));
        if($userLevel != 'administrator' && $userLevel != 'super admin') {
            $this->session->set_flashdata('pesan', 'Akses Ditolak!');
            redirect('admin/transaksi');
        }

        date_default_timezone_set('Asia/Jakarta');

        $idAdmin        = $this->session->userdata('id');
        // PERBAIKAN 4: Gunakan $this->input->post()
        $idNasabah      = $this->input->post('idNasabah');
        $tanggal        = $this->input->post('tanggal');
        $nominal        = $this->input->post('nominal');
        $jenis          = $this->input->post('jenis');
        $keterangan     = $this->input->post('keterangan');
        $terdaftar      = date('Y-m-d H:i:s');

        if($nominal > 0) {
            if($jenis == 'Masuk') {
                $data = array(
                    'idAdmin'       => $idAdmin,
                    'idNasabah'     => $idNasabah,
                    'tanggal'       => $tanggal,
                    'nominal'       => $nominal,
                    'jenis'         => $jenis,
                    'keterangan'    => $keterangan,
                    'terdaftar'     => $terdaftar,
                );
        
                $this->m_model->insert($data, 'tb_transaksi');
                $this->session->set_flashdata('pesan','Data berhasil ditambahkan!');
            } elseif($jenis == 'Keluar') {
                foreach ($this->db->query('SELECT SUM(nominal) AS totalTabunganMasuk FROM tb_transaksi WHERE idNasabah="'.$idNasabah.'" AND jenis="Masuk"')->result() as $tbMsk) {}
                foreach ($this->db->query('SELECT SUM(nominal) AS totalTransferMasuk FROM tb_transfer WHERE idPenerima="'.$idNasabah.'"')->result() as $tfMsk) {}
    
                $totalMasuk = $tbMsk->totalTabunganMasuk + $tfMsk->totalTransferMasuk ;
    
                foreach ($this->db->query('SELECT SUM(nominal) AS totalTabunganKeluar FROM tb_transaksi WHERE idNasabah="'.$idNasabah.'" AND jenis="Keluar"')->result() as $tbKlr) {}
                foreach ($this->db->query('SELECT SUM(nominal) AS totalTransferKeluar FROM tb_transfer WHERE idPengirim="'.$idNasabah.'"')->result() as $tfKlr) {}
    
                $totalKeluar = $tbKlr->totalTabunganKeluar + $tfKlr->totalTransferKeluar ;
    
                $sisaSaldo  = $totalMasuk - $totalKeluar;
    
                if($sisaSaldo >= $nominal) {
                    $data = array(
                        'idAdmin'       => $idAdmin,
                        'idNasabah'     => $idNasabah,
                        'tanggal'       => $tanggal,
                        'nominal'       => $nominal,
                        'jenis'         => $jenis,
                        'keterangan'    => $keterangan,
                        'terdaftar'     => $terdaftar,
                    );
                    
                    $this->m_model->insert($data, 'tb_transaksi');
                    $this->session->set_flashdata('pesan','Data berhasil ditambahkan!');
                } else {
                    $this->session->set_flashdata('pesanError','Saldo nasabah tidak cukup!');
                }
            }
        } else {
            $this->session->set_flashdata('pesanError','Nominal tidak valid!');
        }

        redirect('admin/transaksi');
    }

    public function update($id)
    {
        // PERBAIKAN 5: Batasi akses update
        $userLevel = strtolower($this->session->userdata('level'));
        if($userLevel != 'administrator' && $userLevel != 'super admin') {
            $this->session->set_flashdata('pesan', 'Akses Ditolak!');
            redirect('admin/transaksi');
        }

        $tanggal        = $this->input->post('tanggal');
        $nominal        = $this->input->post('nominal');
        $keterangan     = $this->input->post('keterangan');

        $data = array(
            'tanggal'       => $tanggal,
            'nominal'       => $nominal,
            'keterangan'    => $keterangan,
        );

        $where = array('id' => $id );

        $this->m_model->update($where, $data, 'tb_transaksi');
        $this->session->set_flashdata('pesan','Data berhasil diubah!');
        redirect('admin/transaksi');
    }

    public function carinasabah()
    {
        $idNasabah = $this->input->post('idNasabah');

        redirect("admin/transaksi/ceksaldo/$idNasabah");
    }

   public function ceksaldo($idNasabah)
    {
        // PERBAIKAN 6: Batasi akses ceksaldo
        $userLevel = strtolower($this->session->userdata('level'));
        if($userLevel != 'administrator' && $userLevel != 'super admin') {
            $this->session->set_flashdata('pesan', 'Akses Ditolak!');
            redirect('admin/transaksi');
        }

        $data['title']     = 'Cek Saldo Nasabah';
        $data['subtitle']  = 'Semua data transaksi dan transfer nasabah akan ditampilkan disini';
        $data['idNasabah'] = $idNasabah;
    
        // Ambil data user
        $this->db->where('id', $idNasabah);
        $data['user'] = $this->m_model->get_desc('tb_user');
    
        // Ambil transaksi
        $this->db->where('idNasabah', $idNasabah);
        $data['transaksi'] = $this->m_model->get_desc('tb_transaksi');
    
        // Ambil transfer
        $data['transfer'] = $this->db->query("
            SELECT * FROM tb_transfer 
            WHERE idPengirim = '$idNasabah' OR idPenerima = '$idNasabah'
            ORDER BY id DESC
        ");
    
        // Hitung total masuk
        $qMasuk = $this->db->query("
            SELECT 
                (SELECT IFNULL(SUM(nominal),0) 
                 FROM tb_transaksi 
                 WHERE idNasabah='$idNasabah' AND jenis='Masuk')
                +
                (SELECT IFNULL(SUM(nominal),0) 
                 FROM tb_transfer 
                 WHERE idPenerima='$idNasabah')
            AS totalMasuk
        ")->row();
    
        // Hitung total keluar
        $qKeluar = $this->db->query("
            SELECT 
                (SELECT IFNULL(SUM(nominal),0) 
                 FROM tb_transaksi 
                 WHERE idNasabah='$idNasabah' AND jenis='Keluar')
                +
                (SELECT IFNULL(SUM(nominal),0) 
                 FROM tb_transfer 
                 WHERE idPengirim='$idNasabah')
            AS totalKeluar
        ")->row();
    
        $data['totalMasuk']  = $qMasuk->totalMasuk;
        $data['totalKeluar'] = $qKeluar->totalKeluar;
        $data['sisaSaldo']   = $qMasuk->totalMasuk - $qKeluar->totalKeluar;
    
        // Load views
        $this->load->view('admin/templates/header', $data);
        $this->load->view('admin/templates/sidebar');
        $this->load->view('admin/ceksaldo', $data);
        $this->load->view('admin/templates/footer');
    }

    public function rekap()
    {
        // PERBAIKAN 7: Batasi akses rekap
        $userLevel = strtolower($this->session->userdata('level'));
        if($userLevel != 'administrator' && $userLevel != 'super admin') {
            $this->session->set_flashdata('pesan', 'Akses Ditolak!');
            redirect('admin/transaksi');
        }

        $data['title']  = 'Rekap Data Transaksi';

        $dariTanggal    = $this->input->post('dariTanggal');
        $sampaiTanggal  = $this->input->post('sampaiTanggal');

        $data['transaksi']      = $this->db->query('SELECT * FROM tb_transaksi WHERE tanggal BETWEEN "'.$dariTanggal.'" AND "'.$sampaiTanggal.'" ');
        $data['jumlahMasuk']    = $this->db->query('SELECT SUM(nominal) AS jumlahMasuk FROM tb_transaksi WHERE tanggal BETWEEN "'.$dariTanggal.'" AND "'.$sampaiTanggal.'" AND jenis="Masuk"');
        $data['jumlahKeluar']   = $this->db->query('SELECT SUM(nominal) AS jumlahKeluar FROM tb_transaksi WHERE tanggal BETWEEN "'.$dariTanggal.'" AND "'.$sampaiTanggal.'" AND jenis="Keluar"');

        $data['dariTanggal']    = $dariTanggal;
        $data['sampaiTanggal']  = $sampaiTanggal;

        $this->load->view('admin/rekaptransaksi', $data);
    }
}