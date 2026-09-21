<?php
defined('BASEPATH') or exit('No direct script access allowed');

class Settlement extends CI_Controller
{
    private $userLevel = '';
    private $isSuperAdmin = false;
    private $cabangId = 0;
    private $userId = 0;

    public function __construct()
    {
        parent::__construct();
        date_default_timezone_set('Asia/Jakarta');

        if (!$this->session->userdata('level')) {
            $this->session->set_flashdata(
                'pesan',
                'Anda harus masuk terlebih dahulu!'
            );
            redirect('home');
            return;
        }

        $this->userLevel = strtolower(trim(
            (string) $this->session->userdata('level')
        ));
        $this->isSuperAdmin = $this->userLevel === 'super admin';
        $this->cabangId = (int) $this->session->userdata('cabang_id');
        $this->userId = (int) $this->session->userdata('id');

        if (!in_array(
            $this->userLevel,
            ['administrator', 'super admin'],
            true
        )) {
            $this->gagal('Akses settlement hanya untuk Administrator.');
            return;
        }

        if (!$this->isSuperAdmin && $this->cabangId <= 0) {
            $this->gagal('Administrator belum terhubung dengan cabang.');
            return;
        }
    }

    public function index()
    {
        $data['title'] = 'Settlement Antar Cabang';
        $data['subtitle'] = $this->isSuperAdmin
            ? 'Pantau pemindahan dana fisik seluruh cabang'
            : 'Proses dan verifikasi pemindahan dana cabang Anda';
        $data['isSuperAdmin'] = $this->isSuperAdmin;
        $data['cabangId'] = $this->cabangId;

        $data['kewajibanTerbuka'] = $this->ambilKewajibanTerbuka();
        $data['rekeningAsal'] = $this->ambilRekeningAktif(
            $this->isSuperAdmin ? null : $this->cabangId
        );
        $data['rekeningTujuan'] = $this->ambilRekeningAktif(null);
        $data['settlement'] = $this->ambilSettlement();

        $this->load->view('admin/templates/header', $data);
        $this->load->view('admin/templates/sidebar');
        $this->load->view('admin/settlement', $data);
        $this->load->view('admin/templates/footer');
    }

    public function kirim()
    {
        if (!$this->pastikanAdminCabang()) {
            return;
        }

        $this->pastikanPost();

        $ids = $this->normalisasiIds(
            $this->input->post('kewajiban_ids')
        );
        $rekeningAsalId = (int) $this->input->post('rekening_asal_id');
        $rekeningTujuanId = (int) $this->input->post('rekening_tujuan_id');
        $referensiBank = trim((string) $this->input->post(
            'referensi_bank',
            true
        ));
        $catatan = trim((string) $this->input->post('catatan', true));

        if (empty($ids)) {
            $this->gagal('Pilih minimal satu kewajiban yang akan dibayar.');
            return;
        }

        if ($rekeningAsalId <= 0 || $rekeningTujuanId <= 0) {
            $this->gagal('Rekening asal dan tujuan wajib dipilih.');
            return;
        }

        if ($referensiBank === '' || strlen($referensiBank) > 100) {
            $this->gagal('Referensi bank wajib diisi, maksimal 100 karakter.');
            return;
        }

        if (strlen($catatan) > 500) {
            $this->gagal('Catatan maksimal 500 karakter.');
            return;
        }

        $bukti = $this->unggahBukti('bukti_transfer');
        if ($bukti === null) {
            return;
        }

        $this->db->trans_begin();

        $kewajiban = $this->kunciKewajiban($ids);

        if (count($kewajiban) !== count($ids)) {
            $this->batalkanDenganBukti(
                $bukti,
                'Sebagian kewajiban tidak ditemukan atau sudah diproses.'
            );
            return;
        }

        $cabangTujuanId = 0;
        $nominalTotal = 0;

        foreach ($kewajiban as $row) {
            if ((int) $row['cabang_asal_id'] !== $this->cabangId) {
                $this->batalkanDenganBukti(
                    $bukti,
                    'Kewajiban bukan milik cabang Anda.'
                );
                return;
            }

            if ($row['status'] !== 'Terbuka') {
                $this->batalkanDenganBukti(
                    $bukti,
                    'Kewajiban sudah masuk proses settlement.'
                );
                return;
            }

            if ($cabangTujuanId === 0) {
                $cabangTujuanId = (int) $row['cabang_tujuan_id'];
            }

            if ((int) $row['cabang_tujuan_id'] !== $cabangTujuanId) {
                $this->batalkanDenganBukti(
                    $bukti,
                    'Semua kewajiban dalam satu settlement harus menuju cabang yang sama.'
                );
                return;
            }

            $nominalTotal += (int) $row['nominal'];
        }

        $rekeningAsal = $this->rekeningAktif(
            $rekeningAsalId,
            $this->cabangId
        );
        $rekeningTujuan = $this->rekeningAktif(
            $rekeningTujuanId,
            $cabangTujuanId
        );

        if (!$rekeningAsal || !$rekeningTujuan) {
            $this->batalkanDenganBukti(
                $bukti,
                'Rekening asal atau tujuan tidak aktif/tidak sesuai cabang.'
            );
            return;
        }

        if ($nominalTotal <= 0) {
            $this->batalkanDenganBukti($bukti, 'Nominal settlement tidak valid.');
            return;
        }

        if ($this->referensiSudahAda($referensiBank)) {
            $this->batalkanDenganBukti(
                $bukti,
                'Referensi bank sudah digunakan.'
            );
            return;
        }

        $sekarang = date('Y-m-d H:i:s');
        $kode = $this->buatKodeSettlement();

        $header = [
            'kode_settlement'            => $kode,
            'cabang_asal_id'             => $this->cabangId,
            'cabang_tujuan_id'           => $cabangTujuanId,
            'rekening_asal_id'            => (int) $rekeningAsal['id'],
            'rekening_tujuan_id'          => (int) $rekeningTujuan['id'],
            'rekening_asal_nama'          => $rekeningAsal['nama_bank'],
            'rekening_asal_nomor'         => $rekeningAsal['nomor_rekening'],
            'rekening_asal_atas_nama'     => $rekeningAsal['atas_nama'],
            'rekening_tujuan_nama'        => $rekeningTujuan['nama_bank'],
            'rekening_tujuan_nomor'       => $rekeningTujuan['nomor_rekening'],
            'rekening_tujuan_atas_nama'   => $rekeningTujuan['atas_nama'],
            'nominal_total'               => $nominalTotal,
            'status'                      => 'MenungguVerifikasi',
            'referensi_bank'              => $referensiBank,
            'bukti_transfer'              => $bukti,
            'dibuat_oleh'                 => $this->userId,
            'dikirim_oleh'                => $this->userId,
            'dikirim_pada'                => $sekarang,
            'catatan'                     => $catatan !== '' ? $catatan : null,
            'dibuat_pada'                 => $sekarang,
            'diperbarui_pada'             => $sekarang
        ];

        if (!$this->db->insert('tb_settlement_cabang', $header)) {
            $this->batalkanDenganBukti($bukti, 'Settlement gagal disimpan.');
            return;
        }

        $idSettlement = (int) $this->db->insert_id();

        foreach ($kewajiban as $row) {
            $detail = [
                'id_settlement'       => $idSettlement,
                'id_kewajiban'        => (int) $row['id_kewajiban'],
                'nominal_dialokasikan'=> (int) $row['nominal'],
                'dibuat_pada'         => $sekarang
            ];

            if (!$this->db->insert('tb_settlement_detail', $detail)) {
                $this->batalkanDenganBukti(
                    $bukti,
                    'Detail settlement gagal disimpan.'
                );
                return;
            }
        }

        $this->db->where_in('id_kewajiban', $ids);
        $this->db->where('status', 'Terbuka');
        $berhasilUpdate = $this->db->update(
            'tb_kewajiban_antar_cabang',
            [
                'status'            => 'Dibatch',
                'catatan_status'    => 'Masuk settlement ' . $kode,
                'diperbarui_pada'   => $sekarang
            ]
        );

        if (!$berhasilUpdate || $this->db->affected_rows() !== count($ids)) {
            $this->batalkanDenganBukti(
                $bukti,
                'Status kewajiban gagal diperbarui.'
            );
            return;
        }

        if ($this->db->trans_status() === false) {
            $this->batalkanDenganBukti($bukti, 'Settlement gagal diproses.');
            return;
        }

        $this->db->trans_commit();
        $this->sukses('Bukti transfer berhasil dikirim untuk diverifikasi.');
    }

    public function verifikasi($idSettlement)
    {
        if (!$this->pastikanAdminCabang()) {
            return;
        }

        $this->pastikanPost();
        $idSettlement = (int) $idSettlement;

        $this->db->trans_begin();
        $settlement = $this->kunciSettlement($idSettlement);

        if (!$settlement) {
            $this->batalkan('Settlement tidak ditemukan.');
            return;
        }

        if ((int) $settlement['cabang_tujuan_id'] !== $this->cabangId) {
            $this->batalkan('Hanya admin cabang tujuan yang dapat memverifikasi.');
            return;
        }

        if ($settlement['status'] !== 'MenungguVerifikasi') {
            $this->batalkan('Settlement tidak sedang menunggu verifikasi.');
            return;
        }

        if ((int) $settlement['dikirim_oleh'] === $this->userId) {
            $this->batalkan('Pengirim tidak boleh memverifikasi settlement sendiri.');
            return;
        }

        $detail = $this->detailSettlement($idSettlement);
        if (empty($detail)) {
            $this->batalkan('Detail settlement tidak ditemukan.');
            return;
        }

        $totalDetail = 0;
        $ids = [];
        foreach ($detail as $row) {
            $totalDetail += (int) $row['nominal_dialokasikan'];
            $ids[] = (int) $row['id_kewajiban'];
        }

        if ($totalDetail !== (int) $settlement['nominal_total']) {
            $this->batalkan('Total detail settlement tidak sesuai.');
            return;
        }

        $sekarang = date('Y-m-d H:i:s');

        $this->db->where('id_settlement', $idSettlement);
        $this->db->where('status', 'MenungguVerifikasi');
        $headerOk = $this->db->update('tb_settlement_cabang', [
            'status'               => 'Selesai',
            'diverifikasi_oleh'    => $this->userId,
            'diverifikasi_pada'    => $sekarang,
            'diperbarui_pada'      => $sekarang
        ]);

        $this->db->where_in('id_kewajiban', $ids);
        $this->db->where('status', 'Dibatch');
        $kewajibanOk = $this->db->update(
            'tb_kewajiban_antar_cabang',
            [
                'status'          => 'Selesai',
                'selesai_pada'    => $sekarang,
                'catatan_status'  => 'Selesai melalui ' . $settlement['kode_settlement'],
                'diperbarui_pada' => $sekarang
            ]
        );

        if (
            !$headerOk ||
            !$kewajibanOk ||
            $this->db->affected_rows() !== count($ids) ||
            $this->db->trans_status() === false
        ) {
            $this->batalkan('Verifikasi settlement gagal.');
            return;
        }

        $this->db->trans_commit();
        $this->sukses('Settlement berhasil diverifikasi dan diselesaikan.');
    }

    public function tolak($idSettlement)
    {
        if (!$this->pastikanAdminCabang()) {
            return;
        }

        $this->pastikanPost();
        $alasan = trim((string) $this->input->post('alasan_penolakan', true));

        if ($alasan === '' || strlen($alasan) > 500) {
            $this->gagal('Alasan penolakan wajib diisi, maksimal 500 karakter.');
            return;
        }

        $this->db->trans_begin();
        $settlement = $this->kunciSettlement((int) $idSettlement);

        if (!$settlement) {
            $this->batalkan('Settlement tidak ditemukan.');
            return;
        }

        if ((int) $settlement['cabang_tujuan_id'] !== $this->cabangId) {
            $this->batalkan('Hanya admin cabang tujuan yang dapat menolak.');
            return;
        }

        if ($settlement['status'] !== 'MenungguVerifikasi') {
            $this->batalkan('Settlement tidak sedang menunggu verifikasi.');
            return;
        }

        $sekarang = date('Y-m-d H:i:s');
        $this->db->where('id_settlement', (int) $idSettlement);
        $this->db->where('status', 'MenungguVerifikasi');
        $ok = $this->db->update('tb_settlement_cabang', [
            'status'             => 'Ditolak',
            'ditolak_oleh'       => $this->userId,
            'ditolak_pada'       => $sekarang,
            'alasan_penolakan'   => $alasan,
            'diperbarui_pada'    => $sekarang
        ]);

        if (!$ok || $this->db->trans_status() === false) {
            $this->batalkan('Penolakan settlement gagal disimpan.');
            return;
        }

        $this->db->trans_commit();
        $this->sukses('Settlement ditolak dan dikembalikan kepada admin asal.');
    }

    public function kirim_ulang($idSettlement)
    {
        if (!$this->pastikanAdminCabang()) {
            return;
        }

        $this->pastikanPost();

        $referensiBank = trim((string) $this->input->post(
            'referensi_bank',
            true
        ));
        $catatan = trim((string) $this->input->post('catatan', true));

        if ($referensiBank === '' || strlen($referensiBank) > 100) {
            $this->gagal('Referensi bank wajib diisi, maksimal 100 karakter.');
            return;
        }

        if (strlen($catatan) > 500) {
            $this->gagal('Catatan maksimal 500 karakter.');
            return;
        }

        $buktiBaru = $this->unggahBukti('bukti_transfer');
        if ($buktiBaru === null) {
            return;
        }

        $this->db->trans_begin();
        $settlement = $this->kunciSettlement((int) $idSettlement);

        if (!$settlement) {
            $this->batalkanDenganBukti($buktiBaru, 'Settlement tidak ditemukan.');
            return;
        }

        if ((int) $settlement['cabang_asal_id'] !== $this->cabangId) {
            $this->batalkanDenganBukti(
                $buktiBaru,
                'Hanya admin cabang asal yang dapat mengirim ulang.'
            );
            return;
        }

        if ($settlement['status'] !== 'Ditolak') {
            $this->batalkanDenganBukti(
                $buktiBaru,
                'Hanya settlement yang ditolak yang dapat dikirim ulang.'
            );
            return;
        }

        if ($this->referensiSudahAda($referensiBank, (int) $idSettlement)) {
            $this->batalkanDenganBukti($buktiBaru, 'Referensi bank sudah digunakan.');
            return;
        }

        $buktiLama = $settlement['bukti_transfer'];
        $sekarang = date('Y-m-d H:i:s');
        $catatanAudit = trim(
            ($catatan !== '' ? $catatan . ' | ' : '') .
            'Kirim ulang setelah penolakan: ' .
            (string) $settlement['alasan_penolakan'] .
            ' | Bukti sebelumnya: ' .
            (string) $buktiLama
        );
        $catatanAudit = substr($catatanAudit, 0, 500);

        $this->db->where('id_settlement', (int) $idSettlement);
        $this->db->where('status', 'Ditolak');
        $ok = $this->db->update('tb_settlement_cabang', [
            'status'               => 'MenungguVerifikasi',
            'referensi_bank'       => $referensiBank,
            'bukti_transfer'       => $buktiBaru,
            'dikirim_oleh'         => $this->userId,
            'dikirim_pada'         => $sekarang,
            'catatan'              => $catatanAudit,
            'diperbarui_pada'      => $sekarang
        ]);

        if (!$ok || $this->db->trans_status() === false) {
            $this->batalkanDenganBukti($buktiBaru, 'Pengiriman ulang gagal.');
            return;
        }

        $this->db->trans_commit();
        $this->sukses('Bukti pengganti berhasil dikirim ulang.');
    }

    private function ambilKewajibanTerbuka()
    {
        $this->db->select([
            'k.*',
            'asal.kode AS kode_cabang_asal',
            'asal.nama AS nama_cabang_asal',
            'tujuan.kode AS kode_cabang_tujuan',
            'tujuan.nama AS nama_cabang_tujuan'
        ]);
        $this->db->from('tb_kewajiban_antar_cabang AS k');
        $this->db->join('tb_cabang AS asal', 'asal.id = k.cabang_asal_id');
        $this->db->join('tb_cabang AS tujuan', 'tujuan.id = k.cabang_tujuan_id');
        $this->db->where('k.status', 'Terbuka');

        if (!$this->isSuperAdmin) {
            $this->db->where('k.cabang_asal_id', $this->cabangId);
        }

        $this->db->order_by('k.dibuat_pada', 'ASC');
        return $this->db->get();
    }

    private function ambilSettlement()
    {
        $this->db->select([
            's.*',
            'asal.kode AS kode_cabang_asal',
            'asal.nama AS nama_cabang_asal',
            'tujuan.kode AS kode_cabang_tujuan',
            'tujuan.nama AS nama_cabang_tujuan',
            'pembuat.nama AS nama_pembuat',
            'pengirim.nama AS nama_pengirim',
            'verifikator.nama AS nama_verifikator',
            'penolak.nama AS nama_penolak',
            'COUNT(d.id_detail) AS jumlah_kewajiban',
            'GROUP_CONCAT(k.kode_kewajiban ORDER BY k.id_kewajiban SEPARATOR ", ") AS daftar_kewajiban'
        ]);
        $this->db->from('tb_settlement_cabang AS s');
        $this->db->join('tb_cabang AS asal', 'asal.id = s.cabang_asal_id');
        $this->db->join('tb_cabang AS tujuan', 'tujuan.id = s.cabang_tujuan_id');
        $this->db->join('tb_user AS pembuat', 'pembuat.id = s.dibuat_oleh', 'left');
        $this->db->join('tb_user AS pengirim', 'pengirim.id = s.dikirim_oleh', 'left');
        $this->db->join('tb_user AS verifikator', 'verifikator.id = s.diverifikasi_oleh', 'left');
        $this->db->join('tb_user AS penolak', 'penolak.id = s.ditolak_oleh', 'left');
        $this->db->join('tb_settlement_detail AS d', 'd.id_settlement = s.id_settlement', 'left');
        $this->db->join('tb_kewajiban_antar_cabang AS k', 'k.id_kewajiban = d.id_kewajiban', 'left');

        if (!$this->isSuperAdmin) {
            $this->db->group_start();
            $this->db->where('s.cabang_asal_id', $this->cabangId);
            $this->db->or_where('s.cabang_tujuan_id', $this->cabangId);
            $this->db->group_end();
        }

        $this->db->group_by('s.id_settlement');
        $this->db->order_by('s.id_settlement', 'DESC');
        return $this->db->get();
    }

    private function ambilRekeningAktif($cabangId)
    {
        $this->db->select([
            'r.*',
            'c.kode AS kode_cabang',
            'c.nama AS nama_cabang'
        ]);
        $this->db->from('tb_rekening_penampungan AS r');
        $this->db->join('tb_cabang AS c', 'c.id = r.cabang_id');
        $this->db->where('r.status', 'Aktif');
        $this->db->where('c.status', 'Aktif');

        if ($cabangId !== null) {
            $this->db->where('r.cabang_id', (int) $cabangId);
        }

        $this->db->order_by('c.nama', 'ASC');
        $this->db->order_by('r.urutan', 'ASC');
        return $this->db->get();
    }

    private function rekeningAktif($id, $cabangId)
    {
        return $this->db->get_where('tb_rekening_penampungan', [
            'id'        => (int) $id,
            'cabang_id' => (int) $cabangId,
            'status'    => 'Aktif'
        ])->row_array();
    }

    private function kunciKewajiban(array $ids)
    {
        $placeholders = implode(',', array_fill(0, count($ids), '?'));
        return $this->db->query(
            'SELECT * FROM tb_kewajiban_antar_cabang ' .
            'WHERE id_kewajiban IN (' . $placeholders . ') FOR UPDATE',
            $ids
        )->result_array();
    }

    private function kunciSettlement($id)
    {
        return $this->db->query(
            'SELECT * FROM tb_settlement_cabang ' .
            'WHERE id_settlement = ? FOR UPDATE',
            [(int) $id]
        )->row_array();
    }

    private function detailSettlement($id)
    {
        return $this->db->query(
            'SELECT * FROM tb_settlement_detail ' .
            'WHERE id_settlement = ? FOR UPDATE',
            [(int) $id]
        )->result_array();
    }

    private function normalisasiIds($ids)
    {
        if (!is_array($ids)) {
            return [];
        }

        $hasil = [];
        foreach ($ids as $id) {
            $id = (int) $id;
            if ($id > 0) {
                $hasil[$id] = $id;
            }
        }
        return array_values($hasil);
    }

    private function buatKodeSettlement()
    {
        do {
            $kode = 'STL-' . date('YmdHis') . '-' . strtoupper(bin2hex(random_bytes(3)));
            $ada = $this->db
                ->where('kode_settlement', $kode)
                ->count_all_results('tb_settlement_cabang') > 0;
        } while ($ada);

        return $kode;
    }

    private function referensiSudahAda($referensi, $kecualiId = 0)
    {
        $this->db->where('referensi_bank', $referensi);
        if ($kecualiId > 0) {
            $this->db->where('id_settlement !=', $kecualiId);
        }
        return $this->db->count_all_results('tb_settlement_cabang') > 0;
    }

    private function unggahBukti($field)
    {
        if (empty($_FILES[$field]['name'])) {
            $this->gagal('Bukti transfer wajib diunggah.');
            return null;
        }

        $folder = FCPATH . 'assets/settlement/';
        if (!is_dir($folder) && !mkdir($folder, 0755, true)) {
            $this->gagal('Folder bukti settlement tidak dapat dibuat.');
            return null;
        }

        $config = [
            'upload_path'      => $folder,
            'allowed_types'    => 'jpg|jpeg|png|pdf',
            'max_size'         => 5120,
            'encrypt_name'     => true,
            'remove_spaces'    => true,
            'detect_mime'      => true
        ];

        $this->load->library('upload', $config);
        $this->upload->initialize($config);

        if (!$this->upload->do_upload($field)) {
            $this->gagal(strip_tags($this->upload->display_errors('', '')));
            return null;
        }

        $data = $this->upload->data();
        return 'assets/settlement/' . basename($data['file_name']);
    }

    private function hapusBukti($path)
    {
        if (empty($path)) {
            return;
        }

        $path = str_replace('\\', '/', (string) $path);
        if (strpos($path, 'assets/settlement/') !== 0) {
            return;
        }

        $file = FCPATH . $path;
        if (is_file($file)) {
            @unlink($file);
        }
    }

    private function pastikanAdminCabang()
    {
        if ($this->isSuperAdmin) {
            $this->gagal('Super Admin hanya dapat memantau settlement.');
            return false;
        }
        return $this->userLevel === 'administrator';
    }

    private function pastikanPost()
    {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            $this->gagal('Gunakan metode POST.');
            exit;
        }
    }

    private function batalkanDenganBukti($bukti, $pesan)
    {
        $this->db->trans_rollback();
        $this->hapusBukti($bukti);
        $this->gagal($pesan);
    }

    private function batalkan($pesan)
    {
        $this->db->trans_rollback();
        $this->gagal($pesan);
    }

    private function sukses($pesan)
    {
        $this->session->set_flashdata('pesan', $pesan);
        redirect('admin/settlement');
    }

    private function gagal($pesan)
    {
        $this->session->set_flashdata('pesanError', $pesan);
        redirect('admin/settlement');
    }
}
