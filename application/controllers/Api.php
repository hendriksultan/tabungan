<?php
defined('BASEPATH') or exit('No direct script access allowed');

class Api extends CI_Controller
{
  public function __construct()
  {
    parent::__construct();

    date_default_timezone_set('Asia/Jakarta');

    header("Access-Control-Allow-Origin: *");
    header("Access-Control-Allow-Methods: GET, POST, OPTIONS, PUT, DELETE");
    header("Access-Control-Allow-Headers: Content-Type, Content-Length, Accept-Encoding, Authorization");

    if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
      header("HTTP/1.1 200 OK");
      exit();
    }

    header("Content-Type: application/json; charset=UTF-8");
    $this->load->database();
  }


  /**
   * Mengirim respons JSON dengan HTTP status code.
   */
  private function api_response($data, $http_code = 200)
  {
    $this->output->set_status_header($http_code);
    echo json_encode($data);
  }


  private function get_authorization_header()
  {
    $authorization = $this->input->get_request_header(
      'Authorization',
      true
    );

    if (
      empty($authorization) &&
      isset($_SERVER['HTTP_AUTHORIZATION'])
    ) {
      $authorization = $_SERVER['HTTP_AUTHORIZATION'];
    }

    if (
      empty($authorization) &&
      isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])
    ) {
      $authorization =
        $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
    }

    if (!is_string($authorization)) {
      return '';
    }

    return trim($authorization);
  }
  /**
   * Mengambil Bearer token dari header Authorization.
   */
  private function get_bearer_token()
  {
    $authorization =
      $this->get_authorization_header();

    if (
      $authorization === '' ||
      !preg_match(
        '/^Bearer\s+(\S+)$/i',
        $authorization,
        $matches
      )
    ) {
      return null;
    }

    $token = trim($matches[1]);

    // Token login harus berupa 64 karakter hexadecimal.
    if (
      strlen($token) !== 64 ||
      !ctype_xdigit($token)
    ) {
      return null;
    }

    return $token;
  }

  /**
   * Memvalidasi Bearer token dan mengembalikan data pengguna.
   */
  private function authenticate_api()
  {
    $authorization =
      $this->get_authorization_header();

    if ($authorization === '') {
      $this->api_response([
        'status'  => false,
        'message' => 'Bearer token tidak ditemukan.'
      ], 401);

      return null;
    }

    $token = $this->get_bearer_token();

    if (empty($token)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Format Bearer token tidak valid.'
      ], 401);

      return null;
    }

    $token_hash = hash('sha256', $token);

    $this->db->select(
      't.id AS token_id,
         t.id_user,
         t.expires_at,
         t.revoked_at,
         u.nama,
         u.username,
         u.level,
         u.cabang_id,
         c.kode AS kode_cabang,
         c.nama AS nama_cabang,
         c.status AS status_cabang,
         c.is_pusat'
    );
    $this->db->from('tb_api_token AS t');
    $this->db->join('tb_user AS u', 'u.id = t.id_user', 'inner');
    $this->db->join('tb_cabang AS c', 'c.id = u.cabang_id', 'left');
    $this->db->where('t.token_hash', $token_hash);
    $this->db->limit(1);

    $auth = $this->db->get()->row();

    if (!$auth) {
      $this->api_response([
        'status'  => false,
        'message' => 'Token tidak valid.'
      ], 401);

      return null;
    }

    if (!empty($auth->revoked_at)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Token sudah tidak aktif.'
      ], 401);

      return null;
    }

    if (
      empty($auth->expires_at) ||
      strtotime($auth->expires_at) <= time()
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Sesi login telah berakhir. Silakan login kembali.'
      ], 401);

      return null;
    }

    if (empty($auth->cabang_id)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Akun belum terhubung dengan cabang.'
      ], 403);

      return null;
    }

    if ($auth->status_cabang !== 'Aktif') {
      $this->api_response([
        'status'  => false,
        'message' => 'Cabang akun sedang tidak aktif.'
      ], 403);

      return null;
    }

    // Catat waktu terakhir token digunakan
    $this->db->where('id', $auth->token_id);
    $this->db->update('tb_api_token', [
      'last_used_at' => date('Y-m-d H:i:s')
    ]);

    return $auth;
  }

  // ==========================================
  // 1. ENDPOINT LOGIN (SUDAH DENGAN FOTO)
  // ==========================================
  public function login()
  {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
      echo json_encode([
        'status'  => false,
        'message' => 'Gunakan metode POST.'
      ]);
      return;
    }

    $request = json_decode($this->input->raw_input_stream, true);

    if (!is_array($request)) {
      echo json_encode([
        'status'  => false,
        'message' => 'Format permintaan tidak valid.'
      ]);
      return;
    }

    $username = trim((string) ($request['username'] ?? ''));
    $password = (string) ($request['password'] ?? '');
    $device   = trim((string) ($request['device'] ?? 'Perangkat tidak diketahui'));

    if ($username === '' || $password === '') {
      echo json_encode([
        'status'  => false,
        'message' => 'Username dan password harus diisi.'
      ]);
      return;
    }

    // Ambil pengguna beserta identitas cabangnya
    $this->db->select(
      'u.*, 
         c.kode AS kode_cabang,
         c.nama AS nama_cabang,
         c.status AS status_cabang,
         c.is_pusat'
    );
    $this->db->from('tb_user AS u');
    $this->db->join('tb_cabang AS c', 'c.id = u.cabang_id', 'left');
    $this->db->where('u.username', $username);
    $user = $this->db->get()->row();

    // Gunakan pesan yang sama agar username terdaftar tidak mudah ditebak
    if (!$user || !password_verify($password, $user->password)) {
      echo json_encode([
        'status'  => false,
        'message' => 'Username atau password salah.'
      ]);
      return;
    }

    /*
 * Nasabah baru tidak boleh login sebelum diverifikasi.
 * Super Admin dan Administrator lama tetap harus berstatus Ya.
 */
    if ($user->login !== 'Ya') {
      $message = $user->login === 'Ditolak'
        ? 'Pendaftaran akun Anda telah ditolak.'
        : 'Akun Anda belum diverifikasi oleh Administrator.';

      echo json_encode([
        'status'  => false,
        'message' => $message
      ]);

      return;
    }

    if (empty($user->cabang_id)) {
      echo json_encode([
        'status'  => false,
        'message' => 'Akun belum terhubung dengan cabang.'
      ]);
      return;
    }

    if ($user->status_cabang !== 'Aktif') {
      echo json_encode([
        'status'  => false,
        'message' => 'Cabang akun Anda sedang tidak aktif.'
      ]);
      return;
    }

    try {
      // Token asli hanya dikirim kepada aplikasi
      $token = bin2hex(random_bytes(32));

      // Database hanya menyimpan hash token
      $tokenHash = hash('sha256', $token);
      $expiresAt = date('Y-m-d H:i:s', strtotime('+30 days'));

      $dataToken = [
        'id_user'      => (int) $user->id,
        'token_hash'   => $tokenHash,
        'device'       => mb_substr($device, 0, 255),
        'ip_address'   => $this->input->ip_address(),
        'expires_at'   => $expiresAt,
        'last_used_at' => null,
        'revoked_at'   => null,
        'terdaftar'    => date('Y-m-d H:i:s')
      ];

      if (!$this->db->insert('tb_api_token', $dataToken)) {
        echo json_encode([
          'status'  => false,
          'message' => 'Gagal membuat sesi login.'
        ]);
        return;
      }

      echo json_encode([
        'status'       => true,
        'message'      => 'Login berhasil.',
        'token'        => $token,
        'token_type'   => 'Bearer',
        'expires_at'   => $expiresAt,
        'expires_in'   => 2592000,
        'data'         => [
          'id'             => (int) $user->id,
          'nama'           => $user->nama,
          'username'       => $user->username,
          'level'          => $user->level,
          'skin'           => $user->skin,
          'foto'           => $user->foto,
          'jenis_kelamin'  => $user->jenisKelamin,
          'telp'           => $user->telp,
          'email'          => $user->email,
          'alamat'         => $user->alamat,
          'cabang_id'      => (int) $user->cabang_id,
          'kode_cabang'    => $user->kode_cabang,
          'nama_cabang'    => $user->nama_cabang,
          'is_pusat'       => (int) $user->is_pusat
        ]
      ]);
    } catch (Exception $e) {
      log_message('error', 'Gagal membuat token API: ' . $e->getMessage());

      echo json_encode([
        'status'  => false,
        'message' => 'Terjadi kesalahan saat membuat sesi login.'
      ]);
    }
  }


  // ==========================================
  // ENDPOINT LOGOUT API
  // ==========================================
  public function logout()
  {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
      $this->api_response([
        'status'  => false,
        'message' => 'Gunakan metode POST.'
      ], 405);

      return;
    }

    $auth = $this->authenticate_api();

    if (!$auth) {
      return;
    }

    $this->db->where('id', $auth->token_id);
    $updated = $this->db->update('tb_api_token', [
      'revoked_at' => date('Y-m-d H:i:s')
    ]);

    if (!$updated) {
      $this->api_response([
        'status'  => false,
        'message' => 'Logout gagal diproses.'
      ], 500);

      return;
    }

    $this->api_response([
      'status'  => true,
      'message' => 'Logout berhasil.'
    ]);
  }


  // ==========================================
  // 2. ENDPOINT SALDO 
  // ==========================================
  // ==========================================
  // ENDPOINT SALDO TERPROTEKSI BEARER TOKEN
  // ==========================================
  public function saldo()
  {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
      $this->api_response([
        'status'  => false,
        'message' => 'Gunakan metode POST.'
      ], 405);

      return;
    }

    $auth = $this->authenticate_api();

    if (!$auth) {
      return;
    }

    $id_user  = (int) $auth->id_user;
    $level    = $auth->level;
    $cabang_id = (int) $auth->cabang_id;

    $total_masuk          = 0;
    $total_keluar         = 0;
    $total_target         = 0;
    $transfer_masuk       = 0;
    $transfer_keluar      = 0;
    $sisa_saldo           = 0;

    /*
     * SUPER ADMIN
     * Melihat saldo keseluruhan dari seluruh cabang.
     */
    if ($level === 'Super Admin') {
      $this->db->select_sum('nominal', 'total');
      $this->db->where('jenis', 'Masuk');
      $this->db->where('status_konfirmasi', 'Sukses');
      $total_masuk = (int) (
        $this->db->get('tb_transaksi')->row()->total ?? 0
      );

      $this->db->select_sum('nominal', 'total');
      $this->db->where('jenis', 'Keluar');
      $this->db->where('status_konfirmasi', 'Sukses');
      $total_keluar = (int) (
        $this->db->get('tb_transaksi')->row()->total ?? 0
      );

      $this->db->select_sum('terkumpul', 'total');
      $total_target = (int) (
        $this->db->get('tb_target')->row()->total ?? 0
      );

      // Transfer antar pengguna tidak mengubah total dana pusat.
      $sisa_saldo = (
        $total_masuk -
        $total_keluar +
        $total_target
      );
    }

    /*
     * ADMINISTRATOR CABANG
     * Hanya melihat saldo cabangnya sendiri.
     */ elseif ($level === 'Administrator') {
      $this->db->select_sum('nominal', 'total');
      $this->db->where('jenis', 'Masuk');
      $this->db->where('status_konfirmasi', 'Sukses');
      $this->db->where('cabang_id', $cabang_id);
      $total_masuk = (int) (
        $this->db->get('tb_transaksi')->row()->total ?? 0
      );

      $this->db->select_sum('nominal', 'total');
      $this->db->where('jenis', 'Keluar');
      $this->db->where('status_konfirmasi', 'Sukses');
      $this->db->where('cabang_id', $cabang_id);
      $total_keluar = (int) (
        $this->db->get('tb_transaksi')->row()->total ?? 0
      );

      // Dana Celengan Impian milik nasabah cabang tersebut
      $this->db->select_sum('t.terkumpul', 'total');
      $this->db->from('tb_target AS t');
      $this->db->join(
        'tb_user AS u',
        'u.id = t.id_nasabah',
        'inner'
      );
      $this->db->where('u.cabang_id', $cabang_id);
      $total_target = (int) (
        $this->db->get()->row()->total ?? 0
      );

      // Transfer yang masuk dari cabang lain
      $this->db->select_sum('nominal', 'total');
      $this->db->where('cabang_tujuan_id', $cabang_id);
      $this->db->where('status_transfer', 'Sukses');
      $transfer_masuk = (int) (
        $this->db->get('tb_transfer')->row()->total ?? 0
      );

      // Transfer yang keluar menuju cabang lain
      $this->db->select_sum('nominal', 'total');
      $this->db->where('cabang_asal_id', $cabang_id);
      $this->db->where('status_transfer', 'Sukses');
      $transfer_keluar = (int) (
        $this->db->get('tb_transfer')->row()->total ?? 0
      );

      $sisa_saldo = (
        $total_masuk -
        $total_keluar +
        $total_target +
        $transfer_masuk -
        $transfer_keluar
      );
    }

    /*
     * NASABAH
     * Hanya melihat saldo miliknya sendiri.
     */ elseif ($level === 'Nasabah') {
      $this->db->select_sum('nominal', 'total');
      $this->db->where('idNasabah', $id_user);
      $this->db->where('jenis', 'Masuk');
      $this->db->where('status_konfirmasi', 'Sukses');
      $total_masuk = (int) (
        $this->db->get('tb_transaksi')->row()->total ?? 0
      );

      $this->db->select_sum('nominal', 'total');
      $this->db->where('idNasabah', $id_user);
      $this->db->where('jenis', 'Keluar');
      $this->db->where('status_konfirmasi', 'Sukses');
      $total_keluar = (int) (
        $this->db->get('tb_transaksi')->row()->total ?? 0
      );

      $this->db->select_sum('nominal', 'total');
      $this->db->where('idPenerima', $id_user);
      $this->db->where('status_transfer', 'Sukses');
      $transfer_masuk = (int) (
        $this->db->get('tb_transfer')->row()->total ?? 0
      );

      $this->db->select_sum('nominal', 'total');
      $this->db->where('idPengirim', $id_user);
      $this->db->where('status_transfer', 'Sukses');
      $transfer_keluar = (int) (
        $this->db->get('tb_transfer')->row()->total ?? 0
      );

      $sisa_saldo = (
        $total_masuk +
        $transfer_masuk -
        $total_keluar -
        $transfer_keluar
      );
    }

    /*
     * Level selain tiga level resmi ditolak.
     */ else {
      $this->api_response([
        'status'  => false,
        'message' => 'Level pengguna tidak memiliki akses.'
      ], 403);

      return;
    }

    $this->api_response([
      'status'        => true,
      'saldo_raw'     => $sisa_saldo,
      'saldo_format'  => 'Rp ' . number_format(
        $sisa_saldo,
        0,
        ',',
        '.'
      ),
      'cabang'        => [
        'id'   => $cabang_id,
        'kode' => $auth->kode_cabang,
        'nama' => $auth->nama_cabang
      ],
      'rincian'       => [
        'transaksi_masuk'  => $total_masuk,
        'transaksi_keluar' => $total_keluar,
        'transfer_masuk'   => $transfer_masuk,
        'transfer_keluar'  => $transfer_keluar,
        'dana_target'      => $total_target
      ]
    ]);
  }

  // ==========================================
  // ENDPOINT RIWAYAT TRANSAKSI TERPROTEKSI
  // ==========================================
  public function transaksi()
  {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
      $this->api_response([
        'status'  => false,
        'message' => 'Gunakan metode POST.'
      ], 405);

      return;
    }

    $auth = $this->authenticate_api();

    if (!$auth) {
      return;
    }

    $request = json_decode($this->input->raw_input_stream, true);

    if (!is_array($request)) {
      $request = [];
    }

    /*
     * id_user dan level tidak lagi diambil dari request.
     * Seluruh identitas berasal dari Bearer token.
     */
    $id_user   = (int) $auth->id_user;
    $level     = $auth->level;
    $cabang_id = (int) $auth->cabang_id;

    $start = trim((string) ($request['start'] ?? ''));
    $end   = trim((string) ($request['end'] ?? ''));
    $limit_request = $request['limit'] ?? 10;

    if (
      ($start !== '' || $end !== '') &&
      (
        !preg_match('/^\d{4}-\d{2}-\d{2}$/', $start) ||
        !preg_match('/^\d{4}-\d{2}-\d{2}$/', $end)
      )
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Format tanggal harus YYYY-MM-DD.'
      ], 422);

      return;
    }

    if (
      !in_array(
        $level,
        ['Super Admin', 'Administrator', 'Nasabah'],
        true
      )
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Level pengguna tidak memiliki akses.'
      ], 403);

      return;
    }

    if ($limit_request === 'all') {
      $limit = null;
    } else {
      $limit = (int) $limit_request;

      if ($limit < 1) {
        $limit = 10;
      }

      // Batasi respons agar endpoint tidak terlalu berat
      if ($limit > 500) {
        $limit = 500;
      }
    }

    $formatted_data = [];

    // ==========================================
    // 1. TRANSAKSI SETOR DAN TARIK
    // ==========================================
    $this->db->select(
      'tb_transaksi.*,
         tb_user.nama AS nama_nasabah,
         tb_cabang.kode AS kode_cabang,
         tb_cabang.nama AS nama_cabang'
    );
    $this->db->from('tb_transaksi');
    $this->db->join(
      'tb_user',
      'tb_transaksi.idNasabah = tb_user.id',
      'left'
    );
    $this->db->join(
      'tb_cabang',
      'tb_transaksi.cabang_id = tb_cabang.id',
      'left'
    );

    if ($level === 'Administrator') {
      $this->db->where(
        'tb_transaksi.cabang_id',
        $cabang_id
      );
    } elseif ($level === 'Nasabah') {
      $this->db->where(
        'tb_transaksi.idNasabah',
        $id_user
      );
    }

    if ($start !== '' && $end !== '') {
      $this->db->where(
        'tb_transaksi.tanggal >=',
        $start
      );
      $this->db->where(
        'tb_transaksi.tanggal <=',
        $end
      );
    }

    $transaksi_query = $this->db->get();

    if ($transaksi_query->num_rows() > 0) {
      foreach ($transaksi_query->result_array() as $row) {
        $jenis = $row['jenis'] ?? '';
        $is_masuk = $jenis === 'Masuk';

        $color  = $is_masuk ? '#10b981' : '#ef4444';
        $prefix = $is_masuk ? '+ Rp ' : '- Rp ';

        $nama_nasabah = $row['nama_nasabah']
          ?? 'Tidak diketahui';

        $title = !empty($row['keterangan'])
          ? $row['keterangan']
          : 'Transaksi';

        if (
          in_array(
            $level,
            ['Super Admin', 'Administrator'],
            true
          )
        ) {
          $title .= ' (' . $nama_nasabah . ')';
        }

        $tanggal = $row['tanggal'] ?? date('Y-m-d');

        $waktu_lengkap = !empty($row['terdaftar'])
          ? $row['terdaftar']
          : $tanggal . ' 00:00:00';

        $formatted_data[] = [
          'id'             => 'trx_' . $row['id'],
          'type'           => $jenis,
          'direction'      => strtolower($jenis),
          'source'         => 'transaksi',
          'nama_nasabah'   => $nama_nasabah,
          'title'          => $title,
          'keterangan'     => $row['keterangan'] ?? '',
          'date'           => date(
            'd M Y',
            strtotime($tanggal)
          ),
          'waktu_struk'    => date(
            'd-m-Y H:i:s',
            strtotime($waktu_lengkap)
          ),
          'timestamp'      => strtotime($waktu_lengkap),
          'amount'         => $prefix . number_format(
            (float) ($row['nominal'] ?? 0),
            0,
            ',',
            '.'
          ),
          'nominal_raw'    => (int) ($row['nominal'] ?? 0),
          'color'          => $color,
          'status'         => $row['status_konfirmasi']
            ?? 'Pending',
          'bukti'          => $row['bukti_transfer'] ?? null,
          'kode_cabang'    => $row['kode_cabang'] ?? null,
          'nama_cabang'    => $row['nama_cabang'] ?? null,
          'gold_gram'      => (
            isset($row['gram_emas']) &&
            (float) $row['gram_emas'] != 0
          )
            ? abs((float) $row['gram_emas'])
            : null
        ];
      }
    }

    // ==========================================
    // 2. RIWAYAT TRANSFER
    // ==========================================
    if ($this->db->table_exists('tb_transfer')) {
      $this->db->select(
        'tb_transfer.*,
             pengirim.nama AS nama_pengirim,
             penerima.nama AS nama_penerima,
             cabang_asal.kode AS kode_cabang_asal,
             cabang_asal.nama AS nama_cabang_asal,
             cabang_tujuan.kode AS kode_cabang_tujuan,
             cabang_tujuan.nama AS nama_cabang_tujuan'
      );
      $this->db->from('tb_transfer');

      $this->db->join(
        'tb_user AS pengirim',
        'tb_transfer.idPengirim = pengirim.id',
        'left'
      );
      $this->db->join(
        'tb_user AS penerima',
        'tb_transfer.idPenerima = penerima.id',
        'left'
      );
      $this->db->join(
        'tb_cabang AS cabang_asal',
        'tb_transfer.cabang_asal_id = cabang_asal.id',
        'left'
      );
      $this->db->join(
        'tb_cabang AS cabang_tujuan',
        'tb_transfer.cabang_tujuan_id = cabang_tujuan.id',
        'left'
      );

      if ($level === 'Administrator') {
        $this->db->group_start();
        $this->db->where(
          'tb_transfer.cabang_asal_id',
          $cabang_id
        );
        $this->db->or_where(
          'tb_transfer.cabang_tujuan_id',
          $cabang_id
        );
        $this->db->group_end();
      } elseif ($level === 'Nasabah') {
        $this->db->group_start();
        $this->db->where(
          'tb_transfer.idPengirim',
          $id_user
        );
        $this->db->or_where(
          'tb_transfer.idPenerima',
          $id_user
        );
        $this->db->group_end();
      }

      if ($start !== '' && $end !== '') {
        $this->db->where(
          'tb_transfer.terdaftar >=',
          $start . ' 00:00:00'
        );
        $this->db->where(
          'tb_transfer.terdaftar <=',
          $end . ' 23:59:59'
        );
      }

      $transfer_query = $this->db->get();

      if ($transfer_query->num_rows() > 0) {
        foreach ($transfer_query->result_array() as $row) {
          $is_sender = (
            $level === 'Nasabah' &&
            (int) $row['idPengirim'] === $id_user
          );

          if ($level === 'Nasabah') {
            $jenis = $is_sender ? 'Keluar' : 'Masuk';
            $prefix = $is_sender ? '- Rp ' : '+ Rp ';
            $color = $is_sender ? '#ef4444' : '#10b981';

            if ($is_sender) {
              $title_suffix = ' ke ' .
                ($row['nama_penerima'] ?? 'Nasabah');
            } else {
              $title_suffix = ' dari ' .
                ($row['nama_pengirim'] ?? 'Nasabah');
            }

            $title = (
              !empty($row['keterangan'])
              ? $row['keterangan']
              : 'Transfer'
            ) . $title_suffix;
          } else {
            $jenis  = 'Transfer';
            $prefix = 'Rp ';
            $color  = '#3b82f6';

            $title = (
              !empty($row['keterangan'])
              ? $row['keterangan']
              : 'Transfer'
            );

            $title .= ' (' .
              ($row['nama_pengirim'] ?? 'Tidak diketahui') .
              ' → ' .
              ($row['nama_penerima'] ?? 'Tidak diketahui') .
              ')';
          }

          $waktu_lengkap = !empty($row['terdaftar'])
            ? $row['terdaftar']
            : date('Y-m-d H:i:s');

          $formatted_data[] = [
            'id'                    => 'tf_' . $row['id'],
            'kode_transfer'         => $row['kode_transfer']
              ?? null,
            'type'                  => $jenis,
            'direction'             => strtolower($jenis),
            'source'                => 'transfer',
            'nama_pengirim'         => $row['nama_pengirim']
              ?? 'Tidak diketahui',
            'nama_penerima'         => $row['nama_penerima']
              ?? 'Tidak diketahui',
            'title'                 => $title,
            'keterangan'            => $row['keterangan'] ?? '',
            'date'                  => date(
              'd M Y',
              strtotime($waktu_lengkap)
            ),
            'waktu_struk'           => date(
              'd-m-Y H:i:s',
              strtotime($waktu_lengkap)
            ),
            'timestamp'             => strtotime($waktu_lengkap),
            'amount'                => $prefix . number_format(
              (float) ($row['nominal'] ?? 0),
              0,
              ',',
              '.'
            ),
            'nominal_raw'           => (int) ($row['nominal'] ?? 0),
            'color'                 => $color,
            'status'                => $row['status_transfer']
              ?? 'Sukses',
            'bukti'                 => null,
            'kode_cabang_asal'      => $row['kode_cabang_asal']
              ?? null,
            'nama_cabang_asal'      => $row['nama_cabang_asal']
              ?? null,
            'kode_cabang_tujuan'    => $row['kode_cabang_tujuan']
              ?? null,
            'nama_cabang_tujuan'    => $row['nama_cabang_tujuan']
              ?? null
          ];
        }
      }
    }

    // Urutkan berdasarkan waktu terbaru
    usort($formatted_data, function ($a, $b) {
      return $b['timestamp'] <=> $a['timestamp'];
    });

    if ($limit !== null) {
      $formatted_data = array_slice(
        $formatted_data,
        0,
        $limit
      );
    }

    $this->api_response([
      'status' => true,
      'cabang' => [
        'id'   => $cabang_id,
        'kode' => $auth->kode_cabang,
        'nama' => $auth->nama_cabang
      ],
      'data' => $formatted_data
    ]);
  }

  // ==========================================
  // ENDPOINT DAFTAR NASABAH TERPROTEKSI
  // ==========================================
  public function get_nasabah()
  {
    if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
      $this->api_response([
        'status'  => false,
        'message' => 'Gunakan metode GET.'
      ], 405);

      return;
    }

    $auth = $this->authenticate_api();

    if (!$auth) {
      return;
    }

    $id_user   = (int) $auth->id_user;
    $level     = $auth->level;
    $cabang_id = (int) $auth->cabang_id;

    if (
      !in_array(
        $level,
        ['Super Admin', 'Administrator', 'Nasabah'],
        true
      )
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Level pengguna tidak memiliki akses.'
      ], 403);

      return;
    }

    $this->db->select(
      'u.id,
         u.nama,
         u.cabang_id,
         c.kode AS kode_cabang,
         c.nama AS nama_cabang'
    );
    $this->db->from('tb_user AS u');
    $this->db->join(
      'tb_cabang AS c',
      'c.id = u.cabang_id',
      'inner'
    );
    $this->db->where('u.level', 'Nasabah');
    $this->db->where('c.status', 'Aktif');

    /*
     * Administrator hanya melihat nasabah
     * yang terdaftar pada cabangnya.
     */
    if ($level === 'Administrator') {
      $this->db->where('u.cabang_id', $cabang_id);
    }

    /*
     * Nasabah dapat mencari penerima transfer
     * dari seluruh cabang aktif, kecuali dirinya sendiri.
     */
    if ($level === 'Nasabah') {
      $this->db->where('u.id !=', $id_user);
    }

    $this->db->order_by('c.nama', 'ASC');
    $this->db->order_by('u.nama', 'ASC');

    $nasabah = $this->db->get()->result_array();

    if ($level === 'Super Admin') {
      $scope = 'semua_cabang';
    } elseif ($level === 'Administrator') {
      $scope = 'cabang_sendiri';
    } else {
      $scope = 'penerima_transfer';
    }

    $this->api_response([
      'status' => true,
      'scope'  => $scope,
      'cabang' => [
        'id'   => $cabang_id,
        'kode' => $auth->kode_cabang,
        'nama' => $auth->nama_cabang
      ],
      'data' => $nasabah
    ]);
  }
  // ==========================================
  // ENDPOINT SIMPAN TRANSAKSI TERPROTEKSI
  // ==========================================
  public function simpan_transaksi()
  {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
      $this->api_response([
        'status'  => false,
        'message' => 'Gunakan metode POST.'
      ], 405);

      return;
    }

    $auth = $this->authenticate_api();

    if (!$auth) {
      return;
    }

    $request = json_decode($this->input->raw_input_stream, true);

    if (!is_array($request)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Format permintaan tidak valid.'
      ], 400);

      return;
    }

    $level = $auth->level;

    if (
      !in_array(
        $level,
        ['Super Admin', 'Administrator', 'Nasabah'],
        true
      )
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Level pengguna tidak memiliki akses.'
      ], 403);

      return;
    }

    /*
     * Nasabah hanya boleh membuat transaksi untuk dirinya.
     * Admin memilih nasabah melalui id_nasabah.
     */
    if ($level === 'Nasabah') {
      $id_nasabah = (int) $auth->id_user;
    } else {
      $id_nasabah = (int) ($request['id_nasabah'] ?? 0);
    }

    if ($id_nasabah <= 0) {
      $this->api_response([
        'status'  => false,
        'message' => 'Nasabah belum dipilih.'
      ], 422);

      return;
    }

    // Validasi nasabah dan cabangnya
    $this->db->select(
      'u.id,
         u.nama,
         u.cabang_id,
         c.kode AS kode_cabang,
         c.nama AS nama_cabang,
         c.status AS status_cabang'
    );
    $this->db->from('tb_user AS u');
    $this->db->join(
      'tb_cabang AS c',
      'c.id = u.cabang_id',
      'inner'
    );
    $this->db->where('u.id', $id_nasabah);
    $this->db->where('u.level', 'Nasabah');
    $nasabah = $this->db->get()->row();

    if (!$nasabah) {
      $this->api_response([
        'status'  => false,
        'message' => 'Data nasabah tidak ditemukan.'
      ], 404);

      return;
    }

    if ($nasabah->status_cabang !== 'Aktif') {
      $this->api_response([
        'status'  => false,
        'message' => 'Cabang nasabah sedang tidak aktif.'
      ], 403);

      return;
    }

    /*
     * Administrator hanya dapat memproses nasabah
     * dari cabangnya sendiri.
     */
    if (
      $level === 'Administrator' &&
      (int) $nasabah->cabang_id !== (int) $auth->cabang_id
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Nasabah tidak terdaftar pada cabang Anda.'
      ], 403);

      return;
    }

    $jenis = trim((string) ($request['jenis'] ?? ''));

    if (!in_array($jenis, ['Masuk', 'Keluar'], true)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Jenis transaksi harus Masuk atau Keluar.'
      ], 422);

      return;
    }

    // Nominal Rupiah disimpan sebagai bilangan bulat
    $nominal_input = trim((string) ($request['nominal'] ?? ''));

    if (
      $nominal_input === '' ||
      strpos($nominal_input, '-') !== false
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Nominal transaksi tidak valid.'
      ], 422);

      return;
    }

    $nominal = (int) preg_replace(
      '/[^0-9]/',
      '',
      $nominal_input
    );

    if ($nominal <= 0 || $nominal > 2147483647) {
      $this->api_response([
        'status'  => false,
        'message' => 'Nominal transaksi berada di luar batas.'
      ], 422);

      return;
    }

    $keterangan = trim(
      (string) ($request['keterangan'] ?? '')
    );

    if (mb_strlen($keterangan) > 1000) {
      $this->api_response([
        'status'  => false,
        'message' => 'Keterangan maksimal 1.000 karakter.'
      ], 422);

      return;
    }

    /*
     * Validasi bukti transaksi.
     * File belum ditulis sebelum seluruh data dinyatakan valid.
     */
    $image_binary = null;
    $image_extension = null;
    $bukti_base64 = $request['bukti_base64'] ?? '';

    if (!empty($bukti_base64)) {
      if (
        !preg_match(
          '/^data:image\/(jpeg|jpg|png|webp);base64,(.+)$/is',
          $bukti_base64,
          $image_matches
        )
      ) {
        $this->api_response([
          'status'  => false,
          'message' => 'Format bukti transaksi tidak didukung.'
        ], 422);

        return;
      }

      $image_binary = base64_decode(
        $image_matches[2],
        true
      );

      if ($image_binary === false) {
        $this->api_response([
          'status'  => false,
          'message' => 'Bukti transaksi tidak dapat dibaca.'
        ], 422);

        return;
      }

      // Maksimal 5 MB
      if (strlen($image_binary) > 5 * 1024 * 1024) {
        $this->api_response([
          'status'  => false,
          'message' => 'Ukuran bukti transaksi maksimal 5 MB.'
        ], 422);

        return;
      }

      $image_info = @getimagesizefromstring($image_binary);
      $mime = $image_info['mime'] ?? '';

      $allowed_mimes = [
        'image/jpeg' => 'jpg',
        'image/png'  => 'png',
        'image/webp' => 'webp'
      ];

      if (!isset($allowed_mimes[$mime])) {
        $this->api_response([
          'status'  => false,
          'message' => 'Isi file bukti bukan gambar yang valid.'
        ], 422);

        return;
      }

      $image_extension = $allowed_mimes[$mime];
    }

    /*
     * Server menentukan admin dan status.
     * Nilai id_admin dari request tidak digunakan.
     */
    if ($level === 'Nasabah') {
      $id_admin = 0;
      $status_konfirmasi = 'Pending';
    } else {
      $id_admin = (int) $auth->id_user;
      $status_konfirmasi = 'Sukses';
    }

    $file_name = null;
    $saved_file_path = null;

    $this->db->trans_begin();

    /*
     * Kunci baris nasabah selama pengecekan saldo.
     * Ini mengurangi risiko dua penarikan diproses bersamaan.
     */
    $this->db->query(
      'SELECT id FROM tb_user WHERE id = ? FOR UPDATE',
      [$id_nasabah]
    );

    if ($jenis === 'Keluar') {
      $this->db->select_sum('nominal', 'total');
      $this->db->where('idNasabah', $id_nasabah);
      $this->db->where('jenis', 'Masuk');
      $this->db->where('status_konfirmasi', 'Sukses');
      $transaksi_masuk = (int) (
        $this->db->get('tb_transaksi')->row()->total ?? 0
      );

      $this->db->select_sum('nominal', 'total');
      $this->db->where('idNasabah', $id_nasabah);
      $this->db->where('jenis', 'Keluar');
      $this->db->where('status_konfirmasi', 'Sukses');
      $transaksi_keluar = (int) (
        $this->db->get('tb_transaksi')->row()->total ?? 0
      );

      $this->db->select_sum('nominal', 'total');
      $this->db->where('idPenerima', $id_nasabah);
      $this->db->where('status_transfer', 'Sukses');
      $transfer_masuk = (int) (
        $this->db->get('tb_transfer')->row()->total ?? 0
      );

      $this->db->select_sum('nominal', 'total');
      $this->db->where('idPengirim', $id_nasabah);
      $this->db->where('status_transfer', 'Sukses');
      $transfer_keluar = (int) (
        $this->db->get('tb_transfer')->row()->total ?? 0
      );

      $saldo_aktif = (
        $transaksi_masuk +
        $transfer_masuk -
        $transaksi_keluar -
        $transfer_keluar
      );

      if ($nominal > $saldo_aktif) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Penarikan gagal. Saldo tidak mencukupi.',
          'saldo_raw' => $saldo_aktif,
          'saldo_format' => 'Rp ' . number_format(
            $saldo_aktif,
            0,
            ',',
            '.'
          )
        ], 422);

        return;
      }
    }

    // Simpan bukti setelah validasi dan pengecekan saldo
    if ($image_binary !== null) {
      $upload_dir = FCPATH . 'assets/bukti_transfer/';

      if (
        !is_dir($upload_dir) &&
        !mkdir($upload_dir, 0755, true)
      ) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Folder bukti transaksi tidak dapat dibuat.'
        ], 500);

        return;
      }

      try {
        $random_name = bin2hex(random_bytes(8));
      } catch (Exception $e) {
        $random_name = uniqid('', true);
      }

      $file_name = 'bukti_' .
        date('YmdHis') . '_' .
        $random_name . '.' .
        $image_extension;

      $saved_file_path = $upload_dir . $file_name;

      if (
        file_put_contents(
          $saved_file_path,
          $image_binary,
          LOCK_EX
        ) === false
      ) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Bukti transaksi gagal disimpan.'
        ], 500);

        return;
      }
    }

    $data = [
      'idAdmin'            => $id_admin,
      'idNasabah'          => $id_nasabah,
      'idPotongan'         => 0,
      'cabang_id'          => (int) $nasabah->cabang_id,
      'tanggal'            => date('Y-m-d'),
      'nominal'            => $nominal,
      'jenis'              => $jenis,
      'keterangan'         => $keterangan,
      'status_konfirmasi'  => $status_konfirmasi,
      'bukti_transfer'     => $file_name,
      'terdaftar'          => date('Y-m-d H:i:s')
    ];

    $insert = $this->db->insert('tb_transaksi', $data);
    $id_transaksi = (int) $this->db->insert_id();

    if (!$insert || $this->db->trans_status() === false) {
      $this->db->trans_rollback();

      if (
        $saved_file_path !== null &&
        is_file($saved_file_path)
      ) {
        unlink($saved_file_path);
      }

      log_message(
        'error',
        'Gagal menyimpan transaksi API: ' .
          json_encode($this->db->error())
      );

      $this->api_response([
        'status'  => false,
        'message' => 'Transaksi gagal disimpan.'
      ], 500);

      return;
    }

    $this->db->trans_commit();

    /*
     * Notifikasi dilakukan setelah transaksi database selesai,
     * sehingga koneksi WhatsApp/push tidak menahan transaksi.
     */
    if ($status_konfirmasi === 'Pending') {
      $jenis_teks = $jenis === 'Masuk'
        ? 'menabung'
        : 'penarikan';

      $jenis_wa = $jenis === 'Masuk'
        ? 'Menabung'
        : 'Penarikan';

      $pesan_wa = "🔔 *PENGAJUAN TRANSAKSI BARU*\n\n";
      $pesan_wa .= "👤 *Nama:* {$nasabah->nama}\n";
      $pesan_wa .= "🏢 *Cabang:* {$nasabah->nama_cabang}\n";
      $pesan_wa .= "📝 *Jenis:* {$jenis_wa} Dana\n";
      $pesan_wa .= "💰 *Nominal:* Rp " .
        number_format($nominal, 0, ',', '.') . "\n";
      $pesan_wa .= "📌 *Keterangan:* " .
        ($keterangan !== '' ? $keterangan : '-') . "\n\n";
      $pesan_wa .= "Mohon segera periksa aplikasi.";

      /*
         * Administrator cabang terkait dan seluruh Super Admin.
         */
      $this->db->select(
        'id, nama, telp, expo_token, level, cabang_id'
      );
      $this->db->from('tb_user');
      $this->db->group_start();

      $this->db->group_start();
      $this->db->where('level', 'Administrator');
      $this->db->where(
        'cabang_id',
        (int) $nasabah->cabang_id
      );
      $this->db->group_end();

      $this->db->or_where('level', 'Super Admin');
      $this->db->group_end();

      $admins = $this->db->get()->result();

      foreach ($admins as $admin) {
        $judul_notifikasi = '🔔 Pengajuan Transaksi Baru';
        $isi_notifikasi =
          "Nasabah {$nasabah->nama} mengajukan " .
          "{$jenis_teks} sebesar Rp " .
          number_format($nominal, 0, ',', '.') .
          " di {$nasabah->nama_cabang}.";

        $this->db->insert('tb_notifikasi', [
          'id_user' => $admin->id,
          'judul'   => $judul_notifikasi,
          'pesan'   => $isi_notifikasi,
          'tanggal' => date('Y-m-d H:i:s')
        ]);

        if (!empty($admin->expo_token)) {
          $this->send_expo_push_notification(
            $admin->expo_token,
            $judul_notifikasi,
            $isi_notifikasi
          );
        }

        if (!empty($admin->telp)) {
          $this->send_whatsapp(
            $admin->telp,
            $pesan_wa
          );
        }
      }

      $pesan_balasan =
        'Pengajuan berhasil dikirim dan menunggu konfirmasi.';
    } else {
      $pesan_balasan = 'Transaksi berhasil disimpan.';
    }

    $this->api_response([
      'status'  => true,
      'message' => $pesan_balasan,
      'data'    => [
        'id_transaksi'       => $id_transaksi,
        'id_nasabah'         => $id_nasabah,
        'nama_nasabah'       => $nasabah->nama,
        'jenis'              => $jenis,
        'nominal'            => $nominal,
        'status_konfirmasi'  => $status_konfirmasi,
        'cabang_id'          => (int) $nasabah->cabang_id,
        'kode_cabang'        => $nasabah->kode_cabang,
        'nama_cabang'        => $nasabah->nama_cabang,
        'bukti_transfer'     => $file_name
      ]
    ]);
  }

  // ==========================================
  // ENDPOINT SIMPAN TRANSFER TERPROTEKSI
  // ==========================================
  public function simpan_transfer()
  {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
      $this->api_response([
        'status'  => false,
        'message' => 'Gunakan metode POST.'
      ], 405);

      return;
    }

    $auth = $this->authenticate_api();

    if (!$auth) {
      return;
    }

    $request = json_decode($this->input->raw_input_stream, true);

    if (!is_array($request)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Format permintaan tidak valid.'
      ], 400);

      return;
    }

    $level = $auth->level;

    if (
      !in_array(
        $level,
        ['Super Admin', 'Administrator', 'Nasabah'],
        true
      )
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Level pengguna tidak memiliki akses.'
      ], 403);

      return;
    }

    /*
     * Nasabah hanya boleh mengirim dari rekeningnya sendiri.
     * Administrator dan Super Admin dapat memilih pengirim.
     */
    if ($level === 'Nasabah') {
      $id_pengirim = (int) $auth->id_user;
    } else {
      $id_pengirim = (int) ($request['id_pengirim'] ?? 0);
    }

    $id_penerima = (int) ($request['id_penerima'] ?? 0);

    if ($id_pengirim <= 0 || $id_penerima <= 0) {
      $this->api_response([
        'status'  => false,
        'message' => 'Pengirim dan penerima harus dipilih.'
      ], 422);

      return;
    }

    if ($id_pengirim === $id_penerima) {
      $this->api_response([
        'status'  => false,
        'message' => 'Pengirim dan penerima tidak boleh sama.'
      ], 422);

      return;
    }

    $nominal_input = trim((string) ($request['nominal'] ?? ''));

    if (
      $nominal_input === '' ||
      strpos($nominal_input, '-') !== false
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Nominal transfer tidak valid.'
      ], 422);

      return;
    }

    $nominal = (int) preg_replace(
      '/[^0-9]/',
      '',
      $nominal_input
    );

    if ($nominal <= 0 || $nominal > 2147483647) {
      $this->api_response([
        'status'  => false,
        'message' => 'Nominal transfer berada di luar batas.'
      ], 422);

      return;
    }

    $keterangan = trim(
      (string) ($request['keterangan'] ?? '')
    );

    if (mb_strlen($keterangan) > 1000) {
      $this->api_response([
        'status'  => false,
        'message' => 'Keterangan maksimal 1.000 karakter.'
      ], 422);

      return;
    }

    $this->db->trans_begin();

    /*
     * Kunci kedua akun dengan urutan ID yang konsisten.
     * Ini mengurangi risiko saldo ganda dan deadlock.
     */
    $lock_ids = [$id_pengirim, $id_penerima];
    sort($lock_ids, SORT_NUMERIC);

    $users = $this->db->query(
      'SELECT
            u.id,
            u.nama,
            u.level,
            u.cabang_id,
            c.kode AS kode_cabang,
            c.nama AS nama_cabang,
            c.status AS status_cabang
         FROM tb_user AS u
         INNER JOIN tb_cabang AS c
            ON c.id = u.cabang_id
         WHERE u.id IN (?, ?)
         ORDER BY u.id ASC
         FOR UPDATE',
      [$lock_ids[0], $lock_ids[1]]
    )->result();

    $pengirim = null;
    $penerima = null;

    foreach ($users as $user) {
      if ((int) $user->id === $id_pengirim) {
        $pengirim = $user;
      }

      if ((int) $user->id === $id_penerima) {
        $penerima = $user;
      }
    }

    if (!$pengirim || $pengirim->level !== 'Nasabah') {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Data pengirim tidak ditemukan.'
      ], 404);

      return;
    }

    if (!$penerima || $penerima->level !== 'Nasabah') {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Data penerima tidak ditemukan.'
      ], 404);

      return;
    }

    if (
      $pengirim->status_cabang !== 'Aktif' ||
      $penerima->status_cabang !== 'Aktif'
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Cabang pengirim atau penerima sedang tidak aktif.'
      ], 403);

      return;
    }

    /*
     * Administrator hanya boleh menggunakan rekening pengirim
     * dari cabangnya sendiri. Penerima boleh berbeda cabang.
     */
    if (
      $level === 'Administrator' &&
      (int) $pengirim->cabang_id !== (int) $auth->cabang_id
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Pengirim tidak terdaftar pada cabang Anda.'
      ], 403);

      return;
    }

    // ==========================================
    // HITUNG SALDO PENGIRIM
    // ==========================================
    $this->db->select_sum('nominal', 'total');
    $this->db->where('idNasabah', $id_pengirim);
    $this->db->where('jenis', 'Masuk');
    $this->db->where('status_konfirmasi', 'Sukses');
    $transaksi_masuk = (int) (
      $this->db->get('tb_transaksi')->row()->total ?? 0
    );

    $this->db->select_sum('nominal', 'total');
    $this->db->where('idNasabah', $id_pengirim);
    $this->db->where('jenis', 'Keluar');
    $this->db->where('status_konfirmasi', 'Sukses');
    $transaksi_keluar = (int) (
      $this->db->get('tb_transaksi')->row()->total ?? 0
    );

    $this->db->select_sum('nominal', 'total');
    $this->db->where('idPenerima', $id_pengirim);
    $this->db->where('status_transfer', 'Sukses');
    $transfer_masuk = (int) (
      $this->db->get('tb_transfer')->row()->total ?? 0
    );

    $this->db->select_sum('nominal', 'total');
    $this->db->where('idPengirim', $id_pengirim);
    $this->db->where('status_transfer', 'Sukses');
    $transfer_keluar = (int) (
      $this->db->get('tb_transfer')->row()->total ?? 0
    );

    $saldo_pengirim = (
      $transaksi_masuk +
      $transfer_masuk -
      $transaksi_keluar -
      $transfer_keluar
    );

    if ($nominal > $saldo_pengirim) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'       => false,
        'message'      => 'Transfer gagal. Saldo pengirim tidak mencukupi.',
        'saldo_raw'    => $saldo_pengirim,
        'saldo_format' => 'Rp ' . number_format(
          $saldo_pengirim,
          0,
          ',',
          '.'
        )
      ], 422);

      return;
    }

    // ==========================================
    // BUAT KODE TRANSFER UNIK
    // ==========================================
    $kode_transfer = null;

    for ($attempt = 1; $attempt <= 5; $attempt++) {
      try {
        $random_code = strtoupper(
          bin2hex(random_bytes(3))
        );
      } catch (Exception $e) {
        $random_code = strtoupper(
          substr(md5(uniqid('', true)), 0, 6)
        );
      }

      $candidate = 'TRF-' .
        date('YmdHis') . '-' .
        $random_code;

      $exists = $this->db
        ->where('kode_transfer', $candidate)
        ->count_all_results('tb_transfer');

      if ($exists === 0) {
        $kode_transfer = $candidate;
        break;
      }
    }

    if ($kode_transfer === null) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Kode transfer gagal dibuat.'
      ], 500);

      return;
    }

    $data_transfer = [
      'idPengirim'       => $id_pengirim,
      'idPenerima'       => $id_penerima,
      'dibuat_oleh'      => (int) $auth->id_user,
      'cabang_asal_id'   => (int) $pengirim->cabang_id,
      'cabang_tujuan_id' => (int) $penerima->cabang_id,
      'kode_transfer'    => $kode_transfer,
      'status_transfer'  => 'Sukses',
      'nominal'          => $nominal,
      'keterangan'       => $keterangan,
      'terdaftar'        => date('Y-m-d H:i:s')
    ];

    $insert = $this->db->insert(
      'tb_transfer',
      $data_transfer
    );

    $id_transfer = (int) $this->db->insert_id();

    if (!$insert || $this->db->trans_status() === false) {
      $database_error = $this->db->error();
      $this->db->trans_rollback();

      log_message(
        'error',
        'Gagal menyimpan transfer API: ' .
          json_encode($database_error)
      );

      $this->api_response([
        'status'  => false,
        'message' => 'Transfer gagal disimpan.'
      ], 500);

      return;
    }

    $this->db->trans_commit();

    $this->api_response([
      'status'  => true,
      'message' => 'Transfer berhasil dikirim.',
      'data'    => [
        'id_transfer'        => $id_transfer,
        'kode_transfer'      => $kode_transfer,
        'nominal'            => $nominal,
        'status_transfer'    => 'Sukses',
        'dibuat_oleh'        => (int) $auth->id_user,
        'nama_operator'      => $auth->nama,
        'id_pengirim'        => $id_pengirim,
        'nama_pengirim'      => $pengirim->nama,
        'cabang_asal_id'     => (int) $pengirim->cabang_id,
        'kode_cabang_asal'   => $pengirim->kode_cabang,
        'nama_cabang_asal'   => $pengirim->nama_cabang,
        'id_penerima'        => $id_penerima,
        'nama_penerima'      => $penerima->nama,
        'cabang_tujuan_id'   => (int) $penerima->cabang_id,
        'kode_cabang_tujuan' => $penerima->kode_cabang,
        'nama_cabang_tujuan' => $penerima->nama_cabang,
        'saldo_sebelum'      => $saldo_pengirim,
        'saldo_sesudah'      => $saldo_pengirim - $nominal
      ]
    ]);
  }

  // ==========================================
  // ENDPOINT KONFIRMASI TRANSAKSI TERPROTEKSI
  // ==========================================
  public function konfirmasi_transaksi()
  {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
      $this->api_response([
        'status'  => false,
        'message' => 'Gunakan metode POST.'
      ], 405);

      return;
    }

    $auth = $this->authenticate_api();

    if (!$auth) {
      return;
    }

    if (
      !in_array(
        $auth->level,
        ['Super Admin', 'Administrator'],
        true
      )
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Hanya pengelola yang dapat mengonfirmasi transaksi.'
      ], 403);

      return;
    }

    $request = json_decode($this->input->raw_input_stream, true);

    if (!is_array($request)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Format permintaan tidak valid.'
      ], 400);

      return;
    }

    $raw_id_transaksi = trim(
      (string) ($request['id_transaksi'] ?? '')
    );

    $status_baru = trim(
      (string) ($request['status'] ?? '')
    );

    // Menerima format 123 maupun trx_123
    $id_string = preg_replace(
      '/^trx_/i',
      '',
      $raw_id_transaksi
    );

    if ($id_string === '' || !ctype_digit($id_string)) {
      $this->api_response([
        'status'  => false,
        'message' => 'ID transaksi tidak valid.'
      ], 422);

      return;
    }

    $id_transaksi = (int) $id_string;

    if (!in_array($status_baru, ['Sukses', 'Ditolak'], true)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Status hanya boleh Sukses atau Ditolak.'
      ], 422);

      return;
    }

    /*
     * Ambil ID nasabah untuk menentukan urutan penguncian.
     */
    $transaksi_awal = $this->db
      ->select('idNasabah')
      ->where('id', $id_transaksi)
      ->get('tb_transaksi')
      ->row();

    if (!$transaksi_awal) {
      $this->api_response([
        'status'  => false,
        'message' => 'Transaksi tidak ditemukan.'
      ], 404);

      return;
    }

    $id_nasabah = (int) $transaksi_awal->idNasabah;

    $this->db->trans_begin();

    /*
     * Semua proses finansial mengunci pengguna terlebih dahulu.
     */
    $this->db->query(
      'SELECT id
         FROM tb_user
         WHERE id = ?
         FOR UPDATE',
      [$id_nasabah]
    );

    /*
     * Ambil ulang transaksi di dalam transaction lock.
     */
    $transaksi = $this->db->query(
      'SELECT
            t.id,
            t.idAdmin,
            t.idNasabah,
            t.cabang_id,
            t.nominal,
            t.jenis,
            t.keterangan,
            t.status_konfirmasi,
            t.bukti_transfer,
            u.nama AS nama_nasabah,
            u.expo_token,
            c.kode AS kode_cabang,
            c.nama AS nama_cabang
         FROM tb_transaksi AS t
         INNER JOIN tb_user AS u
            ON u.id = t.idNasabah
         INNER JOIN tb_cabang AS c
            ON c.id = t.cabang_id
         WHERE t.id = ?
         FOR UPDATE',
      [$id_transaksi]
    )->row();

    if (!$transaksi) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Transaksi tidak ditemukan.'
      ], 404);

      return;
    }

    /*
     * Administrator hanya boleh memproses transaksi cabangnya.
     */
    if (
      $auth->level === 'Administrator' &&
      (int) $transaksi->cabang_id !== (int) $auth->cabang_id
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Transaksi berasal dari cabang lain.'
      ], 403);

      return;
    }

    /*
     * Transaksi yang sudah final tidak boleh diproses ulang.
     */
    if ($transaksi->status_konfirmasi !== 'Pending') {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Transaksi sudah pernah diproses.',
        'status_sekarang' => $transaksi->status_konfirmasi
      ], 409);

      return;
    }

    /*
     * Periksa kembali saldo ketika penarikan disetujui.
     * Ini penting karena saldo bisa berubah sejak pengajuan dibuat.
     */
    $saldo_aktif = null;

    if (
      $status_baru === 'Sukses' &&
      $transaksi->jenis === 'Keluar'
    ) {
      $this->db->select_sum('nominal', 'total');
      $this->db->where('idNasabah', $id_nasabah);
      $this->db->where('jenis', 'Masuk');
      $this->db->where('status_konfirmasi', 'Sukses');
      $transaksi_masuk = (int) (
        $this->db->get('tb_transaksi')->row()->total ?? 0
      );

      $this->db->select_sum('nominal', 'total');
      $this->db->where('idNasabah', $id_nasabah);
      $this->db->where('jenis', 'Keluar');
      $this->db->where('status_konfirmasi', 'Sukses');
      $transaksi_keluar = (int) (
        $this->db->get('tb_transaksi')->row()->total ?? 0
      );

      $this->db->select_sum('nominal', 'total');
      $this->db->where('idPenerima', $id_nasabah);
      $this->db->where('status_transfer', 'Sukses');
      $transfer_masuk = (int) (
        $this->db->get('tb_transfer')->row()->total ?? 0
      );

      $this->db->select_sum('nominal', 'total');
      $this->db->where('idPengirim', $id_nasabah);
      $this->db->where('status_transfer', 'Sukses');
      $transfer_keluar = (int) (
        $this->db->get('tb_transfer')->row()->total ?? 0
      );

      $saldo_aktif = (
        $transaksi_masuk +
        $transfer_masuk -
        $transaksi_keluar -
        $transfer_keluar
      );

      if ((int) $transaksi->nominal > $saldo_aktif) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'       => false,
          'message'      => 'Transaksi tidak dapat disetujui karena saldo nasabah tidak mencukupi.',
          'saldo_raw'    => $saldo_aktif,
          'saldo_format' => 'Rp ' . number_format(
            $saldo_aktif,
            0,
            ',',
            '.'
          )
        ], 422);

        return;
      }
    }

    /*
     * id_admin dari request diabaikan.
     * Pengelola selalu ditentukan dari Bearer token.
     */
    $this->db->where('id', $id_transaksi);
    $updated = $this->db->update('tb_transaksi', [
      'status_konfirmasi' => $status_baru,
      'idAdmin'           => (int) $auth->id_user
    ]);

    if (!$updated || $this->db->trans_status() === false) {
      $database_error = $this->db->error();
      $this->db->trans_rollback();

      log_message(
        'error',
        'Gagal mengonfirmasi transaksi API: ' .
          json_encode($database_error)
      );

      $this->api_response([
        'status'  => false,
        'message' => 'Status transaksi gagal diperbarui.'
      ], 500);

      return;
    }

    $this->db->trans_commit();

    // Notifikasi dikirim setelah transaksi database selesai
    $jenis_teks = $transaksi->jenis === 'Masuk'
      ? 'menabung'
      : 'penarikan';

    $nominal_format = 'Rp ' . number_format(
      (int) $transaksi->nominal,
      0,
      ',',
      '.'
    );

    if ($status_baru === 'Sukses') {
      $judul_notifikasi = '✅ Transaksi Disetujui';
      $isi_notifikasi =
        "Pengajuan {$jenis_teks} sebesar {$nominal_format} " .
        "telah disetujui.";
      $pesan_status = 'disetujui';
    } else {
      $judul_notifikasi = '❌ Transaksi Ditolak';
      $isi_notifikasi =
        "Pengajuan {$jenis_teks} sebesar {$nominal_format} " .
        "telah ditolak.";
      $pesan_status = 'ditolak';
    }

    $this->db->insert('tb_notifikasi', [
      'id_user' => $id_nasabah,
      'judul'   => $judul_notifikasi,
      'pesan'   => $isi_notifikasi,
      'tanggal' => date('Y-m-d H:i:s')
    ]);

    if (!empty($transaksi->expo_token)) {
      $this->send_expo_push_notification(
        $transaksi->expo_token,
        $judul_notifikasi,
        $isi_notifikasi
      );
    }

    $this->api_response([
      'status'  => true,
      'message' => 'Transaksi berhasil ' . $pesan_status . '.',
      'data'    => [
        'id_transaksi'      => $id_transaksi,
        'id_nasabahah'        => $id_nasabah,
        'nama_nasabah'      => $transaksi->nama_nasabah,
        'jenis'             => $transaksi->jenis,
        'nominal'           => (int) $transaksi->nominal,
        'status_sebelumnya' => 'Pending',
        'status_sekarang'   => $status_baru,
        'diproses_oleh'     => (int) $auth->id_user,
        'nama_operator'     => $auth->nama,
        'cabang_id'         => (int) $transaksi->cabang_id,
        'kode_cabang'       => $transaksi->kode_cabang,
        'nama_cabang'       => $transaksi->nama_cabang,
        'saldo_sebelum'     => $saldo_aktif,
        'saldo_sesudah'     => (
          $saldo_aktif !== null &&
          $status_baru === 'Sukses' &&
          $transaksi->jenis === 'Keluar'
        )
          ? $saldo_aktif - (int) $transaksi->nominal
          : null
      ]
    ]);
  }

  // ==========================================
  // ENDPOINT REKENING PEMBAYARAN TERPROTEKSI
  // ==========================================
  public function get_rekening()
  {
    if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
      $this->api_response([
        'status'  => false,
        'message' => 'Gunakan metode GET.'
      ], 405);

      return;
    }

    $auth = $this->authenticate_api();

    if (!$auth) {
      return;
    }

    $rekening = [
      [
        'id'        => 1,
        'bank'      => 'BCA (Bank Central Asia)',
        'nomor'     => '0380463563',
        'atas_nama' => 'a.n. Mohammad Lukman Nurdin',
        'icon'      => 'card'
      ],
      [
        'id'        => 2,
        'bank'      => 'DANA',
        'nomor'     => '085793771111',
        'atas_nama' => 'a.n. Mohammad Lukman Nurdin',
        'icon'      => 'wallet'
      ]
    ];

    $this->api_response([
      'status' => true,
      'scope'  => 'rekening_pusat',
      'cabang' => [
        'id'   => (int) $auth->cabang_id,
        'kode' => $auth->kode_cabang,
        'nama' => $auth->nama_cabang
      ],
      'data' => $rekening
    ]);
  }

  // ==========================================
  // ENDPOINT UPDATE PROFIL TERPROTEKSI
  // ==========================================
  public function update_profil()
  {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
      $this->api_response([
        'status'  => false,
        'message' => 'Gunakan metode POST.'
      ], 405);

      return;
    }

    $auth = $this->authenticate_api();

    if (!$auth) {
      return;
    }

    $request = json_decode($this->input->raw_input_stream, true);

    if (!is_array($request)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Format permintaan tidak valid.'
      ], 400);

      return;
    }

    /*
     * ID pengguna selalu berasal dari Bearer token.
     * id_user dari request tidak digunakan.
     */
    $id_user = (int) $auth->id_user;

    $this->db->select(
      'u.*,
         c.kode AS kode_cabang,
         c.nama AS nama_cabang'
    );
    $this->db->from('tb_user AS u');
    $this->db->join(
      'tb_cabang AS c',
      'c.id = u.cabang_id',
      'inner'
    );
    $this->db->where('u.id', $id_user);
    $current_user = $this->db->get()->row();

    if (!$current_user) {
      $this->api_response([
        'status'  => false,
        'message' => 'Data pengguna tidak ditemukan.'
      ], 404);

      return;
    }

    /*
     * Jika field tidak dikirim, pertahankan nilai lama.
     */
    $nama = array_key_exists('nama', $request)
      ? trim((string) $request['nama'])
      : $current_user->nama;

    $username = array_key_exists('username', $request)
      ? trim((string) $request['username'])
      : $current_user->username;

    $jenis_kelamin = array_key_exists(
      'jenis_kelamin',
      $request
    )
      ? trim((string) $request['jenis_kelamin'])
      : $current_user->jenisKelamin;

    $telp = array_key_exists('telp', $request)
      ? trim((string) $request['telp'])
      : $current_user->telp;

    $email = array_key_exists('email', $request)
      ? trim((string) $request['email'])
      : $current_user->email;

    $alamat = array_key_exists('alamat', $request)
      ? trim((string) $request['alamat'])
      : $current_user->alamat;

    $password = (string) ($request['password'] ?? '');
    $foto_base64 = (string) ($request['foto_base64'] ?? '');

    if ($nama === '' || $username === '') {
      $this->api_response([
        'status'  => false,
        'message' => 'Nama dan username wajib diisi.'
      ], 422);

      return;
    }

    if (
      mb_strlen($nama) > 256 ||
      mb_strlen($username) > 256
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Nama atau username terlalu panjang.'
      ], 422);

      return;
    }

    if (
      !in_array(
        $jenis_kelamin,
        ['Laki-Laki', 'Perempuan'],
        true
      )
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Jenis kelamin tidak valid.'
      ], 422);

      return;
    }

    if (mb_strlen($telp) > 16) {
      $this->api_response([
        'status'  => false,
        'message' => 'Nomor telepon maksimal 16 karakter.'
      ], 422);

      return;
    }

    if (
      $email !== '' &&
      !filter_var($email, FILTER_VALIDATE_EMAIL)
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Format email tidak valid.'
      ], 422);

      return;
    }

    if (mb_strlen($email) > 256) {
      $this->api_response([
        'status'  => false,
        'message' => 'Email terlalu panjang.'
      ], 422);

      return;
    }

    if (mb_strlen($alamat) > 5000) {
      $this->api_response([
        'status'  => false,
        'message' => 'Alamat terlalu panjang.'
      ], 422);

      return;
    }

    /*
     * Password tidak wajib diisi.
     * Jika diisi, gunakan minimal 8 karakter.
     */
    if (
      $password !== '' &&
      (
        mb_strlen($password) < 8 ||
        mb_strlen($password) > 128
      )
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Password harus berisi 8 sampai 128 karakter.'
      ], 422);

      return;
    }

    // Pastikan username belum digunakan akun lain
    $username_exists = $this->db
      ->where('username', $username)
      ->where('id !=', $id_user)
      ->count_all_results('tb_user');

    if ($username_exists > 0) {
      $this->api_response([
        'status'  => false,
        'message' => 'Username sudah digunakan pengguna lain.'
      ], 409);

      return;
    }

    // ==========================================
    // VALIDASI FOTO PROFIL
    // ==========================================
    $image_binary = null;
    $image_extension = null;

    if ($foto_base64 !== '') {
      if (
        !preg_match(
          '/^data:image\/(jpeg|jpg|png|webp);base64,(.+)$/is',
          $foto_base64,
          $image_matches
        )
      ) {
        $this->api_response([
          'status'  => false,
          'message' => 'Format foto profil tidak didukung.'
        ], 422);

        return;
      }

      $image_binary = base64_decode(
        $image_matches[2],
        true
      );

      if ($image_binary === false) {
        $this->api_response([
          'status'  => false,
          'message' => 'Foto profil tidak dapat dibaca.'
        ], 422);

        return;
      }

      if (strlen($image_binary) > 5 * 1024 * 1024) {
        $this->api_response([
          'status'  => false,
          'message' => 'Ukuran foto maksimal 5 MB.'
        ], 422);

        return;
      }

      $image_info = @getimagesizefromstring($image_binary);
      $mime = $image_info['mime'] ?? '';

      $allowed_mimes = [
        'image/jpeg' => 'jpg',
        'image/png'  => 'png',
        'image/webp' => 'webp'
      ];

      if (!isset($allowed_mimes[$mime])) {
        $this->api_response([
          'status'  => false,
          'message' => 'Isi file bukan gambar yang valid.'
        ], 422);

        return;
      }

      $image_extension = $allowed_mimes[$mime];
    }

    $data_update = [
      'nama'         => $nama,
      'username'     => $username,
      'jenisKelamin' => $jenis_kelamin,
      'telp'         => $telp,
      'email'        => $email,
      'alamat'       => $alamat
    ];

    $password_changed = false;

    if ($password !== '') {
      $data_update['password'] = password_hash(
        $password,
        PASSWORD_DEFAULT
      );

      $password_changed = true;
    }

    $file_name = null;
    $saved_file_path = null;

    if ($image_binary !== null) {
      $upload_dir = FCPATH . 'assets/profil/';

      if (
        !is_dir($upload_dir) &&
        !mkdir($upload_dir, 0755, true)
      ) {
        $this->api_response([
          'status'  => false,
          'message' => 'Folder foto profil tidak dapat dibuat.'
        ], 500);

        return;
      }

      try {
        $random_name = bin2hex(random_bytes(8));
      } catch (Exception $e) {
        $random_name = uniqid('', true);
      }

      $file_name = 'profil_' .
        date('YmdHis') . '_' .
        $random_name . '.' .
        $image_extension;

      $saved_file_path = $upload_dir . $file_name;

      if (
        file_put_contents(
          $saved_file_path,
          $image_binary,
          LOCK_EX
        ) === false
      ) {
        $this->api_response([
          'status'  => false,
          'message' => 'Foto profil gagal disimpan.'
        ], 500);

        return;
      }

      $data_update['foto'] = $file_name;
    }

    $this->db->trans_begin();

    $this->db->where('id', $id_user);
    $updated = $this->db->update(
      'tb_user',
      $data_update
    );

    /*
     * Jika password berubah, cabut semua sesi lain.
     * Token yang sedang digunakan tetap aktif.
     */
    if ($updated && $password_changed) {
      $this->db->where('id_user', $id_user);
      $this->db->where('id !=', (int) $auth->token_id);
      $this->db->where(
        'revoked_at IS NULL',
        null,
        false
      );
      $this->db->update('tb_api_token', [
        'revoked_at' => date('Y-m-d H:i:s')
      ]);
    }

    if (!$updated || $this->db->trans_status() === false) {
      $database_error = $this->db->error();
      $this->db->trans_rollback();

      if (
        $saved_file_path !== null &&
        is_file($saved_file_path)
      ) {
        unlink($saved_file_path);
      }

      log_message(
        'error',
        'Gagal memperbarui profil API: ' .
          json_encode($database_error)
      );

      $this->api_response([
        'status'  => false,
        'message' => 'Profil gagal diperbarui.'
      ], 500);

      return;
    }

    $this->db->trans_commit();

    $this->api_response([
      'status'     => true,
      'message'    => 'Profil berhasil diperbarui.',
      'foto_baru'  => $file_name,
      'data'       => [
        'id'              => $id_user,
        'nama'            => $nama,
        'username'        => $username,
        'jenis_kelamin'   => $jenis_kelamin,
        'telp'            => $telp,
        'email'           => $email,
        'alamat'          => $alamat,
        'foto'            => $file_name
          ?? $current_user->foto,
        'level'           => $current_user->level,
        'cabang_id'       => (int) $current_user->cabang_id,
        'kode_cabang'     => $current_user->kode_cabang,
        'nama_cabang'     => $current_user->nama_cabang
      ]
    ]);
  }

  // ==========================================
  // ENDPOINT UPDATE EXPO TOKEN TERPROTEKSI
  // ==========================================
  public function update_token()
  {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
      $this->api_response([
        'status'  => false,
        'message' => 'Gunakan metode POST.'
      ], 405);

      return;
    }

    $auth = $this->authenticate_api();

    if (!$auth) {
      return;
    }

    $request = json_decode($this->input->raw_input_stream, true);

    if (!is_array($request)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Format permintaan tidak valid.'
      ], 400);

      return;
    }

    /*
     * ID pengguna selalu berasal dari Bearer token.
     * id_user dari request diabaikan.
     */
    $id_user = (int) $auth->id_user;
    $expo_token = trim((string) ($request['token'] ?? ''));

    /*
     * Token kosong berarti pengguna ingin
     * melepaskan token notifikasi dari akunnya.
     */
    if ($expo_token === '') {
      $this->db->where('id', $id_user);
      $updated = $this->db->update('tb_user', [
        'expo_token' => null
      ]);

      if (!$updated) {
        $this->api_response([
          'status'  => false,
          'message' => 'Token notifikasi gagal dihapus.'
        ], 500);

        return;
      }

      $this->api_response([
        'status'  => true,
        'message' => 'Token notifikasi berhasil dihapus.',
        'data'    => [
          'id_user'       => $id_user,
          'expo_terpasang' => false
        ]
      ]);

      return;
    }

    if (strlen($expo_token) > 255) {
      $this->api_response([
        'status'  => false,
        'message' => 'Token notifikasi terlalu panjang.'
      ], 422);

      return;
    }

    /*
     * Mendukung format Expo lama dan baru:
     * ExponentPushToken[...] atau ExpoPushToken[...]
     */
    if (
      !preg_match(
        '/^(ExponentPushToken|ExpoPushToken)\[[^\]\s]{10,220}\]$/',
        $expo_token
      )
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Format Expo push token tidak valid.'
      ], 422);

      return;
    }

    $this->db->trans_begin();

    /*
     * Satu Expo token hanya boleh dimiliki satu akun.
     * Ini mencegah notifikasi akun lama masuk ke akun baru
     * pada perangkat yang sama.
     */
    $this->db->where('expo_token', $expo_token);
    $this->db->where('id !=', $id_user);
    $this->db->update('tb_user', [
      'expo_token' => null
    ]);

    $this->db->where('id', $id_user);
    $updated = $this->db->update('tb_user', [
      'expo_token' => $expo_token
    ]);

    if (!$updated || $this->db->trans_status() === false) {
      $database_error = $this->db->error();
      $this->db->trans_rollback();

      log_message(
        'error',
        'Gagal memperbarui Expo token: ' .
          json_encode($database_error)
      );

      $this->api_response([
        'status'  => false,
        'message' => 'Token notifikasi gagal disimpan.'
      ], 500);

      return;
    }

    $this->db->trans_commit();

    $this->api_response([
      'status'  => true,
      'message' => 'Token notifikasi berhasil disimpan.',
      'data'    => [
        'id_user'        => $id_user,
        'expo_terpasang' => true
      ]
    ]);
  }

  private function send_expo_push_notification($token, $title, $body)
  {
    if (empty($token)) return false;

    $url = 'https://exp.host/--/api/v2/push/send';
    $data = [
      'to' => $token,
      'title' => $title,
      'body' => $body,
      'sound' => 'default',
    ];

    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Accept: application/json', 'Content-Type: application/json']);
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $response = curl_exec($ch);
    curl_close($ch);
    return $response;
  }

  private function send_whatsapp($nomor_tujuan, $pesan)
  {
    $token = 'TOKEN_WA_GATEWAY_ANDA_DISINI';

    $curl = curl_init();
    curl_setopt_array($curl, array(
      CURLOPT_URL => 'https://api.fonnte.com/send',
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_ENCODING => '',
      CURLOPT_MAXREDIRS => 10,
      CURLOPT_TIMEOUT => 0,
      CURLOPT_FOLLOWLOCATION => true,
      CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
      CURLOPT_CUSTOMREQUEST => 'POST',
      CURLOPT_POSTFIELDS => array(
        'target' => $nomor_tujuan,
        'message' => $pesan,
        'countryCode' => '62',
      ),
      CURLOPT_HTTPHEADER => array('Authorization: ' . $token),
    ));

    $response = curl_exec($curl);
    curl_close($curl);
    return $response;
  }

  // ==========================================
  // FITUR PENGATURAN APLIKASI
  // ==========================================

  public function get_pengaturan()
  {
    $data = $this->db->get('tb_aplikasi')->row();
    if ($data) {
      echo json_encode(['status' => true, 'data' => $data]);
    } else {
      // 🔥 PERBAIKAN: Jika tabel masih kosong, tetap kirim status true dengan data kosong 
      // agar aplikasi di HP tidak mogok dan tetap membuka modalnya.
      echo json_encode([
        'status' => true,
        'data' => [
          'nama' => '',
          'telp' => '',
          'email' => '',
          'alamat' => '',
          'logo' => null
        ]
      ]);
    }
  }

  // ==========================================
  // ENDPOINT UPDATE PENGATURAN TERPROTEKSI
  // ==========================================
  public function update_pengaturan()
  {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
      $this->api_response([
        'status'  => false,
        'message' => 'Gunakan metode POST.'
      ], 405);

      return;
    }

    $auth = $this->authenticate_api();

    if (!$auth) {
      return;
    }

    if ($auth->level !== 'Super Admin') {
      $this->api_response([
        'status'  => false,
        'message' => 'Akses ditolak. Khusus Super Admin.'
      ], 403);

      return;
    }

    $request = json_decode($this->input->raw_input_stream, true);

    if (!is_array($request)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Format permintaan tidak valid.'
      ], 400);

      return;
    }

    /*
     * id_admin dari request tidak digunakan.
     * Identitas pengelola berasal dari Bearer token.
     */
    $pengaturan_lama = $this->db
      ->order_by('id', 'ASC')
      ->limit(1)
      ->get('tb_aplikasi')
      ->row();

    $nama = array_key_exists('nama', $request)
      ? trim((string) $request['nama'])
      : ($pengaturan_lama->nama ?? '');

    $telp = array_key_exists('telp', $request)
      ? trim((string) $request['telp'])
      : ($pengaturan_lama->telp ?? '');

    $email = array_key_exists('email', $request)
      ? trim((string) $request['email'])
      : ($pengaturan_lama->email ?? '');

    $alamat = array_key_exists('alamat', $request)
      ? trim((string) $request['alamat'])
      : ($pengaturan_lama->alamat ?? '');

    $logo_base64 = (string) (
      $request['logo_base64'] ?? ''
    );

    if ($nama === '') {
      $this->api_response([
        'status'  => false,
        'message' => 'Nama aplikasi wajib diisi.'
      ], 422);

      return;
    }

    if (mb_strlen($nama) > 256) {
      $this->api_response([
        'status'  => false,
        'message' => 'Nama aplikasi terlalu panjang.'
      ], 422);

      return;
    }

    if (mb_strlen($telp) > 16) {
      $this->api_response([
        'status'  => false,
        'message' => 'Nomor telepon maksimal 16 karakter.'
      ], 422);

      return;
    }

    if (
      $email !== '' &&
      !filter_var($email, FILTER_VALIDATE_EMAIL)
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Format email tidak valid.'
      ], 422);

      return;
    }

    if (mb_strlen($email) > 256) {
      $this->api_response([
        'status'  => false,
        'message' => 'Email terlalu panjang.'
      ], 422);

      return;
    }

    if (mb_strlen($alamat) > 5000) {
      $this->api_response([
        'status'  => false,
        'message' => 'Alamat terlalu panjang.'
      ], 422);

      return;
    }

    // ==========================================
    // VALIDASI LOGO
    // ==========================================
    $image_binary = null;
    $image_extension = null;

    if ($logo_base64 !== '') {
      if (
        !preg_match(
          '/^data:image\/(jpeg|jpg|png|webp);base64,(.+)$/is',
          $logo_base64,
          $image_matches
        )
      ) {
        $this->api_response([
          'status'  => false,
          'message' => 'Format logo tidak didukung.'
        ], 422);

        return;
      }

      $image_binary = base64_decode(
        $image_matches[2],
        true
      );

      if ($image_binary === false) {
        $this->api_response([
          'status'  => false,
          'message' => 'Logo tidak dapat dibaca.'
        ], 422);

        return;
      }

      if (strlen($image_binary) > 5 * 1024 * 1024) {
        $this->api_response([
          'status'  => false,
          'message' => 'Ukuran logo maksimal 5 MB.'
        ], 422);

        return;
      }

      $image_info = @getimagesizefromstring($image_binary);
      $mime = $image_info['mime'] ?? '';

      $allowed_mimes = [
        'image/jpeg' => 'jpg',
        'image/png'  => 'png',
        'image/webp' => 'webp'
      ];

      if (!isset($allowed_mimes[$mime])) {
        $this->api_response([
          'status'  => false,
          'message' => 'Isi file logo bukan gambar yang valid.'
        ], 422);

        return;
      }

      $image_extension = $allowed_mimes[$mime];
    }

    /*
     * Jika tabel masih kosong, logo wajib diberikan
     * karena kolom logo pada database bersifat NOT NULL.
     */
    if (!$pengaturan_lama && $image_binary === null) {
      $this->api_response([
        'status'  => false,
        'message' => 'Logo wajib diunggah pada pengaturan pertama.'
      ], 422);

      return;
    }

    $data_update = [
      'nama'   => $nama,
      'telp'   => $telp,
      'email'  => $email,
      'alamat' => $alamat
    ];

    $file_name = null;
    $saved_file_path = null;

    if ($image_binary !== null) {
      $upload_dir = FCPATH . 'assets/logo/';

      if (
        !is_dir($upload_dir) &&
        !mkdir($upload_dir, 0755, true)
      ) {
        $this->api_response([
          'status'  => false,
          'message' => 'Folder logo tidak dapat dibuat.'
        ], 500);

        return;
      }

      try {
        $random_name = bin2hex(random_bytes(8));
      } catch (Exception $e) {
        $random_name = uniqid('', true);
      }

      $file_name = 'logo_' .
        date('YmdHis') . '_' .
        $random_name . '.' .
        $image_extension;

      $saved_file_path = $upload_dir . $file_name;

      if (
        file_put_contents(
          $saved_file_path,
          $image_binary,
          LOCK_EX
        ) === false
      ) {
        $this->api_response([
          'status'  => false,
          'message' => 'Logo gagal disimpan.'
        ], 500);

        return;
      }

      $data_update['logo'] = $file_name;
    }

    $this->db->trans_begin();

    if ($pengaturan_lama) {
      $this->db->where('id', $pengaturan_lama->id);
      $saved = $this->db->update(
        'tb_aplikasi',
        $data_update
      );
    } else {
      $data_update['id'] = 1;
      $saved = $this->db->insert(
        'tb_aplikasi',
        $data_update
      );
    }

    if (!$saved || $this->db->trans_status() === false) {
      $database_error = $this->db->error();
      $this->db->trans_rollback();

      if (
        $saved_file_path !== null &&
        is_file($saved_file_path)
      ) {
        unlink($saved_file_path);
      }

      log_message(
        'error',
        'Gagal memperbarui pengaturan aplikasi: ' .
          json_encode($database_error)
      );

      $this->api_response([
        'status'  => false,
        'message' => 'Pengaturan aplikasi gagal disimpan.'
      ], 500);

      return;
    }

    $this->db->trans_commit();

    $this->api_response([
      'status'  => true,
      'message' => 'Pengaturan aplikasi berhasil disimpan.',
      'data'    => [
        'nama'             => $nama,
        'telp'             => $telp,
        'email'            => $email,
        'alamat'           => $alamat,
        'logo'             => $file_name
          ?? ($pengaturan_lama->logo ?? null),
        'diperbarui_oleh'  => (int) $auth->id_user,
        'nama_operator'    => $auth->nama
      ]
    ]);
  }
  // ==========================================
  // 10. ENDPOINT BANNER DINAMIS
  // ==========================================
  public function get_banner()
  {
    $this->db->order_by('id', 'DESC');
    $data = $this->db->get('tb_banner')->result_array();
    echo json_encode(['status' => true, 'data' => $data]);
  }

  // ==========================================
  // ENDPOINT UPLOAD BANNER GLOBAL
  // ==========================================
  public function upload_banner()
  {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
      $this->api_response([
        'status'  => false,
        'message' => 'Gunakan metode POST.'
      ], 405);

      return;
    }

    $auth = $this->authenticate_api();

    if (!$auth) {
      return;
    }

    if ($auth->level !== 'Super Admin') {
      $this->api_response([
        'status'  => false,
        'message' => 'Akses ditolak. Khusus Super Admin.'
      ], 403);

      return;
    }

    $request = json_decode($this->input->raw_input_stream, true);

    if (!is_array($request)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Format permintaan tidak valid.'
      ], 400);

      return;
    }

    /*
     * id_admin dari request diabaikan.
     * Operator selalu berasal dari Bearer token.
     */
    $gambar_base64 = (string) (
      $request['gambar_base64'] ?? ''
    );

    if ($gambar_base64 === '') {
      $this->api_response([
        'status'  => false,
        'message' => 'Gambar banner wajib dipilih.'
      ], 422);

      return;
    }

    if (
      !preg_match(
        '/^data:image\/(jpeg|jpg|png|webp);base64,(.+)$/is',
        $gambar_base64,
        $image_matches
      )
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Format banner tidak didukung.'
      ], 422);

      return;
    }

    $image_binary = base64_decode(
      $image_matches[2],
      true
    );

    if ($image_binary === false) {
      $this->api_response([
        'status'  => false,
        'message' => 'Gambar banner tidak dapat dibaca.'
      ], 422);

      return;
    }

    if (strlen($image_binary) > 5 * 1024 * 1024) {
      $this->api_response([
        'status'  => false,
        'message' => 'Ukuran banner maksimal 5 MB.'
      ], 422);

      return;
    }

    $image_info = @getimagesizefromstring($image_binary);
    $mime = $image_info['mime'] ?? '';
    $width = (int) ($image_info[0] ?? 0);
    $height = (int) ($image_info[1] ?? 0);

    $allowed_mimes = [
      'image/jpeg' => 'jpg',
      'image/png'  => 'png',
      'image/webp' => 'webp'
    ];

    if (!isset($allowed_mimes[$mime])) {
      $this->api_response([
        'status'  => false,
        'message' => 'Isi file bukan gambar yang valid.'
      ], 422);

      return;
    }

    if (
      $width <= 0 ||
      $height <= 0 ||
      $width > 10000 ||
      $height > 10000 ||
      ($width * $height) > 40000000
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Dimensi gambar banner tidak valid.'
      ], 422);

      return;
    }

    $upload_dir = FCPATH . 'assets/banner/';

    if (
      !is_dir($upload_dir) &&
      !mkdir($upload_dir, 0755, true)
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Folder banner tidak dapat dibuat.'
      ], 500);

      return;
    }

    try {
      $random_name = bin2hex(random_bytes(8));
    } catch (Exception $e) {
      $random_name = uniqid('', true);
    }

    $file_name = 'banner_' .
      date('YmdHis') . '_' .
      $random_name . '.' .
      $allowed_mimes[$mime];

    $file_path = $upload_dir . $file_name;

    if (
      file_put_contents(
        $file_path,
        $image_binary,
        LOCK_EX
      ) === false
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Gambar banner gagal disimpan.'
      ], 500);

      return;
    }

    $insert = $this->db->insert('tb_banner', [
      'gambar'     => $file_name,
      'terdaftar'  => date('Y-m-d H:i:s')
    ]);

    $id_banner = (int) $this->db->insert_id();

    if (!$insert) {
      if (is_file($file_path)) {
        unlink($file_path);
      }

      log_message(
        'error',
        'Gagal menyimpan banner: ' .
          json_encode($this->db->error())
      );

      $this->api_response([
        'status'  => false,
        'message' => 'Data banner gagal disimpan.'
      ], 500);

      return;
    }

    $this->api_response([
      'status'  => true,
      'message' => 'Banner berhasil dipublikasikan.',
      'data'    => [
        'id'                 => $id_banner,
        'gambar'             => $file_name,
        'width'              => $width,
        'height'             => $height,
        'dipublikasikan_oleh' => (int) $auth->id_user,
        'nama_operator'      => $auth->nama
      ]
    ]);
  }

  // ==========================================
  // ENDPOINT HAPUS BANNER GLOBAL
  // ==========================================
  public function hapus_banner()
  {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
      $this->api_response([
        'status'  => false,
        'message' => 'Gunakan metode POST.'
      ], 405);

      return;
    }

    $auth = $this->authenticate_api();

    if (!$auth) {
      return;
    }

    if ($auth->level !== 'Super Admin') {
      $this->api_response([
        'status'  => false,
        'message' => 'Akses ditolak. Khusus Super Admin.'
      ], 403);

      return;
    }

    $request = json_decode($this->input->raw_input_stream, true);

    if (!is_array($request)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Format permintaan tidak valid.'
      ], 400);

      return;
    }

    $id_banner = (int) ($request['id_banner'] ?? 0);

    if ($id_banner <= 0) {
      $this->api_response([
        'status'  => false,
        'message' => 'ID banner tidak valid.'
      ], 422);

      return;
    }

    $this->db->trans_begin();

    $banner = $this->db->query(
      'SELECT id, gambar
         FROM tb_banner
         WHERE id = ?
         FOR UPDATE',
      [$id_banner]
    )->row();

    if (!$banner) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Data banner tidak ditemukan.'
      ], 404);

      return;
    }

    $this->db->where('id', $id_banner);
    $deleted = $this->db->delete('tb_banner');

    if (!$deleted || $this->db->trans_status() === false) {
      $database_error = $this->db->error();
      $this->db->trans_rollback();

      log_message(
        'error',
        'Gagal menghapus banner: ' .
          json_encode($database_error)
      );

      $this->api_response([
        'status'  => false,
        'message' => 'Banner gagal dihapus.'
      ], 500);

      return;
    }

    $this->db->trans_commit();

    /*
     * Hapus file hanya jika benar-benar berada
     * di dalam folder assets/banner.
     */
    $file_removed = false;
    $upload_root = realpath(
      FCPATH . 'assets/banner/'
    );

    if (
      $upload_root !== false &&
      basename($banner->gambar) === $banner->gambar
    ) {
      $candidate_path = $upload_root .
        DIRECTORY_SEPARATOR .
        $banner->gambar;

      $real_file_path = realpath($candidate_path);

      if (
        $real_file_path !== false &&
        strpos(
          $real_file_path,
          $upload_root . DIRECTORY_SEPARATOR
        ) === 0 &&
        is_file($real_file_path)
      ) {
        $file_removed = unlink($real_file_path);
      }
    }

    if (!$file_removed) {
      log_message(
        'debug',
        'File banner tidak ditemukan atau tidak perlu dihapus: ' .
          $banner->gambar
      );
    }

    $this->api_response([
      'status'  => true,
      'message' => 'Banner berhasil dihapus.',
      'data'    => [
        'id_banner'       => $id_banner,
        'gambar'          => $banner->gambar,
        'file_dihapus'    => $file_removed,
        'dihapus_oleh'    => (int) $auth->id_user,
        'nama_operator'   => $auth->nama
      ]
    ]);
  }


  // ==========================================
  // ENDPOINT PUBLIK DAFTAR CABANG AKTIF
  // ==========================================
  public function get_cabang_aktif()
  {
    if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
      $this->api_response([
        'status'  => false,
        'message' => 'Gunakan metode GET.'
      ], 405);

      return;
    }

    /*
     * Endpoint ini sengaja tidak memerlukan Bearer token
     * karena digunakan sebelum pengguna mendaftar/login.
     *
     * Hanya informasi umum cabang yang ditampilkan.
     */
    $this->db->select(
      'id,
         kode,
         nama,
         is_pusat'
    );
    $this->db->from('tb_cabang');
    $this->db->where('status', 'Aktif');
    $this->db->order_by('is_pusat', 'DESC');
    $this->db->order_by('nama', 'ASC');

    $cabang = $this->db->get()->result_array();

    $this->api_response([
      'status' => true,
      'data'   => $cabang
    ]);
  }


  // ==========================================
  // ENDPOINT PENDAFTARAN NASABAH
  // ==========================================
  public function register()
  {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
      $this->api_response([
        'status'  => false,
        'message' => 'Gunakan metode POST.'
      ], 405);

      return;
    }

    $raw_request = $this->input->raw_input_stream;

    // Pendaftaran tidak mengandung foto, jadi 64 KB sudah cukup
    if (strlen($raw_request) > 65536) {
      $this->api_response([
        'status'  => false,
        'message' => 'Ukuran permintaan terlalu besar.'
      ], 413);

      return;
    }

    $request = json_decode($raw_request, true);

    if (!is_array($request)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Format permintaan tidak valid.'
      ], 400);

      return;
    }

    $nama = trim((string) ($request['nama'] ?? ''));
    $username = trim((string) ($request['username'] ?? ''));
    $password = (string) ($request['password'] ?? '');
    $jenis_kelamin = trim(
      (string) ($request['jenis_kelamin'] ?? 'Laki-Laki')
    );
    $telp = trim((string) ($request['telp'] ?? ''));
    $email = trim((string) ($request['email'] ?? ''));
    $alamat = trim((string) ($request['alamat'] ?? ''));
    $cabang_id = (int) ($request['cabang_id'] ?? 0);

    if (
      $nama === '' ||
      $username === '' ||
      $password === '' ||
      $cabang_id <= 0
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Nama, username, password, dan cabang wajib diisi.'
      ], 422);

      return;
    }

    if (mb_strlen($nama) > 256) {
      $this->api_response([
        'status'  => false,
        'message' => 'Nama terlalu panjang.'
      ], 422);

      return;
    }

    if (
      mb_strlen($username) < 3 ||
      mb_strlen($username) > 64 ||
      preg_match('/\s/', $username)
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Username harus 3–64 karakter dan tidak boleh mengandung spasi.'
      ], 422);

      return;
    }

    if (
      mb_strlen($password) < 8 ||
      mb_strlen($password) > 128
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Password harus berisi 8 sampai 128 karakter.'
      ], 422);

      return;
    }

    if (
      !in_array(
        $jenis_kelamin,
        ['Laki-Laki', 'Perempuan'],
        true
      )
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Jenis kelamin tidak valid.'
      ], 422);

      return;
    }

    if (mb_strlen($telp) > 16) {
      $this->api_response([
        'status'  => false,
        'message' => 'Nomor telepon maksimal 16 karakter.'
      ], 422);

      return;
    }

    if (
      $email !== '' &&
      !filter_var($email, FILTER_VALIDATE_EMAIL)
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Format email tidak valid.'
      ], 422);

      return;
    }

    if (mb_strlen($email) > 256) {
      $this->api_response([
        'status'  => false,
        'message' => 'Email terlalu panjang.'
      ], 422);

      return;
    }

    if (mb_strlen($alamat) > 5000) {
      $this->api_response([
        'status'  => false,
        'message' => 'Alamat terlalu panjang.'
      ], 422);

      return;
    }

    // Pastikan cabang ada dan aktif
    $cabang = $this->db
      ->select('id, kode, nama, status')
      ->where('id', $cabang_id)
      ->where('status', 'Aktif')
      ->get('tb_cabang')
      ->row();

    if (!$cabang) {
      $this->api_response([
        'status'  => false,
        'message' => 'Cabang tidak ditemukan atau sedang tidak aktif.'
      ], 422);

      return;
    }

    // Pemeriksaan awal agar pesan lebih ramah
    $username_exists = $this->db
      ->where('username', $username)
      ->count_all_results('tb_user');

    if ($username_exists > 0) {
      $this->api_response([
        'status'  => false,
        'message' => 'Username sudah terdaftar.'
      ], 409);

      return;
    }

    $data_user = [
      'nama'         => $nama,
      'jenisKelamin' => $jenis_kelamin,
      'telp'         => $telp,
      'email'        => $email,
      'alamat'       => $alamat,
      'id_kota'      => 0,
      'username'     => $username,
      'password'     => password_hash(
        $password,
        PASSWORD_DEFAULT
      ),
      'foto'         => 'no-image.png',
      'skin'         => 'green',
      'expo_token'   => null,
      'level'        => 'Nasabah',
      'login'        => 'Tidak',
      'cabang_id'    => (int) $cabang->id,
      'terdaftar'    => date('Y-m-d H:i:s')
    ];

    $this->db->trans_begin();

    $insert = $this->db->insert(
      'tb_user',
      $data_user
    );

    $id_user = (int) $this->db->insert_id();

    if (!$insert || $this->db->trans_status() === false) {
      $database_error = $this->db->error();
      $this->db->trans_rollback();

      log_message(
        'error',
        'Gagal mendaftarkan nasabah: ' .
          json_encode($database_error)
      );

      $message = (
        isset($database_error['code']) &&
        (int) $database_error['code'] === 1062
      )
        ? 'Username sudah terdaftar.'
        : 'Pendaftaran gagal diproses.';

      $this->api_response([
        'status'  => false,
        'message' => $message
      ], 500);

      return;
    }

    $this->db->trans_commit();

    /*
     * Beri tahu Administrator pada cabang pilihan
     * dan seluruh Super Admin.
     */
    $this->db->select('id, expo_token');
    $this->db->from('tb_user');
    $this->db->group_start();

    $this->db->group_start();
    $this->db->where('level', 'Administrator');
    $this->db->where('cabang_id', $cabang_id);
    $this->db->group_end();

    $this->db->or_where('level', 'Super Admin');
    $this->db->group_end();

    $admins = $this->db->get()->result();

    $judul_notifikasi = 'Pendaftar Nasabah Baru 👤';
    $isi_notifikasi =
      "Nasabah baru {$nama} mendaftar pada " .
      "cabang {$cabang->nama}. Silakan lakukan verifikasi.";

    foreach ($admins as $admin) {
      $this->db->insert('tb_notifikasi', [
        'id_user' => $admin->id,
        'judul'   => $judul_notifikasi,
        'pesan'   => $isi_notifikasi,
        'is_read' => 0,
        'tanggal' => date('Y-m-d H:i:s')
      ]);

      if (!empty($admin->expo_token)) {
        $this->send_expo_push_notification(
          $admin->expo_token,
          $judul_notifikasi,
          $isi_notifikasi
        );
      }
    }

    $this->api_response([
      'status'  => true,
      'message' => 'Pendaftaran berhasil. Silakan menunggu verifikasi Administrator.',
      'data'    => [
        'id_user'          => $id_user,
        'nama'             => $nama,
        'username'         => $username,
        'status_verifikasi' => 'Pending',
        'cabang_id'        => (int) $cabang->id,
        'kode_cabang'      => $cabang->kode,
        'nama_cabang'      => $cabang->nama
      ]
    ], 201);
  }

  // ==========================================
  // ENDPOINT DAFTAR PENDAFTAR NASABAH
  // ==========================================
  public function get_nasabah_baru()
  {
    if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
      $this->api_response([
        'status'  => false,
        'message' => 'Gunakan metode GET.'
      ], 405);

      return;
    }

    $auth = $this->authenticate_api();

    if (!$auth) {
      return;
    }

    if (
      !in_array(
        $auth->level,
        ['Super Admin', 'Administrator'],
        true
      )
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Akses ditolak. Khusus pengelola.'
      ], 403);

      return;
    }

    $this->db->select(
      'u.id,
         u.nama,
         u.username,
         u.jenisKelamin AS jenis_kelamin,
         u.telp,
         u.email,
         u.alamat,
         u.cabang_id,
         u.terdaftar,
         c.kode AS kode_cabang,
         c.nama AS nama_cabang'
    );
    $this->db->from('tb_user AS u');
    $this->db->join(
      'tb_cabang AS c',
      'c.id = u.cabang_id',
      'inner'
    );
    $this->db->where('u.level', 'Nasabah');
    $this->db->where('u.login', 'Tidak');

    /*
     * Administrator hanya melihat pendaftar
     * dari cabangnya sendiri.
     */
    if ($auth->level === 'Administrator') {
      $this->db->where(
        'u.cabang_id',
        (int) $auth->cabang_id
      );
    }

    $this->db->order_by('u.id', 'DESC');
    $pendaftar = $this->db->get()->result_array();

    $this->api_response([
      'status' => true,
      'scope'  => $auth->level === 'Super Admin'
        ? 'semua_cabang'
        : 'cabang_sendiri',
      'cabang_pengelola' => [
        'id'   => (int) $auth->cabang_id,
        'kode' => $auth->kode_cabang,
        'nama' => $auth->nama_cabang
      ],
      'jumlah' => count($pendaftar),
      'data'   => $pendaftar
    ]);
  }

  // ==========================================
  // ENDPOINT VERIFIKASI NASABAH TERPROTEKSI
  // ==========================================
  public function verifikasi_nasabah()
  {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
      $this->api_response([
        'status'  => false,
        'message' => 'Gunakan metode POST.'
      ], 405);

      return;
    }

    $auth = $this->authenticate_api();

    if (!$auth) {
      return;
    }

    if (
      !in_array(
        $auth->level,
        ['Super Admin', 'Administrator'],
        true
      )
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Akses ditolak. Khusus pengelola.'
      ], 403);

      return;
    }

    $request = json_decode($this->input->raw_input_stream, true);

    if (!is_array($request)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Format permintaan tidak valid.'
      ], 400);

      return;
    }

    /*
     * id_admin dari request diabaikan.
     * Verifikator berasal dari Bearer token.
     */
    $id_nasabah = (int) ($request['id_user'] ?? 0);

    if ($id_nasabah <= 0) {
      $this->api_response([
        'status'  => false,
        'message' => 'ID nasabah tidak valid.'
      ], 422);

      return;
    }

    $this->db->trans_begin();

    $nasabah = $this->db->query(
      'SELECT
            u.id,
            u.nama,
            u.username,
            u.level,
            u.login,
            u.expo_token,
            u.cabang_id,
            c.kode AS kode_cabang,
            c.nama AS nama_cabang,
            c.status AS status_cabang
         FROM tb_user AS u
         INNER JOIN tb_cabang AS c
            ON c.id = u.cabang_id
         WHERE u.id = ?
         FOR UPDATE',
      [$id_nasabah]
    )->row();

    if (!$nasabah || $nasabah->level !== 'Nasabah') {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Data pendaftar tidak ditemukan.'
      ], 404);

      return;
    }

    /*
     * Administrator hanya boleh memverifikasi
     * nasabah pada cabangnya sendiri.
     */
    if (
      $auth->level === 'Administrator' &&
      (int) $nasabah->cabang_id !== (int) $auth->cabang_id
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Pendaftar berasal dari cabang lain.'
      ], 403);

      return;
    }

    if ($nasabah->status_cabang !== 'Aktif') {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Cabang pendaftar sedang tidak aktif.'
      ], 403);

      return;
    }

    if ($nasabah->login === 'Ya') {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Akun nasabah sudah pernah diverifikasi.'
      ], 409);

      return;
    }

    $waktu_verifikasi = date('Y-m-d H:i:s');

    $this->db->where('id', $id_nasabah);
    $updated = $this->db->update('tb_user', [
      'login'              => 'Ya',
      'diverifikasi_oleh'  => (int) $auth->id_user,
      'diverifikasi_pada'  => $waktu_verifikasi
    ]);

    if (!$updated || $this->db->trans_status() === false) {
      $database_error = $this->db->error();
      $this->db->trans_rollback();

      log_message(
        'error',
        'Gagal memverifikasi nasabah: ' .
          json_encode($database_error)
      );

      $this->api_response([
        'status'  => false,
        'message' => 'Akun nasabah gagal diverifikasi.'
      ], 500);

      return;
    }

    $this->db->trans_commit();

    $judul_notifikasi = '✅ Akun Berhasil Diverifikasi';
    $isi_notifikasi =
      "Akun Anda pada cabang {$nasabah->nama_cabang} " .
      "telah aktif dan sudah dapat digunakan untuk login.";

    $this->db->insert('tb_notifikasi', [
      'id_user' => $id_nasabah,
      'judul'   => $judul_notifikasi,
      'pesan'   => $isi_notifikasi,
      'is_read' => 0,
      'tanggal' => date('Y-m-d H:i:s')
    ]);

    if (!empty($nasabah->expo_token)) {
      $this->send_expo_push_notification(
        $nasabah->expo_token,
        $judul_notifikasi,
        $isi_notifikasi
      );
    }

    $this->api_response([
      'status'  => true,
      'message' => 'Akun nasabah berhasil diverifikasi.',
      'data'    => [
        'id_nasabah'          => $id_nasabah,
        'nama_nasabah'        => $nasabah->nama,
        'username'             => $nasabah->username,
        'status_login'         => 'Ya',
        'cabang_id'            => (int) $nasabah->cabang_id,
        'kode_cabang'          => $nasabah->kode_cabang,
        'nama_cabang'          => $nasabah->nama_cabang,
        'diverifikasi_oleh'    => (int) $auth->id_user,
        'nama_verifikator'     => $auth->nama,
        'diverifikasi_pada'    => $waktu_verifikasi
      ]
    ]);
  }

  // ==========================================
  // ENDPOINT TOLAK PENDAFTAR NASABAH
  // ==========================================
  public function tolak_nasabah()
  {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
      $this->api_response([
        'status'  => false,
        'message' => 'Gunakan metode POST.'
      ], 405);

      return;
    }

    $auth = $this->authenticate_api();

    if (!$auth) {
      return;
    }

    if (
      !in_array(
        $auth->level,
        ['Super Admin', 'Administrator'],
        true
      )
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Akses ditolak. Khusus pengelola.'
      ], 403);

      return;
    }

    $request = json_decode($this->input->raw_input_stream, true);

    if (!is_array($request)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Format permintaan tidak valid.'
      ], 400);

      return;
    }

    $id_nasabah = (int) ($request['id_user'] ?? 0);

    if ($id_nasabah <= 0) {
      $this->api_response([
        'status'  => false,
        'message' => 'ID nasabah tidak valid.'
      ], 422);

      return;
    }

    $this->db->trans_begin();

    $nasabah = $this->db->query(
      'SELECT
            u.id,
            u.nama,
            u.username,
            u.level,
            u.login,
            u.cabang_id,
            c.kode AS kode_cabang,
            c.nama AS nama_cabang
         FROM tb_user AS u
         INNER JOIN tb_cabang AS c
            ON c.id = u.cabang_id
         WHERE u.id = ?
         FOR UPDATE',
      [$id_nasabah]
    )->row();

    if (!$nasabah || $nasabah->level !== 'Nasabah') {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Data pendaftar tidak ditemukan.'
      ], 404);

      return;
    }

    if (
      $auth->level === 'Administrator' &&
      (int) $nasabah->cabang_id !== (int) $auth->cabang_id
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Pendaftar berasal dari cabang lain.'
      ], 403);

      return;
    }

    if ($nasabah->login !== 'Tidak') {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Pendaftaran sudah pernah diproses.',
        'status_sekarang' => $nasabah->login
      ], 409);

      return;
    }

    $waktu_penolakan = date('Y-m-d H:i:s');

    /*
     * Pendaftar tidak dihapus agar jejak keputusan tetap ada.
     */
    $this->db->where('id', $id_nasabah);
    $updated = $this->db->update('tb_user', [
      'login'              => 'Ditolak',
      'diverifikasi_oleh'  => (int) $auth->id_user,
      'diverifikasi_pada'  => $waktu_penolakan
    ]);

    if (!$updated || $this->db->trans_status() === false) {
      $database_error = $this->db->error();
      $this->db->trans_rollback();

      log_message(
        'error',
        'Gagal menolak pendaftar: ' .
          json_encode($database_error)
      );

      $this->api_response([
        'status'  => false,
        'message' => 'Pendaftaran gagal ditolak.'
      ], 500);

      return;
    }

    $this->db->trans_commit();

    $this->api_response([
      'status'  => true,
      'message' => 'Pendaftaran nasabah berhasil ditolak.',
      'data'    => [
        'id_nasabah'       => $id_nasabah,
        'nama_nasabah'     => $nasabah->nama,
        'username'          => $nasabah->username,
        'status_sebelumnya' => 'Tidak',
        'status_sekarang'   => 'Ditolak',
        'cabang_id'         => (int) $nasabah->cabang_id,
        'kode_cabang'       => $nasabah->kode_cabang,
        'nama_cabang'       => $nasabah->nama_cabang,
        'diproses_oleh'     => (int) $auth->id_user,
        'nama_operator'     => $auth->nama,
        'diproses_pada'     => $waktu_penolakan
      ]
    ]);
  }

  public function tambah_nasabah()
  {
    header('Access-Control-Allow-Origin: *');
    header('Content-Type: application/json; charset=UTF-8');
    header('Access-Control-Allow-Methods: POST');

    if ($this->input->method(TRUE) !== 'POST') {
      $this->api_response([
        'status'  => false,
        'message' => 'Metode request tidak diizinkan.'
      ], 405);
      return;
    }

    // Wajib menggunakan Bearer token yang aktif.
    $auth = $this->authenticate_api();

    if (!$auth) {
      return;
    }

    // Hanya Administrator dan Super Admin.
    if (!in_array($auth->level, ['Administrator', 'Super Admin'], true)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Anda tidak memiliki izin untuk menambahkan nasabah.'
      ], 403);
      return;
    }

    // Batasi ukuran request JSON.
    $content_length = (int) $this->input->server('CONTENT_LENGTH');

    if ($content_length > 65536) {
      $this->api_response([
        'status'  => false,
        'message' => 'Ukuran data terlalu besar.'
      ], 413);
      return;
    }

    $json = file_get_contents('php://input');
    $data = json_decode($json, true);

    if (!is_array($data)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Format JSON tidak valid.'
      ], 400);
      return;
    }

    $nama = isset($data['nama'])
      ? trim((string) $data['nama'])
      : '';

    $username = isset($data['username'])
      ? trim((string) $data['username'])
      : '';

    $password = isset($data['password'])
      ? (string) $data['password']
      : '';

    // Mendukung nama field lama dan baru.
    $jenis_kelamin = isset($data['jenis_kelamin'])
      ? trim((string) $data['jenis_kelamin'])
      : (
        isset($data['jenisKelamin'])
        ? trim((string) $data['jenisKelamin'])
        : 'Laki-Laki'
      );

    $telp = isset($data['telp'])
      ? trim((string) $data['telp'])
      : '';

    $email = isset($data['email'])
      ? trim((string) $data['email'])
      : '';

    $alamat = isset($data['alamat'])
      ? trim((string) $data['alamat'])
      : '';

    if ($nama === '' || $username === '' || $password === '') {
      $this->api_response([
        'status'  => false,
        'message' => 'Nama, username, dan password wajib diisi.'
      ], 422);
      return;
    }

    if (strlen($nama) < 3 || strlen($nama) > 100) {
      $this->api_response([
        'status'  => false,
        'message' => 'Nama harus terdiri dari 3 sampai 100 karakter.'
      ], 422);
      return;
    }

    if (
      strlen($username) < 4 ||
      strlen($username) > 50 ||
      !preg_match('/^[A-Za-z0-9._-]+$/', $username)
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Username harus terdiri dari 4 sampai 50 karakter dan hanya boleh berisi huruf, angka, titik, garis bawah, atau tanda hubung.'
      ], 422);
      return;
    }

    if (strlen($password) < 8 || strlen($password) > 72) {
      $this->api_response([
        'status'  => false,
        'message' => 'Password harus terdiri dari 8 sampai 72 karakter.'
      ], 422);
      return;
    }

    if (!in_array($jenis_kelamin, ['Laki-Laki', 'Perempuan'], true)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Jenis kelamin tidak valid.'
      ], 422);
      return;
    }

    if ($telp !== '' && !preg_match('/^[0-9+]{8,20}$/', $telp)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Format nomor telepon tidak valid.'
      ], 422);
      return;
    }

    if ($email !== '' && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Format email tidak valid.'
      ], 422);
      return;
    }

    /*
     * Administrator selalu menggunakan cabangnya sendiri.
     * cabang_id dan id_admin dari request tidak dipercaya.
     */
    if ($auth->level === 'Administrator') {
      $cabang_id = (int) $auth->cabang_id;
    } else {
      // Super Admin diperbolehkan menentukan cabang.
      $cabang_id = isset($data['cabang_id'])
        ? (int) $data['cabang_id']
        : (int) $auth->cabang_id;
    }

    if ($cabang_id <= 0) {
      $this->api_response([
        'status'  => false,
        'message' => 'Cabang nasabah wajib dipilih.'
      ], 422);
      return;
    }

    // Pastikan cabang tersedia dan aktif.
    $cabang = $this->db
      ->select('id, kode, nama, status')
      ->where('id', $cabang_id)
      ->where('status', 'Aktif')
      ->get('tb_cabang')
      ->row();

    if (!$cabang) {
      $this->api_response([
        'status'  => false,
        'message' => 'Cabang tidak ditemukan atau sedang tidak aktif.'
      ], 422);
      return;
    }

    // Perlindungan tambahan untuk Administrator.
    if (
      $auth->level === 'Administrator' &&
      (int) $auth->cabang_id !== (int) $cabang->id
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Administrator hanya dapat menambahkan nasabah pada cabangnya sendiri.'
      ], 403);
      return;
    }

    $cek_username = $this->db
      ->select('id')
      ->where('username', $username)
      ->limit(1)
      ->get('tb_user')
      ->row();

    if ($cek_username) {
      $this->api_response([
        'status'  => false,
        'message' => 'Username sudah terdaftar. Silakan gunakan username lain.'
      ], 409);
      return;
    }

    $waktu_sekarang = date('Y-m-d H:i:s');

    $insert_data = [
      'nama'                => $nama,
      'jenisKelamin'        => $jenis_kelamin,
      'telp'                => $telp,
      'email'               => $email,
      'alamat'              => $alamat,
      'username'            => $username,
      'password'            => password_hash($password, PASSWORD_BCRYPT),
      'foto'                => 'no-image.png',
      'skin'                => 'green',
      'level'               => 'Nasabah',
      'login'               => 'Ya',
      'cabang_id'           => (int) $cabang->id,
      'diverifikasi_oleh'    => (int) $auth->id_user,
      'diverifikasi_pada'    => $waktu_sekarang,
      'terdaftar'           => $waktu_sekarang
    ];

    $this->db->trans_begin();

    $insert = $this->db->insert('tb_user', $insert_data);
    $id_user_baru = (int) $this->db->insert_id();

    if (!$insert || $this->db->trans_status() === false) {
      $this->db->trans_rollback();

      // Termasuk kemungkinan username duplikat akibat request bersamaan.
      $this->api_response([
        'status'  => false,
        'message' => 'Nasabah gagal ditambahkan.'
      ], 500);
      return;
    }

    $this->db->trans_commit();

    $this->api_response([
      'status'  => true,
      'message' => 'Nasabah berhasil ditambahkan dan akun langsung aktif.',
      'data'    => [
        'id_user'              => $id_user_baru,
        'nama'                 => $nama,
        'username'             => $username,
        'level'                => 'Nasabah',
        'status_akun'          => 'Aktif',
        'cabang_id'            => (int) $cabang->id,
        'kode_cabang'          => $cabang->kode,
        'nama_cabang'          => $cabang->nama,
        'ditambahkan_oleh'     => (int) $auth->id_user,
        'nama_operator'        => $auth->nama,
        'diverifikasi_pada'    => $waktu_sekarang
      ]
    ], 201);
  }

  // 🔥 FUNGSI INFAQ YANG SUDAH DILENGKAPI NOTIFIKASI WA & PUSH 🔥
  public function simpan_infaq()
  {
    header('Access-Control-Allow-Origin: *');
    header('Content-Type: application/json; charset=UTF-8');
    header('Access-Control-Allow-Methods: POST');

    if ($this->input->method(TRUE) !== 'POST') {
      $this->api_response([
        'status'  => false,
        'message' => 'Metode request tidak diizinkan.'
      ], 405);
      return;
    }

    $auth = $this->authenticate_api();

    if (!$auth) {
      return;
    }

    // Infaq hanya dilakukan oleh Nasabah dari saldo miliknya sendiri.
    if ($auth->level !== 'Nasabah') {
      $this->api_response([
        'status'  => false,
        'message' => 'Infaq hanya dapat dilakukan oleh akun Nasabah.'
      ], 403);
      return;
    }

    $content_length = (int) $this->input->server('CONTENT_LENGTH');

    if ($content_length > 32768) {
      $this->api_response([
        'status'  => false,
        'message' => 'Ukuran data terlalu besar.'
      ], 413);
      return;
    }

    $json = file_get_contents('php://input');
    $data = json_decode($json, true);

    if (!is_array($data)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Format JSON tidak valid.'
      ], 400);
      return;
    }

    if (!isset($data['nominal'])) {
      $this->api_response([
        'status'  => false,
        'message' => 'Nominal infaq wajib diisi.'
      ], 422);
      return;
    }

    /*
     * Mendukung nominal seperti:
     * 10000
     * "10000"
     * "10.000"
     */
    $nominal_text = trim((string) $data['nominal']);
    $nominal_text = preg_replace('/[.\s]/', '', $nominal_text);

    if (
      $nominal_text === '' ||
      !ctype_digit($nominal_text)
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Nominal infaq harus berupa angka bulat.'
      ], 422);
      return;
    }

    $nominal = (int) $nominal_text;

    if ($nominal < 1) {
      $this->api_response([
        'status'  => false,
        'message' => 'Nominal infaq harus lebih besar dari nol.'
      ], 422);
      return;
    }

    if ($nominal > 1000000000) {
      $this->api_response([
        'status'  => false,
        'message' => 'Nominal infaq melebihi batas yang diperbolehkan.'
      ], 422);
      return;
    }

    $keterangan = isset($data['keterangan'])
      ? trim((string) $data['keterangan'])
      : 'Infaq Umum';

    if ($keterangan === '') {
      $keterangan = 'Infaq Umum';
    }

    if (strlen($keterangan) > 200) {
      $this->api_response([
        'status'  => false,
        'message' => 'Keterangan maksimal 200 karakter.'
      ], 422);
      return;
    }

    /*
     * id_nasabah dan id_admin dari request sengaja tidak digunakan.
     * Identitas nasabah selalu berasal dari Bearer token.
     */
    $id_nasabah = (int) $auth->id_user;

    $this->db->trans_begin();

    /*
     * Kunci baris pengguna agar proses saldo bersamaan untuk nasabah
     * yang sama tidak menyebabkan saldo terpakai dua kali.
     */
    $nasabah = $this->db->query(
      "SELECT id, nama, level, login, cabang_id, expo_token
         FROM tb_user
         WHERE id = ?
         LIMIT 1
         FOR UPDATE",
      [$id_nasabah]
    )->row();

    if (
      !$nasabah ||
      $nasabah->level !== 'Nasabah' ||
      $nasabah->login !== 'Ya'
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Akun Nasabah tidak ditemukan atau tidak aktif.'
      ], 403);
      return;
    }

    $cabang = $this->db
      ->select('id, kode, nama, status')
      ->where('id', (int) $nasabah->cabang_id)
      ->where('status', 'Aktif')
      ->get('tb_cabang')
      ->row();

    if (!$cabang) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Cabang Nasabah tidak ditemukan atau tidak aktif.'
      ], 422);
      return;
    }

    // Hitung saldo dari transaksi yang sudah sukses.
    $saldo_transaksi = $this->db->query(
      "SELECT COALESCE(
            SUM(
                CASE
                    WHEN jenis = 'Masuk' THEN nominal
                    WHEN jenis = 'Keluar' THEN -nominal
                    ELSE 0
                END
            ),
            0
        ) AS total
        FROM tb_transaksi
        WHERE idNasabah = ?
          AND status_konfirmasi = 'Sukses'",
      [$id_nasabah]
    )->row();

    /*
     * Kolom nominal pada tb_transfer masih bertipe varchar,
     * sehingga dikonversi saat perhitungan.
     */
    $saldo_transfer = $this->db->query(
      "SELECT COALESCE(
            SUM(
                CASE
                    WHEN idPenerima = ? THEN
                        CAST(nominal AS DECIMAL(20,2))
                    WHEN idPengirim = ? THEN
                        -CAST(nominal AS DECIMAL(20,2))
                    ELSE 0
                END
            ),
            0
        ) AS total
        FROM tb_transfer
        WHERE status_transfer = 'Sukses'
          AND (idPenerima = ? OR idPengirim = ?)",
      [
        $id_nasabah,
        $id_nasabah,
        $id_nasabah,
        $id_nasabah
      ]
    )->row();

    $total_transaksi = $saldo_transaksi
      ? (float) $saldo_transaksi->total
      : 0;

    $total_transfer = $saldo_transfer
      ? (float) $saldo_transfer->total
      : 0;

    $saldo_sebelum = $total_transaksi + $total_transfer;

    if ($saldo_sebelum < $nominal) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Saldo tidak mencukupi untuk melakukan infaq.',
        'data'    => [
          'saldo_tersedia' => (int) $saldo_sebelum,
          'nominal_infaq'  => $nominal
        ]
      ], 422);
      return;
    }

    $waktu_sekarang = date('Y-m-d H:i:s');

    $insert_data = [
      // Aktor berasal dari token, bukan request.
      'idAdmin'           => $id_nasabah,
      'idNasabah'         => $id_nasabah,
      'idPotongan'        => 0,
      'cabang_id'         => (int) $cabang->id,
      'tanggal'           => date('Y-m-d'),
      'nominal'           => $nominal,
      'jenis'             => 'Keluar',
      'keterangan'        => 'INFAQ: ' . $keterangan,
      'status_konfirmasi' => 'Sukses',
      'terdaftar'         => $waktu_sekarang
    ];

    $insert = $this->db->insert('tb_transaksi', $insert_data);
    $id_transaksi = (int) $this->db->insert_id();

    if (!$insert || $this->db->trans_status() === false) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Gagal memproses infaq.'
      ], 500);
      return;
    }

    $this->db->trans_commit();

    $saldo_sesudah = $saldo_sebelum - $nominal;
    $nominal_format = 'Rp ' . number_format($nominal, 0, ',', '.');

    /*
     * Notifikasi hanya dikirim kepada Administrator cabang terkait
     * dan semua Super Admin yang memiliki Expo token.
     */
    $this->db->group_start();
    $this->db->where('level', 'Super Admin');

    $this->db->or_group_start();
    $this->db->where('level', 'Administrator');
    $this->db->where('cabang_id', (int) $cabang->id);
    $this->db->group_end();
    $this->db->group_end();

    $this->db->where('login', 'Ya');
    $this->db->where('expo_token IS NOT NULL', null, false);
    $this->db->where('expo_token !=', '');

    $admins = $this->db->get('tb_user')->result();

    foreach ($admins as $admin) {
      $this->send_expo_push_notification(
        $admin->expo_token,
        "\u{1F4B0} Infaq Baru Masuk",
        "\u{1F64F} Infaq dari " . $nasabah->nama .
          ' sebesar ' . $nominal_format .
          ' telah diterima.'
      );
    }

    // Notifikasi apresiasi kepada Nasabah.
    if (!empty($nasabah->expo_token)) {
      $this->send_expo_push_notification(
        $nasabah->expo_token,
        "\u{2705} Alhamdulillah, Infaq Berhasil",
        "\u{1F49A} Terima kasih atas infaq sebesar " .
          $nominal_format .
          '. Semoga menjadi amal jariyah.'
      );
    }

    $this->api_response([
      'status'  => true,
      'message' => "\u{1F64F} Alhamdulillah, infaq berhasil disalurkan.",
      'data'    => [
        'id_transaksi'  => $id_transaksi,
        'id_nasabah'    => $id_nasabah,
        'nama_nasabah'  => $nasabah->nama,
        'jenis'         => 'Keluar',
        'nominal'       => $nominal,
        'keterangan'    => 'INFAQ: ' . $keterangan,
        'status'        => 'Sukses',
        'cabang_id'     => (int) $cabang->id,
        'kode_cabang'   => $cabang->kode,
        'nama_cabang'   => $cabang->nama,
        'saldo_sebelum' => (int) $saldo_sebelum,
        'saldo_sesudah' => (int) $saldo_sesudah
      ]
    ], 201);
  }

  // ==========================================
  // 11. ENDPOINT TARGET TABUNGAN (CELENGAN IMPIAN)
  // ==========================================

  // A. Mengambil daftar target milik nasabah
  public function get_target()
  {
    header('Access-Control-Allow-Origin: *');
    header('Content-Type: application/json; charset=UTF-8');
    header('Access-Control-Allow-Methods: POST');

    if ($this->input->method(TRUE) !== 'POST') {
      $this->api_response([
        'status'  => false,
        'message' => 'Metode request tidak diizinkan.'
      ], 405);
      return;
    }

    $auth = $this->authenticate_api();

    if (!$auth) {
      return;
    }

    if ($auth->level !== 'Nasabah') {
      $this->api_response([
        'status'  => false,
        'message' => 'Endpoint ini hanya dapat digunakan oleh Nasabah.'
      ], 403);
      return;
    }

    /*
     * id_nasabah dari request sengaja diabaikan.
     * Target selalu diambil berdasarkan pemilik Bearer token.
     */
    $id_nasabah = (int) $auth->id_user;

    $data = $this->db
      ->where('id_nasabah', $id_nasabah)
      ->order_by('id', 'DESC')
      ->get('tb_target')
      ->result_array();

    $formatted_data = [];

    foreach ($data as $row) {
      $nominal_target = (float) $row['nominal_target'];
      $terkumpul = (float) $row['terkumpul'];

      $persentase = $nominal_target > 0
        ? ($terkumpul / $nominal_target) * 100
        : 0;

      $row['nominal_target'] = (int) $nominal_target;
      $row['terkumpul'] = (int) $terkumpul;
      $row['persentase'] = round($persentase, 1);
      $row['tercapai'] = $nominal_target > 0 &&
        $terkumpul >= $nominal_target;

      $formatted_data[] = $row;
    }

    $this->api_response([
      'status'      => true,
      'id_nasabah' => $id_nasabah,
      'jumlah'      => count($formatted_data),
      'data'        => $formatted_data
    ]);
  }

  // B. Membuat target baru
  public function simpan_target()
  {
    header('Access-Control-Allow-Origin: *');
    header('Content-Type: application/json; charset=UTF-8');
    header('Access-Control-Allow-Methods: POST');

    if ($this->input->method(TRUE) !== 'POST') {
      $this->api_response([
        'status'  => false,
        'message' => 'Metode request tidak diizinkan.'
      ], 405);
      return;
    }

    $auth = $this->authenticate_api();

    if (!$auth) {
      return;
    }

    if ($auth->level !== 'Nasabah') {
      $this->api_response([
        'status'  => false,
        'message' => 'Target tabungan hanya dapat dibuat oleh Nasabah.'
      ], 403);
      return;
    }

    $content_length = (int) $this->input->server('CONTENT_LENGTH');

    if ($content_length > 32768) {
      $this->api_response([
        'status'  => false,
        'message' => 'Ukuran data terlalu besar.'
      ], 413);
      return;
    }

    $request = json_decode($this->input->raw_input_stream, true);

    if (!is_array($request)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Format JSON tidak valid.'
      ], 400);
      return;
    }

    $nama_target = isset($request['nama_target'])
      ? trim((string) $request['nama_target'])
      : '';

    $nominal_text = isset($request['nominal_target'])
      ? trim((string) $request['nominal_target'])
      : '';

    // Mendukung nominal 1000000 dan "1.000.000".
    $nominal_text = preg_replace('/[.\s]/', '', $nominal_text);

    if (
      strlen($nama_target) < 3 ||
      strlen($nama_target) > 100
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Nama target harus terdiri dari 3 sampai 100 karakter.'
      ], 422);
      return;
    }

    if (
      $nominal_text === '' ||
      !ctype_digit($nominal_text)
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Nominal target harus berupa angka bulat.'
      ], 422);
      return;
    }

    $nominal_target = (int) $nominal_text;

    if ($nominal_target < 1000) {
      $this->api_response([
        'status'  => false,
        'message' => 'Nominal target minimal Rp1.000.'
      ], 422);
      return;
    }

    if ($nominal_target > 10000000000) {
      $this->api_response([
        'status'  => false,
        'message' => 'Nominal target melebihi batas yang diperbolehkan.'
      ], 422);
      return;
    }

    /*
     * id_nasabah dari request tidak digunakan.
     * Pemilik target selalu berasal dari Bearer token.
     */
    $id_nasabah = (int) $auth->id_user;

    $nasabah = $this->db
      ->select('id, nama, level, login, cabang_id')
      ->where('id', $id_nasabah)
      ->where('level', 'Nasabah')
      ->where('login', 'Ya')
      ->limit(1)
      ->get('tb_user')
      ->row();

    if (!$nasabah) {
      $this->api_response([
        'status'  => false,
        'message' => 'Akun Nasabah tidak ditemukan atau tidak aktif.'
      ], 403);
      return;
    }

    // Batasi jumlah target agar endpoint tidak disalahgunakan.
    $jumlah_target = $this->db
      ->where('id_nasabah', $id_nasabah)
      ->count_all_results('tb_target');

    if ($jumlah_target >= 20) {
      $this->api_response([
        'status'  => false,
        'message' => 'Maksimal 20 target tabungan untuk setiap Nasabah.'
      ], 422);
      return;
    }

    $data_target = [
      'id_nasabah'    => $id_nasabah,
      'nama_target'   => $nama_target,
      'nominal_target' => $nominal_target,
      'terkumpul'     => 0,
      'terdaftar'     => date('Y-m-d H:i:s')
    ];

    $insert = $this->db->insert('tb_target', $data_target);

    if (!$insert) {
      $this->api_response([
        'status'  => false,
        'message' => 'Gagal membuat target tabungan.'
      ], 500);
      return;
    }

    $id_target = (int) $this->db->insert_id();

    $this->api_response([
      'status'  => true,
      'message' => "\u{1F3AF} Target tabungan berhasil dibuat. Ayo semangat menabung!",
      'data'    => [
        'id_target'      => $id_target,
        'id_nasabah'     => $id_nasabah,
        'nama_nasabah'   => $nasabah->nama,
        'nama_target'    => $nama_target,
        'nominal_target' => $nominal_target,
        'terkumpul'      => 0,
        'persentase'     => 0,
        'cabang_id'      => (int) $nasabah->cabang_id
      ]
    ], 201);
  }
  // C. Top Up Target (Isi Celengan)
  public function topup_target()
  {
    header('Access-Control-Allow-Origin: *');
    header('Content-Type: application/json; charset=UTF-8');
    header('Access-Control-Allow-Methods: POST');

    if ($this->input->method(TRUE) !== 'POST') {
      $this->api_response([
        'status'  => false,
        'message' => 'Metode request tidak diizinkan.'
      ], 405);
      return;
    }

    $auth = $this->authenticate_api();

    if (!$auth) {
      return;
    }

    if ($auth->level !== 'Nasabah') {
      $this->api_response([
        'status'  => false,
        'message' => 'Target tabungan hanya dapat diisi oleh Nasabah.'
      ], 403);
      return;
    }

    $request = json_decode($this->input->raw_input_stream, true);

    if (!is_array($request)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Format JSON tidak valid.'
      ], 400);
      return;
    }

    $id_target = isset($request['id_target'])
      ? (int) $request['id_target']
      : 0;

    $nominal_text = isset($request['nominal'])
      ? trim((string) $request['nominal'])
      : '';

    $nominal_text = preg_replace('/[.\s]/', '', $nominal_text);

    if ($id_target <= 0) {
      $this->api_response([
        'status'  => false,
        'message' => 'ID target tidak valid.'
      ], 422);
      return;
    }

    if (
      $nominal_text === '' ||
      !ctype_digit($nominal_text)
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Nominal top-up harus berupa angka bulat.'
      ], 422);
      return;
    }

    $nominal = (int) $nominal_text;

    if ($nominal < 1) {
      $this->api_response([
        'status'  => false,
        'message' => 'Nominal top-up harus lebih besar dari nol.'
      ], 422);
      return;
    }

    if ($nominal > 1000000000) {
      $this->api_response([
        'status'  => false,
        'message' => 'Nominal top-up melebihi batas yang diperbolehkan.'
      ], 422);
      return;
    }

    /*
     * id_nasabah dari request diabaikan.
     * Pemilik selalu ditentukan dari Bearer token.
     */
    $id_nasabah = (int) $auth->id_user;

    $this->db->trans_begin();

    // Kunci akun Nasabah untuk mencegah penggunaan saldo bersamaan.
    $nasabah = $this->db->query(
      "SELECT id, nama, level, login, cabang_id
         FROM tb_user
         WHERE id = ?
         LIMIT 1
         FOR UPDATE",
      [$id_nasabah]
    )->row();

    if (
      !$nasabah ||
      $nasabah->level !== 'Nasabah' ||
      $nasabah->login !== 'Ya'
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Akun Nasabah tidak ditemukan atau tidak aktif.'
      ], 403);
      return;
    }

    /*
     * Target hanya dapat diambil jika memang dimiliki Nasabah token.
     * Sekaligus dikunci agar tidak dapat di-top-up atau dihapus bersamaan.
     */
    $target = $this->db->query(
      "SELECT id, id_nasabah, nama_target, nominal_target, terkumpul
         FROM tb_target
         WHERE id = ?
           AND id_nasabah = ?
         LIMIT 1
         FOR UPDATE",
      [$id_target, $id_nasabah]
    )->row();

    if (!$target) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Target tidak ditemukan atau bukan milik Anda.'
      ], 404);
      return;
    }

    $nominal_target = (float) $target->nominal_target;
    $terkumpul_sebelum = (float) $target->terkumpul;
    $sisa_target = $nominal_target - $terkumpul_sebelum;

    if ($sisa_target <= 0) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Target tabungan sudah tercapai.'
      ], 422);
      return;
    }

    if ($nominal > $sisa_target) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Nominal top-up melebihi sisa target.',
        'data'    => [
          'sisa_target'     => (int) $sisa_target,
          'nominal_dikirim' => $nominal
        ]
      ], 422);
      return;
    }

    // Hitung saldo transaksi yang telah sukses.
    $saldo_transaksi = $this->db->query(
      "SELECT COALESCE(
            SUM(
                CASE
                    WHEN jenis = 'Masuk' THEN nominal
                    WHEN jenis = 'Keluar' THEN -nominal
                    ELSE 0
                END
            ),
            0
        ) AS total
        FROM tb_transaksi
        WHERE idNasabah = ?
          AND status_konfirmasi = 'Sukses'",
      [$id_nasabah]
    )->row();

    // Hitung saldo transfer yang telah sukses.
    $saldo_transfer = $this->db->query(
      "SELECT COALESCE(
            SUM(
                CASE
                    WHEN idPenerima = ? THEN
                        CAST(nominal AS DECIMAL(20,2))
                    WHEN idPengirim = ? THEN
                        -CAST(nominal AS DECIMAL(20,2))
                    ELSE 0
                END
            ),
            0
        ) AS total
        FROM tb_transfer
        WHERE status_transfer = 'Sukses'
          AND (idPenerima = ? OR idPengirim = ?)",
      [
        $id_nasabah,
        $id_nasabah,
        $id_nasabah,
        $id_nasabah
      ]
    )->row();

    $total_transaksi = $saldo_transaksi
      ? (float) $saldo_transaksi->total
      : 0;

    $total_transfer = $saldo_transfer
      ? (float) $saldo_transfer->total
      : 0;

    $saldo_sebelum = $total_transaksi + $total_transfer;

    if ($saldo_sebelum < $nominal) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Saldo tidak mencukupi untuk mengisi target.',
        'data'    => [
          'saldo_tersedia' => (int) $saldo_sebelum,
          'nominal_topup'  => $nominal
        ]
      ], 422);
      return;
    }

    $waktu_sekarang = date('Y-m-d H:i:s');

    $insert_transaksi = [
      'idAdmin'           => $id_nasabah,
      'idNasabah'         => $id_nasabah,
      'idPotongan'        => 0,
      'cabang_id'         => (int) $nasabah->cabang_id,
      'tanggal'           => date('Y-m-d'),
      'nominal'           => $nominal,
      'jenis'             => 'Keluar',
      'keterangan'        => 'Isi Tabungan: ' . $target->nama_target,
      'status_konfirmasi' => 'Sukses',
      'terdaftar'         => $waktu_sekarang
    ];

    $insert = $this->db->insert(
      'tb_transaksi',
      $insert_transaksi
    );

    $id_transaksi = (int) $this->db->insert_id();
    $terkumpul_baru = $terkumpul_sebelum + $nominal;

    $this->db
      ->where('id', $id_target)
      ->where('id_nasabah', $id_nasabah)
      ->update('tb_target', [
        'terkumpul' => $terkumpul_baru
      ]);

    if (!$insert || $this->db->trans_status() === false) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Gagal mengisi target tabungan.'
      ], 500);
      return;
    }

    $this->db->trans_commit();

    $saldo_sesudah = $saldo_sebelum - $nominal;
    $persentase = $nominal_target > 0
      ? ($terkumpul_baru / $nominal_target) * 100
      : 0;

    $this->api_response([
      'status'  => true,
      'message' => "\u{1F4B0} Alhamdulillah, target tabungan berhasil diisi!",
      'data'    => [
        'id_transaksi'     => $id_transaksi,
        'id_target'        => (int) $target->id,
        'id_nasabah'       => $id_nasabah,
        'nama_target'      => $target->nama_target,
        'nominal_topup'    => $nominal,
        'nominal_target'   => (int) $nominal_target,
        'terkumpul_sebelum' => (int) $terkumpul_sebelum,
        'terkumpul_sesudah' => (int) $terkumpul_baru,
        'persentase'       => round($persentase, 1),
        'target_tercapai'  => $terkumpul_baru >= $nominal_target,
        'saldo_sebelum'    => (int) $saldo_sebelum,
        'saldo_sesudah'    => (int) $saldo_sesudah,
        'cabang_id'        => (int) $nasabah->cabang_id
      ]
    ], 201);
  }

  // D. Hapus Target (Celengan) & Refund Saldo
  public function hapus_target()
  {
    header('Access-Control-Allow-Origin: *');
    header('Content-Type: application/json; charset=UTF-8');
    header('Access-Control-Allow-Methods: POST');

    if ($this->input->method(TRUE) !== 'POST') {
      $this->api_response([
        'status'  => false,
        'message' => 'Metode request tidak diizinkan.'
      ], 405);
      return;
    }

    $auth = $this->authenticate_api();

    if (!$auth) {
      return;
    }

    if ($auth->level !== 'Nasabah') {
      $this->api_response([
        'status'  => false,
        'message' => 'Target tabungan hanya dapat dihapus oleh Nasabah.'
      ], 403);
      return;
    }

    $request = json_decode($this->input->raw_input_stream, true);

    if (!is_array($request)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Format JSON tidak valid.'
      ], 400);
      return;
    }

    $id_target = isset($request['id_target'])
      ? (int) $request['id_target']
      : 0;

    if ($id_target <= 0) {
      $this->api_response([
        'status'  => false,
        'message' => 'ID target tidak valid.'
      ], 422);
      return;
    }

    $id_nasabah = (int) $auth->id_user;

    $this->db->trans_begin();

    /*
     * Kunci akun Nasabah agar refund tidak berbenturan dengan
     * proses saldo lainnya.
     */
    $nasabah = $this->db->query(
      "SELECT id, nama, level, login, cabang_id
         FROM tb_user
         WHERE id = ?
         LIMIT 1
         FOR UPDATE",
      [$id_nasabah]
    )->row();

    if (
      !$nasabah ||
      $nasabah->level !== 'Nasabah' ||
      $nasabah->login !== 'Ya'
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Akun Nasabah tidak ditemukan atau tidak aktif.'
      ], 403);
      return;
    }

    /*
     * Target hanya ditemukan jika dimiliki pengguna token.
     * FOR UPDATE mencegah target dihapus dan di-top-up bersamaan.
     */
    $target = $this->db->query(
      "SELECT id, id_nasabah, nama_target, nominal_target, terkumpul
         FROM tb_target
         WHERE id = ?
           AND id_nasabah = ?
         LIMIT 1
         FOR UPDATE",
      [$id_target, $id_nasabah]
    )->row();

    if (!$target) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Target tidak ditemukan atau bukan milik Anda.'
      ], 404);
      return;
    }

    $dana_refund = max(0, (float) $target->terkumpul);
    $id_transaksi_refund = null;
    $waktu_sekarang = date('Y-m-d H:i:s');

    /*
     * Jika target memiliki dana, buat transaksi masuk sebagai refund.
     * Refund dan penghapusan berada dalam satu transaksi database.
     */
    if ($dana_refund > 0) {
      $insert_refund = $this->db->insert('tb_transaksi', [
        'idAdmin'           => $id_nasabah,
        'idNasabah'         => $id_nasabah,
        'idPotongan'        => 0,
        'cabang_id'         => (int) $nasabah->cabang_id,
        'tanggal'           => date('Y-m-d'),
        'nominal'           => $dana_refund,
        'jenis'             => 'Masuk',
        'keterangan'        => 'Refund Hapus Target: ' .
          $target->nama_target,
        'status_konfirmasi' => 'Sukses',
        'terdaftar'         => $waktu_sekarang
      ]);

      $id_transaksi_refund = (int) $this->db->insert_id();

      if (!$insert_refund) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Gagal mengembalikan dana target.'
        ], 500);
        return;
      }
    }

    $delete = $this->db
      ->where('id', $id_target)
      ->where('id_nasabah', $id_nasabah)
      ->delete('tb_target');

    if (!$delete || $this->db->trans_status() === false) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Gagal menghapus target tabungan.'
      ], 500);
      return;
    }

    $this->db->trans_commit();

    $message = $dana_refund > 0
      ? "\u{267B}\u{FE0F} Target berhasil dihapus dan dana telah dikembalikan ke saldo utama."
      : "\u{1F5D1}\u{FE0F} Target tabungan berhasil dihapus.";

    $this->api_response([
      'status'  => true,
      'message' => $message,
      'data'    => [
        'id_target'             => (int) $target->id,
        'id_nasabah'            => $id_nasabah,
        'nama_target'           => $target->nama_target,
        'dana_dikembalikan'     => (int) $dana_refund,
        'id_transaksi_refund'   => $id_transaksi_refund,
        'cabang_id'             => (int) $nasabah->cabang_id,
        'dihapus_oleh'          => $id_nasabah,
        'waktu_penghapusan'     => $waktu_sekarang
      ]
    ]);
  }
  // ==========================================
  // E. Ambil Semua Target Untuk Admin (Pantau Target)
  // ==========================================
  public function get_all_target()
  {
    header('Access-Control-Allow-Origin: *');
    header('Content-Type: application/json; charset=UTF-8');
    header('Access-Control-Allow-Methods: POST');

    if ($this->input->method(TRUE) !== 'POST') {
      $this->api_response([
        'status'  => false,
        'message' => 'Metode request tidak diizinkan.'
      ], 405);
      return;
    }

    $auth = $this->authenticate_api();

    if (!$auth) {
      return;
    }

    /*
     * Level dari request tidak digunakan.
     * Hak akses selalu berasal dari Bearer token.
     */
    if (!in_array($auth->level, ['Administrator', 'Super Admin'], true)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Anda tidak memiliki izin untuk melihat seluruh target.'
      ], 403);
      return;
    }

    $this->db->select(
      'tb_target.*, ' .
        'tb_user.nama AS nama_nasabah, ' .
        'tb_user.username, ' .
        'tb_user.cabang_id, ' .
        'tb_cabang.kode AS kode_cabang, ' .
        'tb_cabang.nama AS nama_cabang'
    );

    $this->db->from('tb_target');
    $this->db->join(
      'tb_user',
      'tb_target.id_nasabah = tb_user.id',
      'inner'
    );
    $this->db->join(
      'tb_cabang',
      'tb_user.cabang_id = tb_cabang.id',
      'left'
    );

    $this->db->where('tb_user.level', 'Nasabah');

    // Administrator hanya dapat melihat Nasabah cabangnya sendiri.
    if ($auth->level === 'Administrator') {
      $this->db->where(
        'tb_user.cabang_id',
        (int) $auth->cabang_id
      );
    }

    $this->db->order_by('tb_target.id', 'DESC');

    $data = $this->db->get()->result_array();
    $formatted_data = [];

    foreach ($data as $row) {
      $nominal_target = (float) $row['nominal_target'];
      $terkumpul = (float) $row['terkumpul'];

      $persentase = $nominal_target > 0
        ? ($terkumpul / $nominal_target) * 100
        : 0;

      $row['nominal_target'] = (int) $nominal_target;
      $row['terkumpul'] = (int) $terkumpul;
      $row['cabang_id'] = (int) $row['cabang_id'];
      $row['persentase'] = round($persentase, 1);
      $row['tercapai'] = $nominal_target > 0 &&
        $terkumpul >= $nominal_target;

      $formatted_data[] = $row;
    }

    $this->api_response([
      'status' => true,
      'akses'  => [
        'level'       => $auth->level,
        'cabang_id'   => $auth->level === 'Administrator'
          ? (int) $auth->cabang_id
          : null,
        'cakupan'     => $auth->level === 'Super Admin'
          ? 'Semua cabang'
          : 'Cabang sendiri'
      ],
      'jumlah' => count($formatted_data),
      'data'   => $formatted_data
    ]);
  }

  // ==========================================
  // F. Ambil Saldo Seluruh Nasabah (Khusus Admin)
  // ==========================================
  public function get_all_nasabah_saldo()
  {
    header('Access-Control-Allow-Origin: *');
    header('Content-Type: application/json; charset=UTF-8');
    header('Access-Control-Allow-Methods: POST');

    if ($this->input->method(TRUE) !== 'POST') {
      $this->api_response([
        'status'  => false,
        'message' => 'Metode request tidak diizinkan.'
      ], 405);
      return;
    }

    $auth = $this->authenticate_api();

    if (!$auth) {
      return;
    }

    /*
     * Level, id_admin, dan cabang_id dari request tidak digunakan.
     * Hak akses sepenuhnya berasal dari Bearer token.
     */
    if (!in_array($auth->level, ['Administrator', 'Super Admin'], true)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Anda tidak memiliki izin untuk melihat saldo seluruh Nasabah.'
      ], 403);
      return;
    }

    if (
      $auth->level === 'Administrator' &&
      (int) $auth->cabang_id <= 0
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Administrator belum terhubung dengan cabang yang valid.'
      ], 403);
      return;
    }

    /*
     * Saldo dihitung dalam satu query:
     *
     * transaksi Masuk
     * - transaksi Keluar
     * + transfer Masuk
     * - transfer Keluar
     *
     * Hanya transaksi dan transfer berstatus Sukses.
     */
    $sql = "
        SELECT
            u.id,
            u.nama,
            u.username,
            u.foto,
            u.cabang_id,
            c.kode AS kode_cabang,
            c.nama AS nama_cabang,

                       COALESCE(trx.total_transaksi, 0)
            + COALESCE(tf_masuk.total_transfer_masuk, 0)
            - COALESCE(tf_keluar.total_transfer_keluar, 0)
            AS saldo,

            COALESCE(target_data.total_target, 0)
            AS saldo_target

        FROM tb_user AS u

        LEFT JOIN tb_cabang AS c
            ON c.id = u.cabang_id

        LEFT JOIN (
            SELECT
                idNasabah,
                SUM(
                    CASE
                        WHEN jenis = 'Masuk' THEN nominal
                        WHEN jenis = 'Keluar' THEN -nominal
                        ELSE 0
                    END
                ) AS total_transaksi
            FROM tb_transaksi
            WHERE status_konfirmasi = 'Sukses'
            GROUP BY idNasabah
        ) AS trx
            ON trx.idNasabah = u.id

        LEFT JOIN (
            SELECT
                idPenerima,
                SUM(
                    CAST(nominal AS DECIMAL(20,2))
                ) AS total_transfer_masuk
            FROM tb_transfer
            WHERE status_transfer = 'Sukses'
            GROUP BY idPenerima
        ) AS tf_masuk
            ON tf_masuk.idPenerima = u.id

        LEFT JOIN (
            SELECT
                idPengirim,
                SUM(
                    CAST(nominal AS DECIMAL(20,2))
                ) AS total_transfer_keluar
            FROM tb_transfer
            WHERE status_transfer = 'Sukses'
            GROUP BY idPengirim
        ) AS tf_keluar
            ON tf_keluar.idPengirim = u.id
                    LEFT JOIN (
            SELECT
                id_nasabah,
                SUM(terkumpul) AS total_target
            FROM tb_target
            GROUP BY id_nasabah
        ) AS target_data
            ON target_data.id_nasabah = u.id

        WHERE u.level = 'Nasabah'
          AND u.login = 'Ya'
    ";

    $params = [];

    // Administrator hanya boleh melihat Nasabah cabangnya sendiri.
    if ($auth->level === 'Administrator') {
      $sql .= " AND u.cabang_id = ? ";
      $params[] = (int) $auth->cabang_id;
    }

    $sql .= " ORDER BY u.nama ASC ";

    $nasabah = $this->db
      ->query($sql, $params)
      ->result_array();

    $data_saldo = [];
    $total_saldo_utama = 0;
    $total_target = 0;
    $total_kelolaan = 0;

    foreach ($nasabah as $row) {
      $saldo_utama = (float) $row['saldo'];
      $saldo_target = (float) $row['saldo_target'];
      $saldo_kelolaan = $saldo_utama + $saldo_target;

      $data_saldo[] = [
        'id'                    => (int) $row['id'],
        'nama'                  => $row['nama'],
        'username'              => $row['username'],
        'foto'                  => $row['foto'],

        // Dipertahankan untuk kompatibilitas aplikasi lama.
        'saldo'                 => (int) $saldo_utama,
        'saldo_format'          => 'Rp ' .
          number_format($saldo_utama, 0, ',', '.'),

        'saldo_utama'           => (int) $saldo_utama,
        'saldo_utama_format'    => 'Rp ' .
          number_format($saldo_utama, 0, ',', '.'),

        'saldo_target'          => (int) $saldo_target,
        'saldo_target_format'   => 'Rp ' .
          number_format($saldo_target, 0, ',', '.'),

        'saldo_kelolaan'        => (int) $saldo_kelolaan,
        'saldo_kelolaan_format' => 'Rp ' .
          number_format($saldo_kelolaan, 0, ',', '.'),

        'cabang_id'             => (int) $row['cabang_id'],
        'kode_cabang'           => $row['kode_cabang'],
        'nama_cabang'           => $row['nama_cabang']
      ];

      $total_saldo_utama += $saldo_utama;
      $total_target += $saldo_target;
      $total_kelolaan += $saldo_kelolaan;
    }

    $this->api_response([
      'status' => true,
      'akses'  => [
        'level'     => $auth->level,
        'cabang_id' => $auth->level === 'Administrator'
          ? (int) $auth->cabang_id
          : null,
        'cakupan'   => $auth->level === 'Super Admin'
          ? 'Semua cabang'
          : 'Cabang sendiri'
      ],
      'ringkasan' => [
        'jumlah_nasabah'            => count($data_saldo),

        'total_saldo_utama'         => (int) $total_saldo_utama,
        'total_saldo_utama_format'  => 'Rp ' .
          number_format($total_saldo_utama, 0, ',', '.'),

        'total_target'              => (int) $total_target,
        'total_target_format'       => 'Rp ' .
          number_format($total_target, 0, ',', '.'),

        'total_kelolaan'            => (int) $total_kelolaan,
        'total_kelolaan_format'     => 'Rp ' .
          number_format($total_kelolaan, 0, ',', '.')
      ],
      'data' => $data_saldo
    ]);
  }

  // ==========================================
  // G. Validasi PIN Transaksi 6-Digit
  // ==========================================
  public function cek_pin()
  {
    header('Access-Control-Allow-Origin: *');
    header('Content-Type: application/json; charset=UTF-8');
    header('Access-Control-Allow-Methods: POST');

    if ($this->input->method(TRUE) !== 'POST') {
      $this->api_response([
        'status'  => false,
        'message' => 'Metode request tidak diizinkan.'
      ], 405);
      return;
    }

    $auth = $this->authenticate_api();

    if (!$auth) {
      return;
    }

    if ($auth->level !== 'Nasabah') {
      $this->api_response([
        'status'  => false,
        'message' => 'Validasi PIN hanya dapat dilakukan oleh Nasabah.'
      ], 403);
      return;
    }

    $request = json_decode($this->input->raw_input_stream, true);

    if (!is_array($request)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Format JSON tidak valid.'
      ], 400);
      return;
    }

    $pin = isset($request['pin'])
      ? trim((string) $request['pin'])
      : '';

    if (!preg_match('/^[0-9]{6}$/', $pin)) {
      $this->api_response([
        'status'  => false,
        'message' => 'PIN harus terdiri dari tepat 6 digit angka.'
      ], 422);
      return;
    }

    /*
     * id_user dari request diabaikan.
     * Pengguna selalu ditentukan dari Bearer token.
     */
    $id_user = (int) $auth->id_user;

    $this->db->trans_begin();

    $user = $this->db->query(
      "SELECT
            id,
            level,
            login,
            pin,
            pin_gagal,
            pin_terkunci_sampai
         FROM tb_user
         WHERE id = ?
         LIMIT 1
         FOR UPDATE",
      [$id_user]
    )->row();

    if (
      !$user ||
      $user->level !== 'Nasabah' ||
      $user->login !== 'Ya'
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Akun Nasabah tidak ditemukan atau tidak aktif.'
      ], 403);
      return;
    }

    $waktu_sekarang = time();

    /*
     * Jika masa penguncian belum berakhir, PIN tidak diperiksa.
     */
    if (
      !empty($user->pin_terkunci_sampai) &&
      strtotime($user->pin_terkunci_sampai) > $waktu_sekarang
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Terlalu banyak percobaan PIN. Silakan coba kembali setelah waktu penguncian berakhir.',
        'data'    => [
          'terkunci_sampai' => $user->pin_terkunci_sampai
        ]
      ], 429);
      return;
    }

    /*
     * Apabila masa penguncian sudah lewat, penghitung kesalahan
     * dimulai kembali dari nol.
     */
    $pin_gagal = (int) $user->pin_gagal;

    if (
      !empty($user->pin_terkunci_sampai) &&
      strtotime($user->pin_terkunci_sampai) <= $waktu_sekarang
    ) {
      $pin_gagal = 0;

      $this->db
        ->where('id', $id_user)
        ->update('tb_user', [
          'pin_gagal'           => 0,
          'pin_terkunci_sampai' => null
        ]);
    }

    $pin_tersimpan = (string) $user->pin;

    if ($pin_tersimpan === '') {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'PIN transaksi belum diatur.'
      ], 422);
      return;
    }

    /*
     * PIN bcrypt dikenali dari informasi algoritmanya.
     * PIN teks biasa lama tetap dapat diverifikasi satu kali.
     */
    $info_hash = password_get_info($pin_tersimpan);
    $sudah_hash = isset($info_hash['algo']) &&
      $info_hash['algo'] !== 0;

    if ($sudah_hash) {
      $pin_valid = password_verify($pin, $pin_tersimpan);
    } else {
      $pin_valid = hash_equals($pin_tersimpan, $pin);
    }

    if ($pin_valid) {
      $data_update = [
        'pin_gagal'           => 0,
        'pin_terkunci_sampai' => null
      ];

      /*
         * Migrasikan PIN lama ke bcrypt setelah berhasil,
         * atau rehash apabila pengaturan bcrypt berubah.
         */
      if (
        !$sudah_hash ||
        password_needs_rehash(
          $pin_tersimpan,
          PASSWORD_BCRYPT
        )
      ) {
        $data_update['pin'] = password_hash(
          $pin,
          PASSWORD_BCRYPT
        );
      }

      $this->db
        ->where('id', $id_user)
        ->update('tb_user', $data_update);

      if ($this->db->trans_status() === false) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Gagal memproses validasi PIN.'
        ], 500);
        return;
      }

      $this->db->trans_commit();

      $this->api_response([
        'status'  => true,
        'message' => "\u{2705} PIN valid.",
        'data'    => [
          'id_user'       => $id_user,
          'pin_terlindungi' => true
        ]
      ]);
      return;
    }

    /*
     * PIN salah: tambahkan penghitung.
     * Pada kesalahan kelima, akun dikunci selama 15 menit.
     */
    $pin_gagal++;
    $batas_percobaan = 5;

    if ($pin_gagal >= $batas_percobaan) {
      $terkunci_sampai = date(
        'Y-m-d H:i:s',
        strtotime('+15 minutes')
      );

      $this->db
        ->where('id', $id_user)
        ->update('tb_user', [
          'pin_gagal'           => 0,
          'pin_terkunci_sampai' => $terkunci_sampai
        ]);

      if ($this->db->trans_status() === false) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Gagal memproses validasi PIN.'
        ], 500);
        return;
      }

      $this->db->trans_commit();

      $this->api_response([
        'status'  => false,
        'message' => 'PIN salah lima kali. Validasi PIN dikunci selama 15 menit.',
        'data'    => [
          'terkunci_sampai' => $terkunci_sampai
        ]
      ], 429);
      return;
    }

    $this->db
      ->where('id', $id_user)
      ->update('tb_user', [
        'pin_gagal'           => $pin_gagal,
        'pin_terkunci_sampai' => null
      ]);

    if ($this->db->trans_status() === false) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Gagal memproses validasi PIN.'
      ], 500);
      return;
    }

    $this->db->trans_commit();

    $this->api_response([
      'status'  => false,
      'message' => 'PIN yang Anda masukkan salah.',
      'data'    => [
        'sisa_percobaan' => $batas_percobaan - $pin_gagal
      ]
    ], 401);
  }

  public function ubah_pin()
  {
    header('Access-Control-Allow-Origin: *');
    header('Content-Type: application/json; charset=UTF-8');
    header('Access-Control-Allow-Methods: POST');

    if ($this->input->method(TRUE) !== 'POST') {
      $this->api_response([
        'status'  => false,
        'message' => 'Metode request tidak diizinkan.'
      ], 405);
      return;
    }

    $auth = $this->authenticate_api();

    if (!$auth) {
      return;
    }

    if ($auth->level !== 'Nasabah') {
      $this->api_response([
        'status'  => false,
        'message' => 'Perubahan PIN hanya dapat dilakukan oleh Nasabah.'
      ], 403);
      return;
    }

    $request = json_decode($this->input->raw_input_stream, true);

    if (!is_array($request)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Format JSON tidak valid.'
      ], 400);
      return;
    }

    $pin_lama = isset($request['pin_lama'])
      ? trim((string) $request['pin_lama'])
      : '';

    $pin_baru = isset($request['pin_baru'])
      ? trim((string) $request['pin_baru'])
      : '';

    $konfirmasi_pin_baru = isset($request['konfirmasi_pin_baru'])
      ? trim((string) $request['konfirmasi_pin_baru'])
      : '';

    if (!preg_match('/^[0-9]{6}$/', $pin_baru)) {
      $this->api_response([
        'status'  => false,
        'message' => 'PIN baru harus terdiri dari tepat 6 digit angka.'
      ], 422);
      return;
    }

    if ($pin_baru !== $konfirmasi_pin_baru) {
      $this->api_response([
        'status'  => false,
        'message' => 'Konfirmasi PIN baru tidak cocok.'
      ], 422);
      return;
    }

    /*
     * Tolak PIN yang terlalu mudah ditebak.
     */
    $pin_lemah = [
      '000000',
      '111111',
      '222222',
      '333333',
      '444444',
      '555555',
      '666666',
      '777777',
      '888888',
      '999999',
      '123456',
      '654321'
    ];

    if (in_array($pin_baru, $pin_lemah, true)) {
      $this->api_response([
        'status'  => false,
        'message' => 'PIN baru terlalu mudah ditebak. Gunakan kombinasi angka lain.'
      ], 422);
      return;
    }

    /*
     * id_user dari request tidak digunakan.
     * Pengguna selalu berasal dari Bearer token.
     */
    $id_user = (int) $auth->id_user;

    $this->db->trans_begin();

    $user = $this->db->query(
      "SELECT
            id,
            level,
            login,
            pin,
            pin_gagal,
            pin_terkunci_sampai
         FROM tb_user
         WHERE id = ?
         LIMIT 1
         FOR UPDATE",
      [$id_user]
    )->row();

    if (
      !$user ||
      $user->level !== 'Nasabah' ||
      $user->login !== 'Ya'
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Akun Nasabah tidak ditemukan atau tidak aktif.'
      ], 403);
      return;
    }

    $waktu_sekarang = time();

    if (
      !empty($user->pin_terkunci_sampai) &&
      strtotime($user->pin_terkunci_sampai) > $waktu_sekarang
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Perubahan PIN sementara dikunci karena terlalu banyak percobaan.',
        'data'    => [
          'terkunci_sampai' => $user->pin_terkunci_sampai
        ]
      ], 429);
      return;
    }

    $pin_gagal = (int) $user->pin_gagal;

    if (
      !empty($user->pin_terkunci_sampai) &&
      strtotime($user->pin_terkunci_sampai) <= $waktu_sekarang
    ) {
      $pin_gagal = 0;

      $this->db
        ->where('id', $id_user)
        ->update('tb_user', [
          'pin_gagal'           => 0,
          'pin_terkunci_sampai' => null
        ]);
    }

    $pin_tersimpan = (string) $user->pin;
    $pin_belum_diatur = $pin_tersimpan === '';

    /*
     * Untuk akun lama, PIN lama wajib benar.
     * Untuk akun baru dengan PIN NULL, PIN dapat dibuat tanpa PIN lama.
     */
    if (!$pin_belum_diatur) {
      if (!preg_match('/^[0-9]{6}$/', $pin_lama)) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'PIN lama harus terdiri dari tepat 6 digit angka.'
        ], 422);
        return;
      }

      $info_hash = password_get_info($pin_tersimpan);
      $sudah_hash = isset($info_hash['algo']) &&
        $info_hash['algo'] !== 0;

      if ($sudah_hash) {
        $pin_lama_valid = password_verify(
          $pin_lama,
          $pin_tersimpan
        );
      } else {
        // Dukungan sementara untuk PIN lama yang masih berupa teks.
        $pin_lama_valid = hash_equals(
          $pin_tersimpan,
          $pin_lama
        );
      }

      if (!$pin_lama_valid) {
        $pin_gagal++;
        $batas_percobaan = 5;

        if ($pin_gagal >= $batas_percobaan) {
          $terkunci_sampai = date(
            'Y-m-d H:i:s',
            strtotime('+15 minutes')
          );

          $this->db
            ->where('id', $id_user)
            ->update('tb_user', [
              'pin_gagal'           => 0,
              'pin_terkunci_sampai' => $terkunci_sampai
            ]);

          if ($this->db->trans_status() === false) {
            $this->db->trans_rollback();

            $this->api_response([
              'status'  => false,
              'message' => 'Gagal memproses perubahan PIN.'
            ], 500);
            return;
          }

          $this->db->trans_commit();

          $this->api_response([
            'status'  => false,
            'message' => 'PIN lama salah lima kali. Perubahan PIN dikunci selama 15 menit.',
            'data'    => [
              'terkunci_sampai' => $terkunci_sampai
            ]
          ], 429);
          return;
        }

        $this->db
          ->where('id', $id_user)
          ->update('tb_user', [
            'pin_gagal'           => $pin_gagal,
            'pin_terkunci_sampai' => null
          ]);

        if ($this->db->trans_status() === false) {
          $this->db->trans_rollback();

          $this->api_response([
            'status'  => false,
            'message' => 'Gagal memproses perubahan PIN.'
          ], 500);
          return;
        }

        $this->db->trans_commit();

        $this->api_response([
          'status'  => false,
          'message' => 'PIN lama yang Anda masukkan salah.',
          'data'    => [
            'sisa_percobaan' =>
            $batas_percobaan - $pin_gagal
          ]
        ], 401);
        return;
      }

      if ($pin_baru === $pin_lama) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'PIN baru tidak boleh sama dengan PIN lama.'
        ], 422);
        return;
      }
    }

    $hash_pin_baru = password_hash(
      $pin_baru,
      PASSWORD_BCRYPT
    );

    if ($hash_pin_baru === false) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Gagal melindungi PIN baru.'
      ], 500);
      return;
    }

    $update = $this->db
      ->where('id', $id_user)
      ->update('tb_user', [
        'pin'                  => $hash_pin_baru,
        'pin_gagal'            => 0,
        'pin_terkunci_sampai'  => null
      ]);

    if (!$update || $this->db->trans_status() === false) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Terjadi kesalahan sistem. PIN gagal diperbarui.'
      ], 500);
      return;
    }

    $this->db->trans_commit();

    $this->api_response([
      'status'  => true,
      'message' => $pin_belum_diatur
        ? "\u{1F510} PIN transaksi berhasil dibuat."
        : "\u{1F510} PIN transaksi berhasil diperbarui.",
      'data'    => [
        'id_user'        => $id_user,
        'pin_terlindungi' => true,
        'login_ulang'    => false
      ]
    ]);
  }

  public function export_laporan_kas()
  {
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: GET');
    header('Access-Control-Allow-Headers: Authorization, Content-Type');

    if ($this->input->method(TRUE) !== 'GET') {
      $this->api_response([
        'status'  => false,
        'message' => 'Metode request tidak diizinkan.'
      ], 405);
      return;
    }

    $auth = $this->authenticate_api();

    if (!$auth) {
      return;
    }

    if (!in_array($auth->level, ['Administrator', 'Super Admin'], true)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Anda tidak memiliki izin untuk mengekspor laporan kas.'
      ], 403);
      return;
    }

    if (
      $auth->level === 'Administrator' &&
      (int) $auth->cabang_id <= 0
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Administrator belum terhubung dengan cabang yang valid.'
      ], 403);
      return;
    }

    $start = trim((string) $this->input->get('start', true));
    $end = trim((string) $this->input->get('end', true));

    // Tanggal awal dan akhir harus diisi bersamaan.
    if (
      ($start === '' && $end !== '') ||
      ($start !== '' && $end === '')
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Tanggal awal dan tanggal akhir harus diisi bersamaan.'
      ], 422);
      return;
    }

    if ($start !== '' && $end !== '') {
      $tanggal_awal = DateTime::createFromFormat(
        '!Y-m-d',
        $start
      );

      $tanggal_akhir = DateTime::createFromFormat(
        '!Y-m-d',
        $end
      );

      $start_valid = $tanggal_awal &&
        $tanggal_awal->format('Y-m-d') === $start;

      $end_valid = $tanggal_akhir &&
        $tanggal_akhir->format('Y-m-d') === $end;

      if (!$start_valid || !$end_valid) {
        $this->api_response([
          'status'  => false,
          'message' => 'Format tanggal harus YYYY-MM-DD.'
        ], 422);
        return;
      }

      if ($tanggal_awal > $tanggal_akhir) {
        $this->api_response([
          'status'  => false,
          'message' => 'Tanggal awal tidak boleh melebihi tanggal akhir.'
        ], 422);
        return;
      }

      $selisih_hari = (int) $tanggal_awal
        ->diff($tanggal_akhir)
        ->format('%a');

      if ($selisih_hari > 366) {
        $this->api_response([
          'status'  => false,
          'message' => 'Periode laporan maksimal 366 hari.'
        ], 422);
        return;
      }
    }

    /*
     * Query dibangun menggunakan Query Builder.
     * Tidak ada parameter tanggal yang ditempel langsung ke SQL.
     */
    $this->db->select(
      "
        t.id,
        t.tanggal,
        u.nama AS nama_nasabah,
        t.jenis,
        t.nominal,
        t.keterangan,
        t.status_konfirmasi,
        COALESCE(t.cabang_id, u.cabang_id) AS cabang_id,
        c.kode AS kode_cabang,
        c.nama AS nama_cabang
        ",
      false
    );

    $this->db->from('tb_transaksi AS t');

    $this->db->join(
      'tb_user AS u',
      't.idNasabah = u.id',
      'left'
    );

    $this->db->join(
      'tb_cabang AS c',
      'c.id = COALESCE(t.cabang_id, u.cabang_id)',
      'left',
      false
    );

    $this->db->where(
      't.status_konfirmasi',
      'Sukses'
    );

    if ($start !== '' && $end !== '') {
      $this->db->where('t.tanggal >=', $start);
      $this->db->where('t.tanggal <=', $end);
    }

    /*
     * Administrator hanya melihat transaksi cabangnya.
     * Transaksi lama tanpa cabang_id mengikuti cabang Nasabah.
     */
    if ($auth->level === 'Administrator') {
      $this->db->group_start();

      $this->db->where(
        't.cabang_id',
        (int) $auth->cabang_id
      );

      $this->db->or_group_start();

      $this->db->where(
        't.cabang_id IS NULL',
        null,
        false
      );

      $this->db->where(
        'u.cabang_id',
        (int) $auth->cabang_id
      );

      $this->db->group_end();
      $this->db->group_end();
    }

    $this->db->order_by('t.tanggal', 'DESC');
    $this->db->order_by('t.id', 'DESC');

    $query = $this->db->get();

    if (!$query) {
      $this->api_response([
        'status'  => false,
        'message' => 'Gagal mengambil data laporan kas.'
      ], 500);
      return;
    }

    $data_laporan = $query->result_array();

    // Nama file hanya berasal dari tanggal yang telah divalidasi.
    if ($start !== '' && $end !== '') {
      $periode_file = $start . '_sd_' . $end;
    } else {
      $periode_file = 'Semua_' . date('Y-m-d');
    }

    if ($auth->level === 'Administrator') {
      $cakupan_file = 'Cabang_' .
        (int) $auth->cabang_id;
    } else {
      $cakupan_file = 'Semua_Cabang';
    }

    $nama_file = 'Laporan_Kas_' .
      $cakupan_file . '_' .
      $periode_file . '.csv';

    /*
     * Perlindungan CSV/Excel formula injection.
     * Sel yang diawali =, +, -, atau @ diberi tanda petik.
     */
    $csv_safe = static function ($value) {
      $text = (string) $value;

      if (
        $text !== '' &&
        preg_match('/^[=+\-@]/', $text)
      ) {
        return "'" . $text;
      }

      return $text;
    };

    header('Content-Type: text/csv; charset=UTF-8');
    header(
      'Content-Disposition: attachment; filename="' .
        $nama_file . '"'
    );
    header('X-Content-Type-Options: nosniff');
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('Pragma: no-cache');

    $output = fopen('php://output', 'w');

    if ($output === false) {
      $this->api_response([
        'status'  => false,
        'message' => 'Gagal membuat file laporan.'
      ], 500);
      return;
    }

    // BOM UTF-8 agar karakter Indonesia terbaca oleh Excel.
    fwrite(
      $output,
      chr(0xEF) . chr(0xBB) . chr(0xBF)
    );

    fputcsv(
      $output,
      [
        'No',
        'ID Transaksi',
        'Tanggal',
        'Nama Nasabah',
        'Cabang',
        'Jenis',
        'Nominal',
        'Keterangan',
        'Status'
      ],
      ';'
    );

    $no = 1;

    foreach ($data_laporan as $row) {
      $nama_cabang = !empty($row['nama_cabang'])
        ? $row['nama_cabang']
        : 'Cabang tidak diketahui';

      if (!empty($row['kode_cabang'])) {
        $nama_cabang = $row['kode_cabang'] .
          ' - ' . $nama_cabang;
      }

      fputcsv(
        $output,
        [
          $no++,
          'TX-' . (int) $row['id'],
          $csv_safe($row['tanggal']),
          $csv_safe(
            $row['nama_nasabah'] ?? 'Nasabah Umum'
          ),
          $csv_safe($nama_cabang),
          $csv_safe($row['jenis']),
          (float) $row['nominal'],
          $csv_safe($row['keterangan']),
          $csv_safe($row['status_konfirmasi'])
        ],
        ';'
      );
    }

    fclose($output);
    exit;
  }

  // ==========================================
  // FITUR MARKETPLACE: MANAJEMEN TOKO
  // ==========================================

  // 1. Endpoint Cek Status Toko Nasabah
  public function cek_toko()
  {
    header('Access-Control-Allow-Origin: *');
    header('Content-Type: application/json; charset=UTF-8');
    header('Access-Control-Allow-Methods: POST');

    if ($this->input->method(TRUE) !== 'POST') {
      $this->api_response([
        'status'  => false,
        'message' => 'Metode request tidak diizinkan.'
      ], 405);
      return;
    }

    $auth = $this->authenticate_api();

    if (!$auth) {
      return;
    }

    if ($auth->level !== 'Nasabah') {
      $this->api_response([
        'status'  => false,
        'message' => 'Informasi toko pribadi hanya dapat diakses oleh Nasabah.'
      ], 403);
      return;
    }

    /*
     * id_user dari request sengaja tidak digunakan.
     * Pemilik toko selalu berasal dari Bearer token.
     */
    $id_user = (int) $auth->id_user;

    $toko = $this->db
      ->select(
        'id_toko, id_user, nama_toko, deskripsi_toko, ' .
          'foto_toko, alamat_toko, logo_toko, status_toko, terdaftar'
      )
      ->where('id_user', $id_user)
      ->limit(1)
      ->get('tb_toko')
      ->row_array();

    if (!$toko) {
      /*
         * Tetap menggunakan HTTP 200 dengan status false agar
         * kompatibel dengan alur aplikasi lama untuk membuka toko.
         */
      $this->api_response([
        'status'          => false,
        'memiliki_toko'   => false,
        'message'         => 'Nasabah belum memiliki toko.',
        'data'            => null
      ]);
      return;
    }

    $toko['id_toko'] = (int) $toko['id_toko'];
    $toko['id_user'] = (int) $toko['id_user'];
    $toko['toko_aktif'] = $toko['status_toko'] === 'Aktif';

    $this->api_response([
      'status'        => true,
      'memiliki_toko' => true,
      'data'          => $toko
    ]);
  }

  // 2. Endpoint Buka Toko Baru
  public function buka_toko()
  {
    header('Access-Control-Allow-Origin: *');
    header('Content-Type: application/json; charset=UTF-8');
    header('Access-Control-Allow-Methods: POST');

    if ($this->input->method(TRUE) !== 'POST') {
      $this->api_response([
        'status'  => false,
        'message' => 'Metode request tidak diizinkan.'
      ], 405);
      return;
    }

    $auth = $this->authenticate_api();

    if (!$auth) {
      return;
    }

    if ($auth->level !== 'Nasabah') {
      $this->api_response([
        'status'  => false,
        'message' => 'Toko hanya dapat dibuka oleh Nasabah.'
      ], 403);
      return;
    }

    $content_length = (int) $this->input->server(
      'CONTENT_LENGTH'
    );

    if ($content_length > 32768) {
      $this->api_response([
        'status'  => false,
        'message' => 'Ukuran data terlalu besar.'
      ], 413);
      return;
    }

    $request = json_decode(
      $this->input->raw_input_stream,
      true
    );

    if (!is_array($request)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Format JSON tidak valid.'
      ], 400);
      return;
    }

    $nama_toko = isset($request['nama_toko'])
      ? trim((string) $request['nama_toko'])
      : '';

    /*
     * Mendukung nama field lama "deskripsi"
     * dan nama field database "deskripsi_toko".
     */
    if (isset($request['deskripsi_toko'])) {
      $deskripsi_toko = trim(
        (string) $request['deskripsi_toko']
      );
    } else {
      $deskripsi_toko = isset($request['deskripsi'])
        ? trim((string) $request['deskripsi'])
        : '';
    }

    if (
      strlen($nama_toko) < 3 ||
      strlen($nama_toko) > 100
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Nama toko harus terdiri dari 3 sampai 100 karakter.'
      ], 422);
      return;
    }

    if (strlen($deskripsi_toko) > 2000) {
      $this->api_response([
        'status'  => false,
        'message' => 'Deskripsi toko maksimal 2.000 karakter.'
      ], 422);
      return;
    }

    /*
     * id_user dari request sengaja diabaikan.
     * Pemilik toko berasal dari Bearer token.
     */
    $id_user = (int) $auth->id_user;

    $this->db->trans_begin();

    /*
     * Kunci akun agar dua request buka toko yang dikirim
     * bersamaan diproses secara berurutan.
     */
    $nasabah = $this->db->query(
      "SELECT id, nama, level, login, cabang_id
         FROM tb_user
         WHERE id = ?
         LIMIT 1
         FOR UPDATE",
      [$id_user]
    )->row();

    if (
      !$nasabah ||
      $nasabah->level !== 'Nasabah' ||
      $nasabah->login !== 'Ya'
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Akun Nasabah tidak ditemukan atau tidak aktif.'
      ], 403);
      return;
    }

    $cek_toko = $this->db
      ->select('id_toko')
      ->where('id_user', $id_user)
      ->limit(1)
      ->get('tb_toko')
      ->row();

    if ($cek_toko) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'        => false,
        'memiliki_toko' => true,
        'message'       => 'Anda sudah memiliki toko yang terdaftar.',
        'data'          => [
          'id_toko' => (int) $cek_toko->id_toko
        ]
      ], 409);
      return;
    }

    $waktu_sekarang = date('Y-m-d H:i:s');

    $insert = $this->db->insert('tb_toko', [
      'id_user'        => $id_user,
      'nama_toko'      => $nama_toko,
      'deskripsi_toko' => $deskripsi_toko,
      'status_toko'    => 'Aktif',
      'terdaftar'      => $waktu_sekarang
    ]);

    $id_toko = (int) $this->db->insert_id();

    if (!$insert || $this->db->trans_status() === false) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Gagal membuka toko.'
      ], 500);
      return;
    }

    $this->db->trans_commit();

    $this->api_response([
      'status'        => true,
      'memiliki_toko' => true,
      'message'       => "\u{1F3EA} Alhamdulillah, toko Anda berhasil dibuka.",
      'data'          => [
        'id_toko'        => $id_toko,
        'id_user'        => $id_user,
        'nama_pemilik'   => $nasabah->nama,
        'nama_toko'      => $nama_toko,
        'deskripsi_toko' => $deskripsi_toko,
        'status_toko'    => 'Aktif',
        'cabang_id'      => (int) $nasabah->cabang_id,
        'terdaftar'      => $waktu_sekarang
      ]
    ], 201);
  }
  // ==========================================
  // FITUR MARKETPLACE: MANAJEMEN TOKO
  // ==========================================

  // Endpoint Edit Toko (Sisi Penjual)
  public function edit_toko()
  {
    header('Access-Control-Allow-Origin: *');
    header('Content-Type: application/json; charset=UTF-8');
    header('Access-Control-Allow-Methods: POST');

    if ($this->input->method(TRUE) !== 'POST') {
      $this->api_response([
        'status'  => false,
        'message' => 'Metode request tidak diizinkan.'
      ], 405);
      return;
    }

    $auth = $this->authenticate_api();

    if (!$auth) {
      return;
    }

    if ($auth->level !== 'Nasabah') {
      $this->api_response([
        'status'  => false,
        'message' => 'Informasi toko hanya dapat diubah oleh Nasabah.'
      ], 403);
      return;
    }

    /*
     * Batas JSON sekitar 4 MB, termasuk gambar base64.
     * Ukuran gambar asli dibatasi lagi menjadi maksimal 2 MB.
     */
    $content_length = (int) $this->input->server(
      'CONTENT_LENGTH'
    );

    if ($content_length > 4194304) {
      $this->api_response([
        'status'  => false,
        'message' => 'Ukuran request terlalu besar.'
      ], 413);
      return;
    }

    $request = json_decode(
      $this->input->raw_input_stream,
      true
    );

    if (!is_array($request)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Format JSON tidak valid.'
      ], 400);
      return;
    }

    $nama_toko = isset($request['nama_toko'])
      ? trim((string) $request['nama_toko'])
      : '';

    if (isset($request['deskripsi_toko'])) {
      $deskripsi_toko = trim(
        (string) $request['deskripsi_toko']
      );
    } else {
      $deskripsi_toko = isset($request['deskripsi'])
        ? trim((string) $request['deskripsi'])
        : '';
    }

    $foto_base64 = isset($request['foto_toko_base64'])
      ? trim((string) $request['foto_toko_base64'])
      : '';

    if (
      strlen($nama_toko) < 3 ||
      strlen($nama_toko) > 100
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Nama toko harus terdiri dari 3 sampai 100 karakter.'
      ], 422);
      return;
    }

    if (strlen($deskripsi_toko) > 2000) {
      $this->api_response([
        'status'  => false,
        'message' => 'Deskripsi toko maksimal 2.000 karakter.'
      ], 422);
      return;
    }

    /*
     * id_user dan id_toko dari request tidak dipercaya.
     * Toko ditentukan dari pemilik Bearer token.
     */
    $id_user = (int) $auth->id_user;

    $this->db->trans_begin();

    $toko = $this->db->query(
      "SELECT
            id_toko,
            id_user,
            nama_toko,
            deskripsi_toko,
            foto_toko,
            status_toko
         FROM tb_toko
         WHERE id_user = ?
         LIMIT 1
         FOR UPDATE",
      [$id_user]
    )->row();

    if (!$toko) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'        => false,
        'memiliki_toko' => false,
        'message'       => 'Anda belum memiliki toko.'
      ], 404);
      return;
    }

    $update_data = [
      'nama_toko'      => $nama_toko,
      'deskripsi_toko' => $deskripsi_toko
    ];

    $folder_path = FCPATH . 'assets/toko/';
    $file_name_baru = null;
    $file_path_baru = null;

    if ($foto_base64 !== '') {
      /*
         * Hanya menerima data URI gambar:
         * PNG, JPG/JPEG, dan WEBP.
         */
      $cocok = preg_match(
        '#^data:image/(png|jpe?g|webp);base64,(.+)$#is',
        $foto_base64,
        $bagian_gambar
      );

      if (!$cocok) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Format foto toko tidak valid.'
        ], 422);
        return;
      }

      $gambar_binary = base64_decode(
        $bagian_gambar[2],
        true
      );

      if ($gambar_binary === false) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Data base64 foto toko tidak valid.'
        ], 422);
        return;
      }

      $ukuran_gambar = strlen($gambar_binary);

      if (
        $ukuran_gambar < 1 ||
        $ukuran_gambar > 2097152
      ) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Ukuran foto toko maksimal 2 MB.'
        ], 422);
        return;
      }

      $informasi_gambar = @getimagesizefromstring(
        $gambar_binary
      );

      if ($informasi_gambar === false) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'File yang dikirim bukan gambar yang valid.'
        ], 422);
        return;
      }

      $lebar = (int) $informasi_gambar[0];
      $tinggi = (int) $informasi_gambar[1];

      if (
        $lebar < 1 ||
        $tinggi < 1 ||
        $lebar > 4000 ||
        $tinggi > 4000
      ) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Dimensi foto toko maksimal 4000 × 4000 piksel.'
        ], 422);
        return;
      }

      $finfo = finfo_open(FILEINFO_MIME_TYPE);

      if ($finfo === false) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Server gagal memeriksa jenis gambar.'
        ], 500);
        return;
      }

      $mime_asli = finfo_buffer(
        $finfo,
        $gambar_binary
      );

      finfo_close($finfo);

      $mime_diizinkan = [
        'image/jpeg' => 'jpg',
        'image/png'  => 'png',
        'image/webp' => 'webp'
      ];

      if (!isset($mime_diizinkan[$mime_asli])) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Jenis foto toko tidak diizinkan.'
        ], 422);
        return;
      }

      if (
        !is_dir($folder_path) &&
        !mkdir($folder_path, 0755, true)
      ) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Folder foto toko tidak dapat dibuat.'
        ], 500);
        return;
      }

      if (!is_writable($folder_path)) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Folder foto toko tidak dapat ditulis.'
        ], 500);
        return;
      }

      $file_name_baru = 'toko_' .
        bin2hex(random_bytes(16)) .
        '.' . $mime_diizinkan[$mime_asli];

      $file_path_baru = $folder_path .
        $file_name_baru;

      $hasil_simpan = file_put_contents(
        $file_path_baru,
        $gambar_binary,
        LOCK_EX
      );

      if (
        $hasil_simpan === false ||
        $hasil_simpan !== $ukuran_gambar
      ) {
        if (is_file($file_path_baru)) {
          unlink($file_path_baru);
        }

        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Foto toko gagal disimpan.'
        ], 500);
        return;
      }

      $update_data['foto_toko'] = $file_name_baru;
    }

    $update = $this->db
      ->where('id_toko', (int) $toko->id_toko)
      ->where('id_user', $id_user)
      ->update('tb_toko', $update_data);

    if (!$update || $this->db->trans_status() === false) {
      if (
        $file_path_baru !== null &&
        is_file($file_path_baru)
      ) {
        unlink($file_path_baru);
      }

      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Gagal memperbarui informasi toko.'
      ], 500);
      return;
    }

    $this->db->trans_commit();

    /*
     * Hapus foto lama hanya setelah database berhasil diperbarui.
     * Hanya file dengan awalan toko_ yang boleh dihapus.
     */
    if (
      $file_name_baru !== null &&
      !empty($toko->foto_toko)
    ) {
      $foto_lama = basename($toko->foto_toko);

      if (
        $foto_lama === $toko->foto_toko &&
        strpos($foto_lama, 'toko_') === 0
      ) {
        $path_foto_lama = $folder_path . $foto_lama;

        if (
          is_file($path_foto_lama) &&
          realpath(dirname($path_foto_lama)) ===
          realpath($folder_path)
        ) {
          unlink($path_foto_lama);
        }
      }
    }

    $this->api_response([
      'status'  => true,
      'message' => "\u{2705} Informasi toko berhasil disimpan.",
      'data'    => [
        'id_toko'        => (int) $toko->id_toko,
        'id_user'        => $id_user,
        'nama_toko'      => $nama_toko,
        'deskripsi_toko' => $deskripsi_toko,
        'foto_toko'      => $file_name_baru !== null
          ? $file_name_baru
          : $toko->foto_toko,
        'status_toko'    => $toko->status_toko
      ]
    ]);
  }

  // Endpoint Ubah Status Toko (Nonaktif/Aktif - Sisi Admin)
  public function ubah_status_toko()
  {
    header('Access-Control-Allow-Origin: *');
    header('Content-Type: application/json; charset=UTF-8');
    header('Access-Control-Allow-Methods: POST');

    if ($this->input->method(TRUE) !== 'POST') {
      $this->api_response([
        'status'  => false,
        'message' => 'Metode request tidak diizinkan.'
      ], 405);
      return;
    }

    $auth = $this->authenticate_api();

    if (!$auth) {
      return;
    }

    if (!in_array($auth->level, ['Administrator', 'Super Admin'], true)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Anda tidak memiliki izin untuk mengubah status toko.'
      ], 403);
      return;
    }

    $request = json_decode(
      $this->input->raw_input_stream,
      true
    );

    if (!is_array($request)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Format JSON tidak valid.'
      ], 400);
      return;
    }

    $id_toko = isset($request['id_toko'])
      ? (int) $request['id_toko']
      : 0;

    if (isset($request['status_toko'])) {
      $status_baru = trim(
        (string) $request['status_toko']
      );
    } else {
      $status_baru = isset($request['status'])
        ? trim((string) $request['status'])
        : '';
    }

    if ($id_toko <= 0) {
      $this->api_response([
        'status'  => false,
        'message' => 'ID toko tidak valid.'
      ], 422);
      return;
    }

    if (!in_array($status_baru, ['Aktif', 'Nonaktif'], true)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Status toko harus Aktif atau Nonaktif.'
      ], 422);
      return;
    }

    /*
     * level, id_admin, dan cabang_id dari request diabaikan.
     * Hak akses berasal dari Bearer token.
     */
    $this->db->trans_begin();

    $toko = $this->db->query(
      "SELECT
            t.id_toko,
            t.id_user,
            t.nama_toko,
            t.status_toko,
            u.nama AS nama_pemilik,
            u.cabang_id,
            u.expo_token
         FROM tb_toko AS t
         INNER JOIN tb_user AS u
            ON u.id = t.id_user
         WHERE t.id_toko = ?
         LIMIT 1
         FOR UPDATE",
      [$id_toko]
    )->row();

    if (!$toko) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Toko tidak ditemukan.'
      ], 404);
      return;
    }

    /*
     * Administrator hanya dapat mengelola toko milik Nasabah
     * yang berada pada cabangnya sendiri.
     */
    if (
      $auth->level === 'Administrator' &&
      (int) $toko->cabang_id !== (int) $auth->cabang_id
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Anda hanya dapat mengelola toko pada cabang sendiri.'
      ], 403);
      return;
    }

    /*
     * Request idempotent: apabila status sudah sama,
     * tidak ada produk atau audit yang diubah.
     */
    if ($toko->status_toko === $status_baru) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => true,
        'message' => 'Status toko sudah ' . $status_baru . '.',
        'data'    => [
          'id_toko'         => (int) $toko->id_toko,
          'nama_toko'       => $toko->nama_toko,
          'status_sebelumnya' => $toko->status_toko,
          'status_sekarang' => $status_baru,
          'produk_diubah'   => 0,
          'tidak_ada_perubahan' => true
        ]
      ]);
      return;
    }

    $produk_diubah = 0;

    if ($status_baru === 'Nonaktif') {
      /*
         * Simpan status asli setiap produk sebelum diarsipkan.
         * Nilai tidak akan ditimpa jika request dijalankan ulang.
         */
      $this->db
        ->set(
          'status_sebelum_toko_nonaktif',
          'status_produk',
          false
        )
        ->set('status_produk', 'Arsip')
        ->where('id_toko', (int) $toko->id_toko)
        ->where(
          'status_sebelum_toko_nonaktif IS NULL',
          null,
          false
        )
        ->update('tb_produk');

      $produk_diubah = $this->db->affected_rows();
    } else {
      /*
         * Kembalikan setiap produk ke status persis sebelum
         * toko dinonaktifkan: Tersedia, Habis, atau Arsip.
         */
      $this->db
        ->set(
          'status_produk',
          'status_sebelum_toko_nonaktif',
          false
        )
        ->set('status_sebelum_toko_nonaktif', null)
        ->where('id_toko', (int) $toko->id_toko)
        ->where(
          'status_sebelum_toko_nonaktif IS NOT NULL',
          null,
          false
        )
        ->update('tb_produk');

      $produk_diubah = $this->db->affected_rows();
    }

    $waktu_sekarang = date('Y-m-d H:i:s');

    $update_toko = $this->db
      ->where('id_toko', (int) $toko->id_toko)
      ->update('tb_toko', [
        'status_toko'        => $status_baru,
        'status_diubah_oleh' => (int) $auth->id_user,
        'status_diubah_pada' => $waktu_sekarang
      ]);

    if (
      !$update_toko ||
      $this->db->trans_status() === false
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Gagal mengubah status toko.'
      ], 500);
      return;
    }

    $status_sebelumnya = $toko->status_toko;

    $this->db->trans_commit();

    // Beri tahu pemilik toko apabila memiliki Expo token.
    if (!empty($toko->expo_token)) {
      $judul_notifikasi = $status_baru === 'Aktif'
        ? "\u{2705} Toko Diaktifkan"
        : "\u{26D4} Toko Dinonaktifkan";

      $pesan_notifikasi = 'Status toko ' .
        $toko->nama_toko . ' sekarang ' .
        $status_baru . '.';

      $this->send_expo_push_notification(
        $toko->expo_token,
        $judul_notifikasi,
        $pesan_notifikasi
      );
    }

    $this->api_response([
      'status'  => true,
      'message' => $status_baru === 'Aktif'
        ? "\u{2705} Toko berhasil diaktifkan."
        : "\u{26D4} Toko berhasil dinonaktifkan.",
      'data'    => [
        'id_toko'          => (int) $toko->id_toko,
        'nama_toko'        => $toko->nama_toko,
        'id_pemilik'       => (int) $toko->id_user,
        'nama_pemilik'     => $toko->nama_pemilik,
        'cabang_id'        => (int) $toko->cabang_id,
        'status_sebelumnya' => $status_sebelumnya,
        'status_sekarang'  => $status_baru,
        'produk_diubah'    => (int) $produk_diubah,
        'diubah_oleh'      => (int) $auth->id_user,
        'nama_operator'    => $auth->nama,
        'diubah_pada'      => $waktu_sekarang,
        'tidak_ada_perubahan' => false
      ]
    ]);
  }
  // Endpoint Hapus Toko Secara Permanen (Sisi Admin)
  public function hapus_toko()
  {
    header('Access-Control-Allow-Origin: *');
    header('Content-Type: application/json; charset=UTF-8');
    header('Access-Control-Allow-Methods: POST');

    if ($this->input->method(TRUE) !== 'POST') {
      $this->api_response([
        'status'  => false,
        'message' => 'Metode request tidak diizinkan.'
      ], 405);
      return;
    }

    $auth = $this->authenticate_api();

    if (!$auth) {
      return;
    }

    if (!in_array($auth->level, ['Administrator', 'Super Admin'], true)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Anda tidak memiliki izin untuk menghapus toko.'
      ], 403);
      return;
    }

    $request = json_decode(
      $this->input->raw_input_stream,
      true
    );

    if (!is_array($request)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Format JSON tidak valid.'
      ], 400);
      return;
    }

    $id_toko = isset($request['id_toko'])
      ? (int) $request['id_toko']
      : 0;

    if ($id_toko <= 0) {
      $this->api_response([
        'status'  => false,
        'message' => 'ID toko tidak valid.'
      ], 422);
      return;
    }

    /*
     * id_admin, level, dan cabang_id dari request diabaikan.
     */
    $this->db->trans_begin();

    $toko = $this->db->query(
      "SELECT
            t.id_toko,
            t.id_user,
            t.nama_toko,
            t.foto_toko,
            t.logo_toko,
            t.status_toko,
            u.nama AS nama_pemilik,
            u.cabang_id,
            u.expo_token
         FROM tb_toko AS t
         INNER JOIN tb_user AS u
            ON u.id = t.id_user
         WHERE t.id_toko = ?
         LIMIT 1
         FOR UPDATE",
      [$id_toko]
    )->row();

    if (!$toko) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Toko tidak ditemukan.'
      ], 404);
      return;
    }

    // Administrator hanya boleh menghapus toko pada cabangnya.
    if (
      $auth->level === 'Administrator' &&
      (int) $toko->cabang_id !== (int) $auth->cabang_id
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Anda hanya dapat menghapus toko pada cabang sendiri.'
      ], 403);
      return;
    }

    /*
     * Kunci dan ambil produk beserta nama file gambarnya.
     */
    $produk = $this->db->query(
      "SELECT
            id_produk,
            foto_produk,
            foto_2,
            foto_3
         FROM tb_produk
         WHERE id_toko = ?
         FOR UPDATE",
      [$id_toko]
    )->result();

    /*
     * Periksa seluruh riwayat yang harus tetap dipertahankan.
     */
    $jumlah_pesanan = (int) $this->db->query(
      "SELECT COUNT(*) AS jumlah
         FROM tb_pesanan
         WHERE id_toko = ?",
      [$id_toko]
    )->row()->jumlah;

    $jumlah_detail_pesanan = (int) $this->db->query(
      "SELECT COUNT(*) AS jumlah
         FROM tb_pesanan_detail AS d
         INNER JOIN tb_produk AS p
            ON p.id_produk = d.id_produk
         WHERE p.id_toko = ?",
      [$id_toko]
    )->row()->jumlah;

    $jumlah_ulasan = (int) $this->db->query(
      "SELECT COUNT(*) AS jumlah
         FROM tb_ulasan AS u
         INNER JOIN tb_produk AS p
            ON p.id_produk = u.id_produk
         WHERE p.id_toko = ?",
      [$id_toko]
    )->row()->jumlah;

    $jumlah_wishlist = (int) $this->db->query(
      "SELECT COUNT(*) AS jumlah
         FROM tb_wishlist AS w
         INNER JOIN tb_produk AS p
            ON p.id_produk = w.id_produk
         WHERE p.id_toko = ?",
      [$id_toko]
    )->row()->jumlah;

    /*
     * Toko dengan riwayat transaksi tidak boleh dihapus permanen.
     * Nonaktifkan toko agar riwayat tetap utuh.
     */
    if (
      $jumlah_pesanan > 0 ||
      $jumlah_detail_pesanan > 0 ||
      $jumlah_ulasan > 0 ||
      $jumlah_wishlist > 0
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Toko memiliki riwayat marketplace dan tidak boleh dihapus permanen. Nonaktifkan toko sebagai gantinya.',
        'data'    => [
          'id_toko'               => (int) $toko->id_toko,
          'jumlah_produk'         => count($produk),
          'jumlah_pesanan'        => $jumlah_pesanan,
          'jumlah_detail_pesanan' => $jumlah_detail_pesanan,
          'jumlah_ulasan'         => $jumlah_ulasan,
          'jumlah_wishlist'       => $jumlah_wishlist
        ]
      ], 409);
      return;
    }

    $jumlah_produk = count($produk);

    $hapus_produk = $this->db
      ->where('id_toko', (int) $toko->id_toko)
      ->delete('tb_produk');

    if (!$hapus_produk) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Gagal menghapus produk toko.'
      ], 500);
      return;
    }

    $hapus_toko = $this->db
      ->where('id_toko', (int) $toko->id_toko)
      ->delete('tb_toko');

    if (
      !$hapus_toko ||
      $this->db->trans_status() === false
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Gagal menghapus toko.'
      ], 500);
      return;
    }

    $this->db->trans_commit();

    /*
     * File hanya dihapus setelah transaksi database berhasil.
     */
    $file_dihapus = 0;
    $file_gagal = 0;

    $hapus_file_aman = static function (
      $folder,
      $nama_file,
      $awalan_diizinkan
    ) use (&$file_dihapus, &$file_gagal) {
      if (empty($nama_file)) {
        return;
      }

      $nama_bersih = basename($nama_file);

      if ($nama_bersih !== $nama_file) {
        return;
      }

      $awalan_valid = false;

      foreach ($awalan_diizinkan as $awalan) {
        if (strpos($nama_bersih, $awalan) === 0) {
          $awalan_valid = true;
          break;
        }
      }

      if (!$awalan_valid) {
        return;
      }

      $path_file = $folder . $nama_bersih;

      if (!is_file($path_file)) {
        return;
      }

      $folder_asli = realpath($folder);
      $folder_file = realpath(dirname($path_file));

      if (
        $folder_asli === false ||
        $folder_file !== $folder_asli
      ) {
        return;
      }

      if (unlink($path_file)) {
        $file_dihapus++;
      } else {
        $file_gagal++;
      }
    };

    $folder_toko = FCPATH . 'assets/toko/';
    $folder_produk = FCPATH . 'assets/produk/';

    $hapus_file_aman(
      $folder_toko,
      $toko->foto_toko,
      ['toko_']
    );

    $hapus_file_aman(
      $folder_toko,
      $toko->logo_toko,
      ['toko_', 'logo_toko_']
    );

    foreach ($produk as $row_produk) {
      $hapus_file_aman(
        $folder_produk,
        $row_produk->foto_produk,
        ['produk_']
      );

      $hapus_file_aman(
        $folder_produk,
        $row_produk->foto_2,
        ['produk_']
      );

      $hapus_file_aman(
        $folder_produk,
        $row_produk->foto_3,
        ['produk_']
      );
    }

    if (!empty($toko->expo_token)) {
      $this->send_expo_push_notification(
        $toko->expo_token,
        "\u{1F5D1}\u{FE0F} Toko Dihapus",
        'Toko ' . $toko->nama_toko .
          ' telah dihapus oleh Administrator.'
      );
    }

    $this->api_response([
      'status'  => true,
      'message' => "\u{1F5D1}\u{FE0F} Toko kosong berhasil dihapus permanen.",
      'data'    => [
        'id_toko'          => (int) $toko->id_toko,
        'nama_toko'        => $toko->nama_toko,
        'id_pemilik'       => (int) $toko->id_user,
        'nama_pemilik'     => $toko->nama_pemilik,
        'cabang_id'        => (int) $toko->cabang_id,
        'jumlah_produk'    => $jumlah_produk,
        'file_dihapus'     => $file_dihapus,
        'file_gagal'       => $file_gagal,
        'dihapus_oleh'     => (int) $auth->id_user,
        'nama_operator'    => $auth->nama
      ]
    ]);
  }

  // Endpoint Admin: Ambil Semua Daftar Toko
  public function admin_get_semua_toko()
  {
    header('Access-Control-Allow-Origin: *');
    header('Content-Type: application/json; charset=UTF-8');
    header('Access-Control-Allow-Methods: POST');

    if ($this->input->method(TRUE) !== 'POST') {
      $this->api_response([
        'status'  => false,
        'message' => 'Metode request tidak diizinkan.'
      ], 405);
      return;
    }

    $auth = $this->authenticate_api();

    if (!$auth) {
      return;
    }

    /*
     * level, id_admin, dan cabang_id dari request tidak dipercaya.
     */
    if (!in_array($auth->level, ['Administrator', 'Super Admin'], true)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Akses ditolak. Endpoint ini khusus Administrator.'
      ], 403);
      return;
    }

    if (
      $auth->level === 'Administrator' &&
      (int) $auth->cabang_id <= 0
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Administrator belum terhubung dengan cabang yang valid.'
      ], 403);
      return;
    }

    /*
     * Jumlah dan status produk dihitung dalam satu subquery
     * sehingga tidak terjadi N+1 query.
     */
    $this->db->select(
      "
        t.id_toko,
        t.id_user,
        t.nama_toko,
        t.deskripsi_toko,
        t.foto_toko,
        t.alamat_toko,
        t.logo_toko,
        t.status_toko,
        t.status_diubah_oleh,
        t.status_diubah_pada,
        t.terdaftar,

        u.nama AS nama_pemilik,
        u.cabang_id,

        c.kode AS kode_cabang,
        c.nama AS nama_cabang,

        operator.nama AS nama_pengubah_status,

        COALESCE(produk.jumlah_produk, 0)
            AS jumlah_produk,

        COALESCE(produk.produk_tersedia, 0)
            AS produk_tersedia,

        COALESCE(produk.produk_habis, 0)
            AS produk_habis,

        COALESCE(produk.produk_arsip, 0)
            AS produk_arsip
        ",
      false
    );

    $this->db->from('tb_toko AS t');

    $this->db->join(
      'tb_user AS u',
      'u.id = t.id_user',
      'inner'
    );

    $this->db->join(
      'tb_cabang AS c',
      'c.id = u.cabang_id',
      'left'
    );

    $this->db->join(
      'tb_user AS operator',
      'operator.id = t.status_diubah_oleh',
      'left'
    );

    $this->db->join(
      "(
            SELECT
                id_toko,
                COUNT(*) AS jumlah_produk,
                SUM(status_produk = 'Tersedia')
                    AS produk_tersedia,
                SUM(status_produk = 'Habis')
                    AS produk_habis,
                SUM(status_produk = 'Arsip')
                    AS produk_arsip
            FROM tb_produk
            GROUP BY id_toko
        ) AS produk",
      'produk.id_toko = t.id_toko',
      'left',
      false
    );

    // Administrator hanya melihat toko pada cabangnya.
    if ($auth->level === 'Administrator') {
      $this->db->where(
        'u.cabang_id',
        (int) $auth->cabang_id
      );
    }

    $this->db->order_by('t.id_toko', 'DESC');

    $hasil_query = $this->db->get();

    if (!$hasil_query) {
      $this->api_response([
        'status'  => false,
        'message' => 'Gagal mengambil daftar toko.'
      ], 500);
      return;
    }

    $toko = $hasil_query->result_array();
    $data_toko = [];

    foreach ($toko as $row) {
      $data_toko[] = [
        'id_toko'              => (int) $row['id_toko'],
        'id_user'              => (int) $row['id_user'],
        'nama_pemilik'         => $row['nama_pemilik'],
        'nama_toko'            => $row['nama_toko'],
        'deskripsi_toko'       => $row['deskripsi_toko'],
        'foto_toko'            => $row['foto_toko'],
        'alamat_toko'          => $row['alamat_toko'],
        'logo_toko'            => $row['logo_toko'],
        'status_toko'          => $row['status_toko'],
        'toko_aktif'           =>
        $row['status_toko'] === 'Aktif',

        'cabang_id'            => (int) $row['cabang_id'],
        'kode_cabang'          => $row['kode_cabang'],
        'nama_cabang'          => $row['nama_cabang'],

        'jumlah_produk'        =>
        (int) $row['jumlah_produk'],
        'produk_tersedia'      =>
        (int) $row['produk_tersedia'],
        'produk_habis'         =>
        (int) $row['produk_habis'],
        'produk_arsip'         =>
        (int) $row['produk_arsip'],

        'status_diubah_oleh'   =>
        $row['status_diubah_oleh'] !== null
          ? (int) $row['status_diubah_oleh']
          : null,

        'nama_pengubah_status' =>
        $row['nama_pengubah_status'],

        'status_diubah_pada'   =>
        $row['status_diubah_pada'],

        'terdaftar'            => $row['terdaftar']
      ];
    }

    $this->api_response([
      'status' => true,
      'akses'  => [
        'level'     => $auth->level,
        'cabang_id' => $auth->level === 'Administrator'
          ? (int) $auth->cabang_id
          : null,
        'cakupan'   => $auth->level === 'Super Admin'
          ? 'Semua cabang'
          : 'Cabang sendiri'
      ],
      'jumlah' => count($data_toko),
      'data'   => $data_toko
    ]);
  }
  // ==========================================
  // FITUR MARKETPLACE: MANAJEMEN PRODUK TOKO
  // ==========================================

  // 3. Endpoint Ambil Produk Milik Toko (Dasbor Penjual)
  public function get_produk_toko()
  {
    header('Access-Control-Allow-Origin: *');
    header('Content-Type: application/json; charset=UTF-8');
    header('Access-Control-Allow-Methods: POST');

    if ($this->input->method(TRUE) !== 'POST') {
      $this->api_response([
        'status'  => false,
        'message' => 'Metode request tidak diizinkan.'
      ], 405);
      return;
    }

    $auth = $this->authenticate_api();

    if (!$auth) {
      return;
    }

    if ($auth->level !== 'Nasabah') {
      $this->api_response([
        'status'  => false,
        'message' => 'Daftar produk toko pribadi hanya dapat diakses oleh Nasabah.'
      ], 403);
      return;
    }

    /*
     * id_toko dan id_user dari request diabaikan.
     * Toko selalu dicari berdasarkan pemilik Bearer token.
     */
    $id_user = (int) $auth->id_user;

    $toko = $this->db
      ->select(
        'id_toko, id_user, nama_toko, status_toko'
      )
      ->where('id_user', $id_user)
      ->limit(1)
      ->get('tb_toko')
      ->row();

    if (!$toko) {
      $this->api_response([
        'status'        => false,
        'memiliki_toko' => false,
        'message'       => 'Nasabah belum memiliki toko.',
        'data'          => []
      ]);
      return;
    }

    /*
     * Pertahankan perilaku aplikasi lama:
     * produk berstatus Arsip tidak ditampilkan di etalase penjual.
     */
    $produk = $this->db
      ->select(
        'id_produk, id_toko, nama_produk, kategori, ' .
          'deskripsi_produk, harga, harga_coret, stok, berat, ' .
          'rating, terjual, foto_produk, foto_2, foto_3, ' .
          'status_produk, terdaftar'
      )
      ->where('id_toko', (int) $toko->id_toko)
      ->where('status_produk !=', 'Arsip')
      ->order_by('id_produk', 'DESC')
      ->get('tb_produk')
      ->result_array();

    $data_produk = [];

    foreach ($produk as $row) {
      $data_produk[] = [
        'id_produk'       => (int) $row['id_produk'],
        'id_toko'         => (int) $row['id_toko'],
        'nama_produk'     => $row['nama_produk'],
        'kategori'        => $row['kategori'],
        'deskripsi_produk' => $row['deskripsi_produk'],
        'harga'           => (int) $row['harga'],
        'harga_coret'     => (int) $row['harga_coret'],
        'stok'            => (int) $row['stok'],
        'berat'           => (int) $row['berat'],
        'rating'          => (float) $row['rating'],
        'terjual'         => (int) $row['terjual'],
        'foto_produk'     => $row['foto_produk'],
        'foto_2'          => $row['foto_2'],
        'foto_3'          => $row['foto_3'],
        'status_produk'   => $row['status_produk'],
        'terdaftar'       => $row['terdaftar']
      ];
    }

    $this->api_response([
      'status'        => true,
      'memiliki_toko' => true,
      'toko'          => [
        'id_toko'     => (int) $toko->id_toko,
        'id_user'     => (int) $toko->id_user,
        'nama_toko'   => $toko->nama_toko,
        'status_toko' => $toko->status_toko
      ],
      'jumlah'        => count($data_produk),
      'data'          => $data_produk
    ]);
  }

  private function simpan_gambar_produk_base64(
    $data_uri,
    $awalan_file
  ) {
    if ($data_uri === null || trim((string) $data_uri) === '') {
      return [
        'status'    => true,
        'nama_file' => null,
        'path_file' => null,
        'message'   => null
      ];
    }

    $data_uri = trim((string) $data_uri);

    /*
     * Hanya menerima PNG, JPG/JPEG, dan WEBP.
     * Jenis MIME tetap akan diperiksa dari isi file.
     */
    $cocok = preg_match(
      '#^data:image/(png|jpe?g|webp);base64,(.+)$#is',
      $data_uri,
      $bagian
    );

    if (!$cocok) {
      return [
        'status'    => false,
        'nama_file' => null,
        'path_file' => null,
        'message'   => 'Format gambar produk tidak valid.'
      ];
    }

    $binary = base64_decode($bagian[2], true);

    if ($binary === false) {
      return [
        'status'    => false,
        'nama_file' => null,
        'path_file' => null,
        'message'   => 'Data base64 gambar produk tidak valid.'
      ];
    }

    $ukuran = strlen($binary);

    if ($ukuran < 1 || $ukuran > 2097152) {
      return [
        'status'    => false,
        'nama_file' => null,
        'path_file' => null,
        'message'   => 'Ukuran setiap gambar produk maksimal 2 MB.'
      ];
    }

    $informasi_gambar = @getimagesizefromstring($binary);

    if ($informasi_gambar === false) {
      return [
        'status'    => false,
        'nama_file' => null,
        'path_file' => null,
        'message'   => 'File yang dikirim bukan gambar yang valid.'
      ];
    }

    $lebar = (int) $informasi_gambar[0];
    $tinggi = (int) $informasi_gambar[1];

    if (
      $lebar < 1 ||
      $tinggi < 1 ||
      $lebar > 4000 ||
      $tinggi > 4000
    ) {
      return [
        'status'    => false,
        'nama_file' => null,
        'path_file' => null,
        'message'   => 'Dimensi gambar produk maksimal 4000 × 4000 piksel.'
      ];
    }

    $finfo = finfo_open(FILEINFO_MIME_TYPE);

    if ($finfo === false) {
      return [
        'status'    => false,
        'nama_file' => null,
        'path_file' => null,
        'message'   => 'Server gagal memeriksa jenis gambar.'
      ];
    }

    $mime_asli = finfo_buffer($finfo, $binary);
    finfo_close($finfo);

    $mime_diizinkan = [
      'image/jpeg' => 'jpg',
      'image/png'  => 'png',
      'image/webp' => 'webp'
    ];

    if (!isset($mime_diizinkan[$mime_asli])) {
      return [
        'status'    => false,
        'nama_file' => null,
        'path_file' => null,
        'message'   => 'Jenis gambar produk tidak diizinkan.'
      ];
    }

    /*
     * Awalan nama tidak boleh berasal langsung dari pengguna.
     */
    if (!in_array(
      $awalan_file,
      ['produk_1_', 'produk_2_', 'produk_3_'],
      true
    )) {
      return [
        'status'    => false,
        'nama_file' => null,
        'path_file' => null,
        'message'   => 'Awalan file gambar tidak valid.'
      ];
    }

    $upload_dir = FCPATH . 'assets/produk/';

    if (
      !is_dir($upload_dir) &&
      !mkdir($upload_dir, 0755, true)
    ) {
      return [
        'status'    => false,
        'nama_file' => null,
        'path_file' => null,
        'message'   => 'Folder gambar produk tidak dapat dibuat.'
      ];
    }

    if (!is_writable($upload_dir)) {
      return [
        'status'    => false,
        'nama_file' => null,
        'path_file' => null,
        'message'   => 'Folder gambar produk tidak dapat ditulis.'
      ];
    }

    $nama_file = $awalan_file .
      bin2hex(random_bytes(16)) .
      '.' . $mime_diizinkan[$mime_asli];

    $path_file = $upload_dir . $nama_file;

    $hasil_simpan = file_put_contents(
      $path_file,
      $binary,
      LOCK_EX
    );

    if (
      $hasil_simpan === false ||
      $hasil_simpan !== $ukuran
    ) {
      if (is_file($path_file)) {
        unlink($path_file);
      }

      return [
        'status'    => false,
        'nama_file' => null,
        'path_file' => null,
        'message'   => 'Gambar produk gagal disimpan.'
      ];
    }

    return [
      'status'    => true,
      'nama_file' => $nama_file,
      'path_file' => $path_file,
      'message'   => null
    ];
  }

  // 4. Endpoint Tambah Produk Baru ke Etalase (Mendukung 3 Foto, Harga Coret & Kategori)
  public function tambah_produk()
  {
    header('Access-Control-Allow-Origin: *');
    header('Content-Type: application/json; charset=UTF-8');
    header('Access-Control-Allow-Methods: POST');

    if ($this->input->method(TRUE) !== 'POST') {
      $this->api_response([
        'status'  => false,
        'message' => 'Metode request tidak diizinkan.'
      ], 405);
      return;
    }

    $auth = $this->authenticate_api();

    if (!$auth) {
      return;
    }

    if ($auth->level !== 'Nasabah') {
      $this->api_response([
        'status'  => false,
        'message' => 'Produk hanya dapat ditambahkan oleh pemilik toko.'
      ], 403);
      return;
    }

    /*
     * Maksimal sekitar 10 MB untuk JSON dan tiga gambar base64.
     * Setiap gambar dibatasi lagi menjadi 2 MB oleh helper.
     */
    $content_length = (int) $this->input->server(
      'CONTENT_LENGTH'
    );

    if ($content_length > 10485760) {
      $this->api_response([
        'status'  => false,
        'message' => 'Ukuran request terlalu besar.'
      ], 413);
      return;
    }

    $request = json_decode(
      $this->input->raw_input_stream,
      true
    );

    if (!is_array($request)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Format JSON tidak valid.'
      ], 400);
      return;
    }

    $nama_produk = isset($request['nama_produk'])
      ? trim((string) $request['nama_produk'])
      : '';

    $kategori = isset($request['kategori'])
      ? trim((string) $request['kategori'])
      : 'Sembako';

    $deskripsi = isset($request['deskripsi_produk'])
      ? trim((string) $request['deskripsi_produk'])
      : '';

    $harga_text = isset($request['harga'])
      ? trim((string) $request['harga'])
      : '';

    $harga_coret_text = isset($request['harga_coret'])
      ? trim((string) $request['harga_coret'])
      : '0';

    $stok_text = isset($request['stok'])
      ? trim((string) $request['stok'])
      : '0';

    $berat_text = isset($request['berat'])
      ? trim((string) $request['berat'])
      : '1000';

    // Mendukung format angka seperti "10.000".
    $harga_text = preg_replace('/[.\s]/', '', $harga_text);
    $harga_coret_text = preg_replace(
      '/[.\s]/',
      '',
      $harga_coret_text
    );
    $stok_text = preg_replace('/[\s]/', '', $stok_text);
    $berat_text = preg_replace('/[.\s]/', '', $berat_text);

    if (
      strlen($nama_produk) < 3 ||
      strlen($nama_produk) > 150
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Nama produk harus terdiri dari 3 sampai 150 karakter.'
      ], 422);
      return;
    }

    if (
      strlen($kategori) < 2 ||
      strlen($kategori) > 50
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Kategori harus terdiri dari 2 sampai 50 karakter.'
      ], 422);
      return;
    }

    if (
      !preg_match(
        '/^[\p{L}\p{N}\s&\/().,-]+$/u',
        $kategori
      )
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Kategori mengandung karakter yang tidak diizinkan.'
      ], 422);
      return;
    }

    if (strlen($deskripsi) > 5000) {
      $this->api_response([
        'status'  => false,
        'message' => 'Deskripsi produk maksimal 5.000 karakter.'
      ], 422);
      return;
    }

    if ($harga_text === '' || !ctype_digit($harga_text)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Harga produk harus berupa angka bulat.'
      ], 422);
      return;
    }

    if (
      $harga_coret_text === '' ||
      !ctype_digit($harga_coret_text)
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Harga coret harus berupa angka bulat.'
      ], 422);
      return;
    }

    if ($stok_text === '' || !ctype_digit($stok_text)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Stok harus berupa angka bulat.'
      ], 422);
      return;
    }

    if ($berat_text === '' || !ctype_digit($berat_text)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Berat harus berupa angka bulat dalam gram.'
      ], 422);
      return;
    }

    $harga = (int) $harga_text;
    $harga_coret = (int) $harga_coret_text;
    $stok = (int) $stok_text;
    $berat = (int) $berat_text;

    if ($harga < 1 || $harga > 2000000000) {
      $this->api_response([
        'status'  => false,
        'message' => 'Harga produk tidak valid.'
      ], 422);
      return;
    }

    if (
      $harga_coret < 0 ||
      $harga_coret > 2000000000
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Harga coret tidak valid.'
      ], 422);
      return;
    }

    if ($harga_coret > 0 && $harga_coret < $harga) {
      $this->api_response([
        'status'  => false,
        'message' => 'Harga coret harus lebih besar atau sama dengan harga jual.'
      ], 422);
      return;
    }

    if ($stok < 0 || $stok > 1000000) {
      $this->api_response([
        'status'  => false,
        'message' => 'Jumlah stok tidak valid.'
      ], 422);
      return;
    }

    if ($berat < 1 || $berat > 1000000) {
      $this->api_response([
        'status'  => false,
        'message' => 'Berat produk harus antara 1 dan 1.000.000 gram.'
      ], 422);
      return;
    }

    $foto_1 = $request['foto_base64'] ?? '';
    $foto_2 = $request['foto_base64_2'] ?? '';
    $foto_3 = $request['foto_base64_3'] ?? '';

    /*
     * id_toko dan id_user dari request diabaikan.
     * Toko ditentukan dari pemilik Bearer token.
     */
    $id_user = (int) $auth->id_user;

    $this->db->trans_begin();

    $toko = $this->db->query(
      "SELECT
            t.id_toko,
            t.id_user,
            t.nama_toko,
            t.status_toko,
            u.cabang_id
         FROM tb_toko AS t
         INNER JOIN tb_user AS u
            ON u.id = t.id_user
         WHERE t.id_user = ?
         LIMIT 1
         FOR UPDATE",
      [$id_user]
    )->row();

    if (!$toko) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'        => false,
        'memiliki_toko' => false,
        'message'       => 'Anda belum memiliki toko.'
      ], 404);
      return;
    }

    if ($toko->status_toko !== 'Aktif') {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Produk tidak dapat ditambahkan karena toko sedang nonaktif.'
      ], 403);
      return;
    }

    $jumlah_produk = $this->db
      ->where('id_toko', (int) $toko->id_toko)
      ->count_all_results('tb_produk');

    if ($jumlah_produk >= 500) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Maksimal 500 produk untuk setiap toko.'
      ], 422);
      return;
    }

    $file_baru = [];

    $hasil_foto_1 = $this->simpan_gambar_produk_base64(
      $foto_1,
      'produk_1_'
    );

    if (!$hasil_foto_1['status']) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => $hasil_foto_1['message']
      ], 422);
      return;
    }

    if ($hasil_foto_1['path_file'] !== null) {
      $file_baru[] = $hasil_foto_1['path_file'];
    }

    $hasil_foto_2 = $this->simpan_gambar_produk_base64(
      $foto_2,
      'produk_2_'
    );

    if (!$hasil_foto_2['status']) {
      foreach ($file_baru as $path_file) {
        if (is_file($path_file)) {
          unlink($path_file);
        }
      }

      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => $hasil_foto_2['message']
      ], 422);
      return;
    }

    if ($hasil_foto_2['path_file'] !== null) {
      $file_baru[] = $hasil_foto_2['path_file'];
    }

    $hasil_foto_3 = $this->simpan_gambar_produk_base64(
      $foto_3,
      'produk_3_'
    );

    if (!$hasil_foto_3['status']) {
      foreach ($file_baru as $path_file) {
        if (is_file($path_file)) {
          unlink($path_file);
        }
      }

      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => $hasil_foto_3['message']
      ], 422);
      return;
    }

    if ($hasil_foto_3['path_file'] !== null) {
      $file_baru[] = $hasil_foto_3['path_file'];
    }

    $nama_foto_1 = $hasil_foto_1['nama_file'] !== null
      ? $hasil_foto_1['nama_file']
      : 'no-product.png';

    $status_produk = $stok > 0
      ? 'Tersedia'
      : 'Habis';

    $waktu_sekarang = date('Y-m-d H:i:s');

    $insert = $this->db->insert('tb_produk', [
      'id_toko'         => (int) $toko->id_toko,
      'nama_produk'     => $nama_produk,
      'kategori'        => $kategori,
      'deskripsi_produk' => $deskripsi,
      'harga'           => $harga,
      'harga_coret'     => $harga_coret,
      'stok'            => $stok,
      'berat'           => $berat,
      'foto_produk'     => $nama_foto_1,
      'foto_2'          => $hasil_foto_2['nama_file'],
      'foto_3'          => $hasil_foto_3['nama_file'],
      'status_produk'   => $status_produk,
      'terdaftar'       => $waktu_sekarang
    ]);

    $id_produk = (int) $this->db->insert_id();

    if (!$insert || $this->db->trans_status() === false) {
      foreach ($file_baru as $path_file) {
        if (is_file($path_file)) {
          unlink($path_file);
        }
      }

      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Gagal menambahkan produk.'
      ], 500);
      return;
    }

    $this->db->trans_commit();

    $this->api_response([
      'status'  => true,
      'message' => "\u{2705} Produk berhasil ditambahkan ke etalase.",
      'data'    => [
        'id_produk'       => $id_produk,
        'id_toko'         => (int) $toko->id_toko,
        'id_user'         => $id_user,
        'nama_toko'       => $toko->nama_toko,
        'nama_produk'     => $nama_produk,
        'kategori'        => $kategori,
        'deskripsi_produk' => $deskripsi,
        'harga'           => $harga,
        'harga_coret'     => $harga_coret,
        'stok'            => $stok,
        'berat'           => $berat,
        'foto_produk'     => $nama_foto_1,
        'foto_2'          => $hasil_foto_2['nama_file'],
        'foto_3'          => $hasil_foto_3['nama_file'],
        'status_produk'   => $status_produk,
        'cabang_id'       => (int) $toko->cabang_id,
        'terdaftar'       => $waktu_sekarang
      ]
    ], 201);
  }

  // 4B. Endpoint Edit Produk di Etalase (Mendukung 3 Foto, Harga Coret & Kategori)
  public function edit_produk()
  {
    header('Access-Control-Allow-Origin: *');
    header('Content-Type: application/json; charset=UTF-8');
    header('Access-Control-Allow-Methods: POST');

    if ($this->input->method(TRUE) !== 'POST') {
      $this->api_response([
        'status'  => false,
        'message' => 'Metode request tidak diizinkan.'
      ], 405);
      return;
    }

    $auth = $this->authenticate_api();

    if (!$auth) {
      return;
    }

    if ($auth->level !== 'Nasabah') {
      $this->api_response([
        'status'  => false,
        'message' => 'Produk hanya dapat diperbarui oleh pemilik toko.'
      ], 403);
      return;
    }

    $content_length = (int) $this->input->server(
      'CONTENT_LENGTH'
    );

    if ($content_length > 10485760) {
      $this->api_response([
        'status'  => false,
        'message' => 'Ukuran request terlalu besar.'
      ], 413);
      return;
    }

    $request = json_decode(
      $this->input->raw_input_stream,
      true
    );

    if (!is_array($request)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Format JSON tidak valid.'
      ], 400);
      return;
    }

    $id_produk_text = isset($request['id_produk'])
      ? trim((string) $request['id_produk'])
      : '';

    if (
      $id_produk_text === '' ||
      !ctype_digit($id_produk_text) ||
      (int) $id_produk_text < 1
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'ID Produk tidak valid.'
      ], 422);
      return;
    }

    $id_produk = (int) $id_produk_text;
    $id_user = (int) $auth->id_user;

    $nama_produk = isset($request['nama_produk'])
      ? trim((string) $request['nama_produk'])
      : '';

    $kategori = isset($request['kategori'])
      ? trim((string) $request['kategori'])
      : 'Sembako';

    $deskripsi = isset($request['deskripsi_produk'])
      ? trim((string) $request['deskripsi_produk'])
      : '';

    $harga_text = isset($request['harga'])
      ? trim((string) $request['harga'])
      : '';

    $harga_coret_text = isset($request['harga_coret'])
      ? trim((string) $request['harga_coret'])
      : '0';

    $stok_text = isset($request['stok'])
      ? trim((string) $request['stok'])
      : '0';

    $berat_text = isset($request['berat'])
      ? trim((string) $request['berat'])
      : '1000';

    $harga_text = preg_replace(
      '/[.\s]/',
      '',
      $harga_text
    );

    $harga_coret_text = preg_replace(
      '/[.\s]/',
      '',
      $harga_coret_text
    );

    $stok_text = preg_replace(
      '/[\s]/',
      '',
      $stok_text
    );

    $berat_text = preg_replace(
      '/[.\s]/',
      '',
      $berat_text
    );

    if (
      strlen($nama_produk) < 3 ||
      strlen($nama_produk) > 150
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Nama produk harus terdiri dari 3 sampai 150 karakter.'
      ], 422);
      return;
    }

    if (
      strlen($kategori) < 2 ||
      strlen($kategori) > 50
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Kategori harus terdiri dari 2 sampai 50 karakter.'
      ], 422);
      return;
    }

    if (
      !preg_match(
        '/^[\p{L}\p{N}\s&\/().,-]+$/u',
        $kategori
      )
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Kategori mengandung karakter yang tidak diizinkan.'
      ], 422);
      return;
    }

    if (strlen($deskripsi) > 5000) {
      $this->api_response([
        'status'  => false,
        'message' => 'Deskripsi produk maksimal 5.000 karakter.'
      ], 422);
      return;
    }

    if (
      $harga_text === '' ||
      !ctype_digit($harga_text)
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Harga produk harus berupa angka bulat.'
      ], 422);
      return;
    }

    if (
      $harga_coret_text === '' ||
      !ctype_digit($harga_coret_text)
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Harga coret harus berupa angka bulat.'
      ], 422);
      return;
    }

    if (
      $stok_text === '' ||
      !ctype_digit($stok_text)
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Stok harus berupa angka bulat.'
      ], 422);
      return;
    }

    if (
      $berat_text === '' ||
      !ctype_digit($berat_text)
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Berat harus berupa angka bulat dalam gram.'
      ], 422);
      return;
    }

    $harga = (int) $harga_text;
    $harga_coret = (int) $harga_coret_text;
    $stok = (int) $stok_text;
    $berat = (int) $berat_text;

    if ($harga < 1 || $harga > 2000000000) {
      $this->api_response([
        'status'  => false,
        'message' => 'Harga produk tidak valid.'
      ], 422);
      return;
    }

    if (
      $harga_coret < 0 ||
      $harga_coret > 2000000000
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Harga coret tidak valid.'
      ], 422);
      return;
    }

    if (
      $harga_coret > 0 &&
      $harga_coret < $harga
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Harga coret harus lebih besar atau sama dengan harga jual.'
      ], 422);
      return;
    }

    if ($stok < 0 || $stok > 1000000) {
      $this->api_response([
        'status'  => false,
        'message' => 'Jumlah stok tidak valid.'
      ], 422);
      return;
    }

    if ($berat < 1 || $berat > 1000000) {
      $this->api_response([
        'status'  => false,
        'message' => 'Berat produk harus antara 1 dan 1.000.000 gram.'
      ], 422);
      return;
    }

    $foto_1 = $request['foto_base64'] ?? '';
    $foto_2 = $request['foto_base64_2'] ?? '';
    $foto_3 = $request['foto_base64_3'] ?? '';

    if (
      !is_string($foto_1) ||
      !is_string($foto_2) ||
      !is_string($foto_3)
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Format data gambar tidak valid.'
      ], 422);
      return;
    }

    /*
   * id_toko dari request sengaja tidak digunakan.
   * Produk harus ditemukan melalui pemilik Bearer token.
   */
    $this->db->trans_begin();

    $produk = $this->db->query(
      "SELECT
        p.id_produk,
        p.id_toko,
        p.foto_produk,
        p.foto_2,
        p.foto_3,
        p.status_produk,
        t.id_user,
        t.nama_toko,
        t.status_toko,
        u.cabang_id
     FROM tb_produk AS p
     INNER JOIN tb_toko AS t
        ON t.id_toko = p.id_toko
     INNER JOIN tb_user AS u
        ON u.id = t.id_user
     WHERE p.id_produk = ?
       AND t.id_user = ?
     LIMIT 1
     FOR UPDATE",
      [
        $id_produk,
        $id_user
      ]
    )->row();

    if (!$produk) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Produk tidak ditemukan atau bukan milik toko Anda.'
      ], 404);
      return;
    }

    if ($produk->status_toko !== 'Aktif') {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Produk tidak dapat diperbarui karena toko sedang nonaktif.'
      ], 403);
      return;
    }

    if ($produk->status_produk === 'Arsip') {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Produk yang telah diarsipkan tidak dapat diperbarui.'
      ], 409);
      return;
    }

    $file_baru = [];

    $hasil_foto_1 = $this->simpan_gambar_produk_base64(
      $foto_1,
      'produk_1_'
    );

    if (!$hasil_foto_1['status']) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => $hasil_foto_1['message']
      ], 422);
      return;
    }

    if ($hasil_foto_1['path_file'] !== null) {
      $file_baru[] = $hasil_foto_1['path_file'];
    }

    $hasil_foto_2 = $this->simpan_gambar_produk_base64(
      $foto_2,
      'produk_2_'
    );

    if (!$hasil_foto_2['status']) {
      foreach ($file_baru as $path_file) {
        if (is_file($path_file)) {
          @unlink($path_file);
        }
      }

      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => $hasil_foto_2['message']
      ], 422);
      return;
    }

    if ($hasil_foto_2['path_file'] !== null) {
      $file_baru[] = $hasil_foto_2['path_file'];
    }

    $hasil_foto_3 = $this->simpan_gambar_produk_base64(
      $foto_3,
      'produk_3_'
    );

    if (!$hasil_foto_3['status']) {
      foreach ($file_baru as $path_file) {
        if (is_file($path_file)) {
          @unlink($path_file);
        }
      }

      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => $hasil_foto_3['message']
      ], 422);
      return;
    }

    if ($hasil_foto_3['path_file'] !== null) {
      $file_baru[] = $hasil_foto_3['path_file'];
    }

    $status_produk = $stok > 0
      ? 'Tersedia'
      : 'Habis';

    $update_data = [
      'nama_produk'      => $nama_produk,
      'kategori'         => $kategori,
      'deskripsi_produk' => $deskripsi,
      'harga'            => $harga,
      'harga_coret'      => $harga_coret,
      'stok'             => $stok,
      'berat'            => $berat,
      'status_produk'    => $status_produk
    ];

    $file_lama = [];
    $upload_dir = FCPATH . 'assets/produk/';

    if ($hasil_foto_1['nama_file'] !== null) {
      $update_data['foto_produk'] =
        $hasil_foto_1['nama_file'];

      if (
        !empty($produk->foto_produk) &&
        $produk->foto_produk !== 'no-product.png' &&
        basename($produk->foto_produk) ===
        $produk->foto_produk
      ) {
        $file_lama[] =
          $upload_dir . $produk->foto_produk;
      }
    }

    if ($hasil_foto_2['nama_file'] !== null) {
      $update_data['foto_2'] =
        $hasil_foto_2['nama_file'];

      if (
        !empty($produk->foto_2) &&
        basename($produk->foto_2) ===
        $produk->foto_2
      ) {
        $file_lama[] =
          $upload_dir . $produk->foto_2;
      }
    }

    if ($hasil_foto_3['nama_file'] !== null) {
      $update_data['foto_3'] =
        $hasil_foto_3['nama_file'];

      if (
        !empty($produk->foto_3) &&
        basename($produk->foto_3) ===
        $produk->foto_3
      ) {
        $file_lama[] =
          $upload_dir . $produk->foto_3;
      }
    }

    $this->db->where(
      'id_produk',
      (int) $produk->id_produk
    );

    $this->db->where(
      'id_toko',
      (int) $produk->id_toko
    );

    $update = $this->db->update(
      'tb_produk',
      $update_data
    );

    if (
      !$update ||
      $this->db->trans_status() === false
    ) {
      foreach ($file_baru as $path_file) {
        if (is_file($path_file)) {
          @unlink($path_file);
        }
      }

      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Gagal memperbarui produk.'
      ], 500);
      return;
    }

    $this->db->trans_commit();

    /*
   * Foto lama baru dihapus setelah transaksi database
   * berhasil disimpan.
   */
    foreach (array_unique($file_lama) as $path_file) {
      if (is_file($path_file)) {
        @unlink($path_file);
      }
    }

    $foto_produk_hasil =
      $hasil_foto_1['nama_file'] !== null
      ? $hasil_foto_1['nama_file']
      : $produk->foto_produk;

    $foto_2_hasil =
      $hasil_foto_2['nama_file'] !== null
      ? $hasil_foto_2['nama_file']
      : $produk->foto_2;

    $foto_3_hasil =
      $hasil_foto_3['nama_file'] !== null
      ? $hasil_foto_3['nama_file']
      : $produk->foto_3;

    $this->api_response([
      'status'  => true,
      'message' => "\u{2705} Produk berhasil diperbarui.",
      'data'    => [
        'id_produk'       => (int) $produk->id_produk,
        'id_toko'         => (int) $produk->id_toko,
        'id_user'         => $id_user,
        'nama_toko'       => $produk->nama_toko,
        'nama_produk'     => $nama_produk,
        'kategori'        => $kategori,
        'deskripsi_produk' => $deskripsi,
        'harga'           => $harga,
        'harga_coret'     => $harga_coret,
        'stok'            => $stok,
        'berat'           => $berat,
        'foto_produk'     => $foto_produk_hasil,
        'foto_2'          => $foto_2_hasil,
        'foto_3'          => $foto_3_hasil,
        'status_produk'   => $status_produk,
        'cabang_id'       => (int) $produk->cabang_id
      ]
    ]);
  }

  // ==========================================
  // FITUR MARKETPLACE: SISI PEMBELI & CHECKOUT
  // ==========================================

  // 5. Endpoint Etalase Semua Toko (Beranda Marketplace)
  public function get_marketplace()
  {
    header('Access-Control-Allow-Origin: *');
    header('Content-Type: application/json; charset=UTF-8');
    header('Access-Control-Allow-Methods: POST');

    if ($this->input->method(TRUE) !== 'POST') {
      $this->api_response([
        'status'  => false,
        'message' => 'Metode request tidak diizinkan.'
      ], 405);
      return;
    }

    /*
   * Etalase dapat dibaca tanpa login.
   * Jika Bearer dikirim, token wajib valid.
   */
    $authorization =
      $this->get_authorization_header();

    $auth = null;

    if ($authorization !== '') {
      $auth = $this->authenticate_api();

      if (!$auth) {
        return;
      }
    }

    /*
   * id_user dari request tidak digunakan.
   * Wishlist pribadi hanya berasal dari Bearer token Nasabah.
   */
    $id_pembeli = 0;

    if (
      $auth &&
      $auth->level === 'Nasabah'
    ) {
      $id_pembeli = (int) $auth->id_user;
    }

    /*
   * Satu agregasi wishlist digunakan untuk seluruh produk.
   * Parameter id_pembeli dibinding, bukan digabungkan ke SQL.
   */
    $sql = "
    SELECT
      p.id_produk,
      p.id_toko,
      p.nama_produk,
      p.kategori,
      p.deskripsi_produk,
      p.harga,
      p.harga_coret,
      p.stok,
      p.berat,
      p.rating,
      p.terjual,
      p.foto_produk,
      p.foto_2,
      p.foto_3,
      p.status_produk,
      p.terdaftar,

      t.id_user,
      t.nama_toko,
      t.deskripsi_toko,
      t.foto_toko,
      t.alamat_toko,
      t.logo_toko,
      t.status_toko,

      u.nama AS nama_pemilik,
      u.alamat AS alamat_penjual,
      u.telp AS no_hp_toko,
      u.cabang_id,

      c.kode AS kode_cabang,
      c.nama AS nama_cabang,

      COALESCE(w.total_wishlist, 0)
        AS total_wishlist,

      COALESCE(w.is_wishlist, 0)
        AS is_wishlist

    FROM tb_produk AS p

    INNER JOIN tb_toko AS t
      ON t.id_toko = p.id_toko

    INNER JOIN tb_user AS u
      ON u.id = t.id_user

    INNER JOIN tb_cabang AS c
      ON c.id = u.cabang_id

    LEFT JOIN (
      SELECT
        id_produk,
        COUNT(id_wishlist) AS total_wishlist,
        MAX(
          CASE
            WHEN id_pembeli = ? THEN 1
            ELSE 0
          END
        ) AS is_wishlist
      FROM tb_wishlist
      GROUP BY id_produk
    ) AS w
      ON w.id_produk = p.id_produk

    WHERE p.stok > 0
      AND p.status_produk = 'Tersedia'
      AND t.status_toko = 'Aktif'
      AND c.status = 'Aktif'

    ORDER BY p.id_produk DESC
  ";

    $produk = $this->db->query(
      $sql,
      [$id_pembeli]
    )->result_array();

    /*
   * Normalisasi tipe data agar aplikasi menerima angka
   * dan boolean yang konsisten, bukan string dari MySQL.
   */
    foreach ($produk as &$row) {
      $row['id_produk'] = (int) $row['id_produk'];
      $row['id_toko'] = (int) $row['id_toko'];
      $row['id_user'] = (int) $row['id_user'];
      $row['cabang_id'] = (int) $row['cabang_id'];

      $row['harga'] = (int) $row['harga'];
      $row['harga_coret'] = (int) $row['harga_coret'];
      $row['stok'] = (int) $row['stok'];
      $row['berat'] = (int) $row['berat'];
      $row['terjual'] = (int) $row['terjual'];
      $row['rating'] = (float) $row['rating'];

      $row['total_wishlist'] =
        (int) $row['total_wishlist'];

      $row['is_wishlist'] =
        (bool) ((int) $row['is_wishlist']);
    }

    unset($row);

    $this->api_response([
      'status' => true,
      'jumlah' => count($produk),
      'akses'  => [
        'login' => $auth !== null,
        'wishlist_personal' => (
          $auth !== null &&
          $auth->level === 'Nasabah'
        )
      ],
      'data' => $produk
    ]);
  }

  // ==========================================
  // FITUR MARKETPLACE: VALIDASI KERANJANG
  // ==========================================
  public function cek_stok_keranjang()
  {
    header('Access-Control-Allow-Origin: *');
    header('Content-Type: application/json; charset=UTF-8');
    header('Access-Control-Allow-Methods: POST');

    if ($this->input->method(TRUE) !== 'POST') {
      $this->api_response([
        'status'  => false,
        'message' => 'Metode request tidak diizinkan.'
      ], 405);
      return;
    }

    $auth = $this->authenticate_api();

    if (!$auth) {
      return;
    }

    if ($auth->level !== 'Nasabah') {
      $this->api_response([
        'status'  => false,
        'message' => 'Keranjang hanya dapat digunakan oleh Nasabah.'
      ], 403);
      return;
    }

    $content_length = (int) $this->input->server(
      'CONTENT_LENGTH'
    );

    if ($content_length > 1048576) {
      $this->api_response([
        'status'  => false,
        'message' => 'Ukuran request terlalu besar.'
      ], 413);
      return;
    }

    $request = json_decode(
      $this->input->raw_input_stream,
      true
    );

    if (!is_array($request)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Format JSON tidak valid.'
      ], 400);
      return;
    }

    $items = $request['items'] ?? [];

    if (!is_array($items) || empty($items)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Keranjang kosong.'
      ], 422);
      return;
    }

    if (count($items) > 100) {
      $this->api_response([
        'status'  => false,
        'message' => 'Maksimal 100 baris produk dalam keranjang.'
      ], 422);
      return;
    }

    /*
   * Gabungkan produk yang sama agar stok tidak dapat
   * dilewati dengan mengirim beberapa baris duplikat.
   */
    $jumlah_per_produk = [];

    foreach ($items as $item) {
      if (!is_array($item)) {
        $this->api_response([
          'status'  => false,
          'message' => 'Format item keranjang tidak valid.'
        ], 422);
        return;
      }

      $id_produk_raw = $item['id_produk'] ?? null;
      $jumlah_raw = $item['jumlah'] ?? null;

      if (
        (!is_int($id_produk_raw) &&
          !is_string($id_produk_raw)) ||
        (!is_int($jumlah_raw) &&
          !is_string($jumlah_raw))
      ) {
        $this->api_response([
          'status'  => false,
          'message' => 'ID produk dan jumlah harus berupa angka bulat.'
        ], 422);
        return;
      }

      $id_produk_text = trim(
        (string) $id_produk_raw
      );

      $jumlah_text = trim(
        (string) $jumlah_raw
      );

      if (
        $id_produk_text === '' ||
        !ctype_digit($id_produk_text) ||
        (int) $id_produk_text < 1
      ) {
        $this->api_response([
          'status'  => false,
          'message' => 'ID produk pada keranjang tidak valid.'
        ], 422);
        return;
      }

      if (
        $jumlah_text === '' ||
        !ctype_digit($jumlah_text) ||
        (int) $jumlah_text < 1
      ) {
        $this->api_response([
          'status'  => false,
          'message' => 'Jumlah produk minimal 1.'
        ], 422);
        return;
      }

      $id_produk = (int) $id_produk_text;
      $jumlah = (int) $jumlah_text;

      if ($jumlah > 1000000) {
        $this->api_response([
          'status'  => false,
          'message' => 'Jumlah produk melebihi batas yang diizinkan.'
        ], 422);
        return;
      }

      if (!isset($jumlah_per_produk[$id_produk])) {
        $jumlah_per_produk[$id_produk] = 0;
      }

      $jumlah_per_produk[$id_produk] += $jumlah;

      if ($jumlah_per_produk[$id_produk] > 1000000) {
        $this->api_response([
          'status'  => false,
          'message' => 'Total jumlah produk melebihi batas yang diizinkan.'
        ], 422);
        return;
      }
    }

    $id_produk_list = array_keys(
      $jumlah_per_produk
    );

    /*
   * Ambil seluruh produk dalam satu query.
   * Produk, toko, dan cabang harus dalam kondisi aktif.
   */
    $this->db->select(
      'p.id_produk,
     p.id_toko,
     p.nama_produk,
     p.harga,
     p.harga_coret,
     p.stok,
     p.berat,
     p.foto_produk,
     p.status_produk,
     t.id_user AS id_penjual,
     t.nama_toko,
     t.status_toko,
     u.cabang_id,
     c.kode AS kode_cabang,
     c.nama AS nama_cabang'
    );

    $this->db->from('tb_produk AS p');

    $this->db->join(
      'tb_toko AS t',
      't.id_toko = p.id_toko',
      'inner'
    );

    $this->db->join(
      'tb_user AS u',
      'u.id = t.id_user',
      'inner'
    );

    $this->db->join(
      'tb_cabang AS c',
      'c.id = u.cabang_id',
      'inner'
    );

    $this->db->where_in(
      'p.id_produk',
      $id_produk_list
    );

    $this->db->where(
      'p.status_produk',
      'Tersedia'
    );

    $this->db->where(
      't.status_toko',
      'Aktif'
    );

    $this->db->where(
      'c.status',
      'Aktif'
    );

    $produk_database = $this->db
      ->get()
      ->result_array();

    $produk_map = [];

    foreach ($produk_database as $produk) {
      $produk_map[(int) $produk['id_produk']] =
        $produk;
    }

    $data_valid = [];
    $total_belanja = 0;
    $total_item = 0;
    $id_pembeli = (int) $auth->id_user;

    foreach (
      $jumlah_per_produk as
      $id_produk => $jumlah
    ) {
      if (!isset($produk_map[$id_produk])) {
        $this->api_response([
          'status'  => false,
          'message' => "Produk ID {$id_produk} sudah tidak tersedia."
        ], 409);
        return;
      }

      $produk = $produk_map[$id_produk];

      if (
        (int) $produk['id_penjual'] ===
        $id_pembeli
      ) {
        $this->api_response([
          'status'  => false,
          'message' => 'Anda tidak dapat membeli produk dari toko sendiri.'
        ], 403);
        return;
      }

      $stok_tersedia = (int) $produk['stok'];

      if ($stok_tersedia < $jumlah) {
        $this->api_response([
          'status'  => false,
          'message' =>
          'Stok "' .
            $produk['nama_produk'] .
            '" tidak mencukupi. Sisa stok: ' .
            $stok_tersedia . '.',
          'data' => [
            'id_produk' => $id_produk,
            'stok'      => $stok_tersedia,
            'diminta'   => $jumlah
          ]
        ], 409);
        return;
      }

      $harga = (int) $produk['harga'];
      $subtotal = $harga * $jumlah;

      $total_belanja += $subtotal;
      $total_item += $jumlah;

      $data_valid[] = [
        'id_produk'   => $id_produk,
        'id_toko'     => (int) $produk['id_toko'],
        'id_penjual'  => (int) $produk['id_penjual'],
        'nama_produk' => $produk['nama_produk'],
        'nama_toko'   => $produk['nama_toko'],
        'harga'       => $harga,
        'harga_coret' => (int) $produk['harga_coret'],
        'jumlah'      => $jumlah,
        'stok'        => $stok_tersedia,
        'berat'       => (int) $produk['berat'],
        'subtotal'    => $subtotal,
        'foto_produk' => $produk['foto_produk'],
        'cabang_id'   => (int) $produk['cabang_id'],
        'kode_cabang' => $produk['kode_cabang'],
        'nama_cabang' => $produk['nama_cabang']
      ];
    }

    $this->api_response([
      'status'  => true,
      'message' => 'Stok keranjang tersedia.',
      'data'    => [
        'jumlah_produk' => count($data_valid),
        'jumlah_item'   => $total_item,
        'total_belanja' => $total_belanja,
        'items'         => $data_valid
      ]
    ]);
  }


  // ==========================================
  // FITUR LOGISTIK MANUAL (SISTEM NEGO ONGKIR 3 FASE)
  // ==========================================

  // FASE 1: Pembeli Checkout (Status: Menunggu Ongkir) - Tanpa potong saldo & tanpa PIN
  // FASE 1: Pembeli Checkout (Status: Menunggu Ongkir) - Tanpa potong saldo & tanpa PIN
  public function checkout_belanja()
  {
    $request = json_decode($this->input->raw_input_stream, true);

    $id_pembeli = $request['id_pembeli'] ?? '';
    $id_toko = $request['id_toko'] ?? '';
    $total_harga_barang = $request['total_harga'] ?? 0;
    $items = $request['items'] ?? [];
    $catatan = $request['catatan'] ?? '';

    if (empty($id_pembeli) || empty($id_toko) || empty($items)) {
      echo json_encode(['status' => false, 'message' => 'Data pesanan tidak lengkap.']);
      return;
    }

    $this->db->trans_start();
    $invoice = 'INV-' . date('Ymd') . '-' . rand(1000, 9999);

    // Buat pesanan awal
    $this->db->insert('tb_pesanan', [
      'invoice_pesanan' => $invoice,
      'id_pembeli' => $id_pembeli,
      'id_toko' => $id_toko,
      'total_harga' => $total_harga_barang,
      'ongkir' => 0,
      'kurir' => 'Menunggu Penjual',
      'status_pesanan' => 'Menunggu Ongkir', // Status awal
      'catatan_pembeli' => $catatan,
      'terdaftar' => date('Y-m-d H:i:s')
    ]);

    $id_pesanan = $this->db->insert_id();

    // Masukkan detail dan potong stok
    foreach ($items as $item) {
      $this->db->insert('tb_pesanan_detail', [
        'id_pesanan' => $id_pesanan,
        'id_produk' => $item['id_produk'],
        'jumlah' => $item['jumlah'],
        'harga_satuan' => $item['harga'],
        'subtotal' => $item['jumlah'] * $item['harga']
      ]);

      $this->db->set('stok', 'stok - ' . (int)$item['jumlah'], FALSE);
      $this->db->where('id_produk', $item['id_produk']);
      $this->db->update('tb_produk');
    }

    $this->db->trans_complete();

    if ($this->db->trans_status() === FALSE) {
      echo json_encode(['status' => false, 'message' => 'Gagal membuat pesanan.']);
    } else {
      // Notifikasi ke Penjual
      // 🔥 PERBAIKAN: Tambahkan tb_toko.id_user pada SELECT
      $this->db->select('tb_user.expo_token, tb_toko.id_user');
      $this->db->from('tb_toko');
      $this->db->join('tb_user', 'tb_toko.id_user = tb_user.id');
      $this->db->where('tb_toko.id_toko', $id_toko);
      $penjual = $this->db->get()->row();

      // 🔥 PERBAIKAN: Pisahkan simpan ke DB dan kirim push
      if ($penjual) {
        $judul_notif = "🛒 Pesanan Baru Masuk";
        $pesan_notif = "Pesanan ($invoice). Segera cek alamat pembeli dan tentukan tarif Ongkos Kirimnya.";

        // 1. SIMPAN KE DB NOTIFIKASI
        $this->db->insert('tb_notifikasi', [
          'id_user' => $penjual->id_user,
          'judul'   => $judul_notif,
          'pesan'   => $pesan_notif,
          'tanggal' => date('Y-m-d H:i:s')
        ]);

        // 2. KIRIM PUSH NOTIFICATION
        if (!empty($penjual->expo_token)) {
          $this->send_expo_push_notification($penjual->expo_token, $judul_notif, $pesan_notif);
        }
      }
      echo json_encode(['status' => true, 'message' => 'Pesanan terkirim! Menunggu penjual menentukan ongkos kirim.']);
    }
  }
  // FASE 2: Penjual Input Ongkir (Status: Menunggu Pembayaran)
  public function input_ongkir_penjual()
  {
    $request = json_decode($this->input->raw_input_stream, true);

    $id_pesanan = $request['id_pesanan'] ?? '';
    $ongkir = str_replace('.', '', $request['ongkir'] ?? '0');
    $kurir = $request['kurir'] ?? 'Kurir Toko / Lokal';

    if (empty($id_pesanan)) {
      echo json_encode(['status' => false, 'message' => 'ID Pesanan tidak valid.']);
      return;
    }

    $data = [
      'ongkir' => $ongkir,
      'kurir' => $kurir,
      'status_pesanan' => 'Menunggu Pembayaran'
    ];

    $this->db->where('id_pesanan', $id_pesanan);
    $update = $this->db->update('tb_pesanan', $data);

    if ($update) {
      // Beritahu Pembeli Tagihan Sudah Siap
      // 🔥 PERBAIKAN: Tambahkan tb_user.id pada SELECT
      $this->db->select('tb_user.id, tb_user.expo_token, tb_pesanan.invoice_pesanan');
      $this->db->from('tb_pesanan');
      $this->db->join('tb_user', 'tb_pesanan.id_pembeli = tb_user.id');
      $this->db->where('tb_pesanan.id_pesanan', $id_pesanan);
      $info = $this->db->get()->row();

      // 🔥 PERBAIKAN: Pisahkan simpan ke DB dan kirim push
      if ($info) {
        $judul_notif = "💳 Tagihan Siap Dibayar!";
        $pesan_notif = "Penjual telah menetapkan ongkir untuk pesanan " . $info->invoice_pesanan . ". Silakan bayar sekarang.";

        // 1. SIMPAN KE DB NOTIFIKASI
        $this->db->insert('tb_notifikasi', [
          'id_user' => $info->id,
          'judul'   => $judul_notif,
          'pesan'   => $pesan_notif,
          'tanggal' => date('Y-m-d H:i:s')
        ]);

        // 2. KIRIM PUSH NOTIFICATION
        if (!empty($info->expo_token)) {
          $this->send_expo_push_notification($info->expo_token, $judul_notif, $pesan_notif);
        }
      }
      echo json_encode(['status' => true, 'message' => 'Ongkir berhasil ditetapkan. Menunggu pembeli melakukan pembayaran.']);
    } else {
      echo json_encode(['status' => false, 'message' => 'Gagal menyimpan ongkir.']);
    }
  }

  // FASE 3: Pembeli Membayar Pesanan (Status: Diproses) - Menggunakan PIN & Potong Saldo
  public function bayar_pesanan()
  {
    $request = json_decode($this->input->raw_input_stream, true);

    $id_pesanan = $request['id_pesanan'] ?? '';
    $id_pembeli = $request['id_pembeli'] ?? '';
    $pin = $request['pin'] ?? '';

    if (empty($id_pesanan) || empty($id_pembeli) || empty($pin)) {
      echo json_encode(['status' => false, 'message' => 'Data tidak lengkap atau PIN kosong.']);
      return;
    }

    // Validasi PIN
    $this->db->where('id', $id_pembeli);
    $user = $this->db->get('tb_user')->row();
    if (!$user || $user->pin !== $pin) {
      echo json_encode(['status' => false, 'message' => 'PIN transaksi salah!']);
      return;
    }

    // Ambil Data Pesanan
    $this->db->where('id_pesanan', $id_pesanan);
    $this->db->where('status_pesanan', 'Menunggu Pembayaran');
    $pesanan = $this->db->get('tb_pesanan')->row();

    if (!$pesanan) {
      echo json_encode(['status' => false, 'message' => 'Pesanan tidak ditemukan atau sudah dibayar.']);
      return;
    }

    $grand_total = $pesanan->total_harga + $pesanan->ongkir;

    // Cek Saldo
    $tbMsk = $this->db->query("SELECT SUM(nominal) AS total FROM tb_transaksi WHERE idNasabah=? AND jenis='Masuk' AND status_konfirmasi='Sukses'", [$id_pembeli])->row()->total ?? 0;
    $tfMsk = $this->db->query("SELECT SUM(nominal) AS total FROM tb_transfer WHERE idPenerima=?", [$id_pembeli])->row()->total ?? 0;
    $tbKlr = $this->db->query("SELECT SUM(nominal) AS total FROM tb_transaksi WHERE idNasabah=? AND jenis='Keluar' AND status_konfirmasi='Sukses'", [$id_pembeli])->row()->total ?? 0;
    $tfKlr = $this->db->query("SELECT SUM(nominal) AS total FROM tb_transfer WHERE idPengirim=?", [$id_pembeli])->row()->total ?? 0;

    $saldo_aktif = ($tbMsk + $tfMsk) - ($tbKlr + $tfKlr);

    if ($saldo_aktif < $grand_total) {
      echo json_encode(['status' => false, 'message' => 'Saldo tabungan tidak mencukupi. Total belanja + ongkir adalah Rp ' . number_format($grand_total, 0, ',', '.')]);
      return;
    }

    $this->db->trans_start();

    // Kurangi saldo
    $this->db->insert('tb_transaksi', [
      'idAdmin' => 0,
      'idNasabah' => $id_pembeli,
      'idPotongan' => 0,
      'tanggal' => date('Y-m-d'),
      'nominal' => $grand_total,
      'jenis' => 'Keluar',
      'keterangan' => 'Bayar Pesanan: ' . $pesanan->invoice_pesanan,
      'status_konfirmasi' => 'Sukses',
      'terdaftar' => date('Y-m-d H:i:s')
    ]);

    // Update status
    $this->db->where('id_pesanan', $id_pesanan);
    $this->db->update('tb_pesanan', ['status_pesanan' => 'Diproses']);

    $this->db->trans_complete();

    if ($this->db->trans_status() === FALSE) {
      echo json_encode(['status' => false, 'message' => 'Gagal memproses pembayaran. Transaksi dibatalkan.']);
    } else {

      // ==========================================
      // 🔥 1. NOTIFIKASI UNTUK PEMBELI (NASABAH)
      // ==========================================
      $pesan_pembeli = "Pembayaran sebesar Rp " . number_format($grand_total, 0, ',', '.') . " untuk pesanan {$pesanan->invoice_pesanan} berhasil dipotong dari saldo Anda.";

      // Simpan ke menu Lonceng Aplikasi
      $this->db->insert('tb_notifikasi', [
        'id_user' => $id_pembeli,
        'judul'   => "💸 Pembayaran Berhasil!",
        'pesan'   => $pesan_pembeli,
        'tanggal' => date('Y-m-d H:i:s')
      ]);

      // Kirim Push Notification Pop-up
      if (!empty($user->expo_token)) {
        $this->send_expo_push_notification($user->expo_token, "💸 Pembayaran Berhasil!", $pesan_pembeli);
      }


      // ==========================================
      // 🔥 2. NOTIFIKASI UNTUK PENJUAL (TOKO)
      // ==========================================
      $this->db->select('tb_user.id, tb_user.expo_token'); // Tambahan: Ambil ID user penjual
      $this->db->from('tb_toko');
      $this->db->join('tb_user', 'tb_toko.id_user = tb_user.id');
      $this->db->where('tb_toko.id_toko', $pesanan->id_toko);
      $penjual = $this->db->get()->row();

      if ($penjual) {
        $pesan_penjual = "Pembeli sudah melunasi tagihan (Pesanan: " . $pesanan->invoice_pesanan . "). Segera siapkan barang.";

        // Simpan ke menu Lonceng Aplikasi
        $this->db->insert('tb_notifikasi', [
          'id_user' => $penjual->id,
          'judul'   => "💸 Pesanan Telah Dibayar!",
          'pesan'   => $pesan_penjual,
          'tanggal' => date('Y-m-d H:i:s')
        ]);

        // Kirim Push Notification Pop-up
        if (!empty($penjual->expo_token)) {
          $this->send_expo_push_notification($penjual->expo_token, "💸 Pesanan Telah Dibayar!", $pesan_penjual);
        }
      }

      echo json_encode(['status' => true, 'message' => 'Alhamdulillah, pembayaran berhasil! Pesanan sedang diproses penjual.']);
    }
  }

  // ==========================================
  // FITUR MARKETPLACE: MANAJEMEN PESANAN & PENCAIRAN (SETTLEMENT)
  // ==========================================

  // 7. Endpoint Riwayat Pesanan (Bisa untuk Pembeli atau Penjual) - OPTIMIZED O(1)
  public function get_pesanan()
  {
    $request = json_decode($this->input->raw_input_stream, true);
    $role = $request['role'] ?? ''; // 'pembeli' atau 'penjual'
    $id = $request['id'] ?? ''; // id_user (jika pembeli) atau id_toko (jika penjual)

    if (empty($role) || empty($id)) {
      echo json_encode(['status' => false, 'message' => 'Parameter tidak lengkap.']);
      return;
    }

    // --- QUERY 1: Ambil data pesanan utama ---
    // (tb_pesanan.* akan otomatis mengambil kolom 'is_dinilai' yang baru kita buat)
    $this->db->select('tb_pesanan.*, tb_user.nama as nama_pembeli, tb_toko.nama_toko');
    $this->db->from('tb_pesanan');
    $this->db->join('tb_user', 'tb_pesanan.id_pembeli = tb_user.id');
    $this->db->join('tb_toko', 'tb_pesanan.id_toko = tb_toko.id_toko');

    if ($role === 'pembeli') {
      $this->db->where('tb_pesanan.id_pembeli', $id);
    } else if ($role === 'penjual') {
      $this->db->where('tb_pesanan.id_toko', $id);
    }

    $this->db->order_by('tb_pesanan.id_pesanan', 'DESC');
    $pesanan = $this->db->get()->result_array();

    if (empty($pesanan)) {
      echo json_encode(['status' => true, 'data' => []]);
      return;
    }

    // --- OPTIMASI N+1 QUERY ---

    // 1. Kumpulkan semua id_pesanan menggunakan array_column
    $id_pesanan_list = array_column($pesanan, 'id_pesanan');

    // 2. QUERY 2: 🔥 TAMBAHKAN tb_produk.berat AGAR MUNCUL DI RIWAYAT BELANJA 🔥
    $this->db->select('tb_pesanan_detail.*, tb_produk.nama_produk, tb_produk.berat');
    $this->db->from('tb_pesanan_detail');
    $this->db->join('tb_produk', 'tb_pesanan_detail.id_produk = tb_produk.id_produk', 'left');
    $this->db->where_in('tb_pesanan_detail.id_pesanan', $id_pesanan_list);
    $semua_detail = $this->db->get()->result_array();

    // 3. Kelompokkan detail barang berdasarkan id_pesanan menggunakan PHP
    $grouped_detail = [];
    foreach ($semua_detail as $detail) {
      $id_pes = $detail['id_pesanan'];
      if (!isset($grouped_detail[$id_pes])) {
        $grouped_detail[$id_pes] = [];
      }
      $grouped_detail[$id_pes][] = $detail;
    }

    // 4. Masukkan array barang yang sudah dikelompokkan ke data pesanan utama
    $formatted_pesanan = [];
    foreach ($pesanan as $p) {
      $p['items'] = $grouped_detail[$p['id_pesanan']] ?? [];
      $formatted_pesanan[] = $p;
    }

    // Kembalikan hasilnya ke React Native
    echo json_encode(['status' => true, 'data' => $formatted_pesanan]);
  }

  // 8. Endpoint Update Status Pesanan (Oleh Penjual)
  public function update_status_pesanan()
  {
    $request = json_decode($this->input->raw_input_stream, true);
    $id_pesanan = $request['id_pesanan'] ?? '';
    $status_baru = $request['status'] ?? ''; // 'Diproses' atau 'Dikirim'

    if (empty($id_pesanan) || empty($status_baru)) {
      echo json_encode(['status' => false, 'message' => 'Data tidak lengkap.']);
      return;
    }

    $this->db->where('id_pesanan', $id_pesanan);
    $update = $this->db->update('tb_pesanan', ['status_pesanan' => $status_baru]);

    if ($update) {
      // 🔥 NOTIFIKASI KE PEMBELI
      // 🔥 PERBAIKAN: Tambahkan tb_user.id pada SELECT
      $this->db->select('tb_user.id, tb_user.expo_token, tb_pesanan.invoice_pesanan');
      $this->db->from('tb_pesanan');
      $this->db->join('tb_user', 'tb_pesanan.id_pembeli = tb_user.id');
      $this->db->where('tb_pesanan.id_pesanan', $id_pesanan);
      $info = $this->db->get()->row();

      // 🔥 PERBAIKAN: Pisahkan simpan ke DB dan kirim push
      if ($info) {
        $teks_status = ($status_baru === 'Diproses') ? "sedang diproses oleh penjual." : "sudah dalam perjalanan (Dikirim).";
        $judul_notif = "📦 Status Pesanan: " . $status_baru;
        $pesan_notif = "Pesanan " . $info->invoice_pesanan . " Anda " . $teks_status;

        // 1. SIMPAN KE DB NOTIFIKASI
        $this->db->insert('tb_notifikasi', [
          'id_user' => $info->id,
          'judul'   => $judul_notif,
          'pesan'   => $pesan_notif,
          'tanggal' => date('Y-m-d H:i:s')
        ]);

        // 2. KIRIM PUSH NOTIFICATION
        if (!empty($info->expo_token)) {
          $this->send_expo_push_notification($info->expo_token, $judul_notif, $pesan_notif);
        }
      }

      echo json_encode(['status' => true, 'message' => 'Status pesanan berhasil diperbarui menjadi ' . $status_baru]);
    } else {
      echo json_encode(['status' => false, 'message' => 'Gagal memperbarui status.']);
    }
  }

  // 9. Endpoint Selesaikan Pesanan & CAIRKAN DANA KE PENJUAL (Oleh Pembeli)
  public function terima_pesanan()
  {
    if (ob_get_length()) ob_clean(); // 🔥 Mencegah error PHP merusak format JSON di aplikasi

    $request = json_decode($this->input->raw_input_stream, true);
    $id_pesanan = $request['id_pesanan'] ?? '';

    if (empty($id_pesanan)) {
      echo json_encode(['status' => false, 'message' => 'ID Pesanan tidak valid.']);
      return;
    }

    // A. Ambil Data Pesanan dan Toko
    $this->db->select('tb_pesanan.*, tb_toko.id_user as id_pemilik_toko');
    $this->db->from('tb_pesanan');
    $this->db->join('tb_toko', 'tb_pesanan.id_toko = tb_toko.id_toko');
    $this->db->where('tb_pesanan.id_pesanan', $id_pesanan);
    $pesanan = $this->db->get()->row();

    if (!$pesanan) {
      echo json_encode(['status' => false, 'message' => 'Pesanan tidak ditemukan.']);
      return;
    }

    if ($pesanan->status_pesanan === 'Selesai') {
      echo json_encode(['status' => false, 'message' => 'Pesanan ini sudah diselesaikan sebelumnya.']);
      return;
    }

    // B. 🔥 MULAI TRANSAKSI PENCAIRAN DANA 🔥
    $this->db->trans_start();

    // 1. Ubah status pesanan menjadi Selesai
    $this->db->where('id_pesanan', $id_pesanan);
    $this->db->update('tb_pesanan', ['status_pesanan' => 'Selesai']);

    // 2. Tambahkan Saldo ke Pemilik Toko (Insert ke tb_transaksi)
    $this->db->insert('tb_transaksi', [
      'idAdmin' => 0, // Sistem otomatis
      'idNasabah' => $pesanan->id_pemilik_toko, // Uang masuk ke ID Nasabah si Pemilik Toko
      'idPotongan' => 0,
      'tanggal' => date('Y-m-d'),
      'nominal' => $pesanan->total_harga,
      'jenis' => 'Masuk',
      'keterangan' => 'Pencairan Dana Penjualan: ' . $pesanan->invoice_pesanan,
      'status_konfirmasi' => 'Sukses',
      'terdaftar' => date('Y-m-d H:i:s')
    ]);

    // 3. Tambah Angka "Terjual" di Produk
    $detail_pesanan = $this->db->get_where('tb_pesanan_detail', ['id_pesanan' => $id_pesanan])->result_array();
    foreach ($detail_pesanan as $item) {
      $this->db->set('terjual', 'terjual + ' . (int)$item['jumlah'], FALSE);
      $this->db->where('id_produk', $item['id_produk']);
      $this->db->update('tb_produk');
    }

    // C. Selesaikan Transaksi
    $this->db->trans_complete();

    if ($this->db->trans_status() === FALSE) {
      echo json_encode(['status' => false, 'message' => 'Gagal memproses pencairan dana. Hubungi Admin.']);
    } else {
      // 🔥 NOTIFIKASI KE PENJUAL BAHWA DANA CAIR (DIPERBAIKI)
      $this->db->select('expo_token, id');
      $this->db->where('id', $pesanan->id_pemilik_toko);
      $penjual = $this->db->get('tb_user')->row();

      if ($penjual) {
        $nominal_rp = 'Rp ' . number_format($pesanan->total_harga, 0, ',', '.');
        $judul_notif = "✅ Alhamdulillah, Dana Cair!";
        $pesan_notif = "Pesanan " . $pesanan->invoice_pesanan . " telah diterima pembeli. Dana " . $nominal_rp . " berhasil masuk ke tabungan Anda.";

        // Simpan ke Lonceng Notifikasi Penjual
        $this->db->insert('tb_notifikasi', [
          'id_user' => $penjual->id,
          'judul'   => $judul_notif,
          'pesan'   => $pesan_notif,
          'is_read' => 0,
          'tanggal' => date('Y-m-d H:i:s')
        ]);

        if (!empty($penjual->expo_token)) {
          $this->send_expo_push_notification($penjual->expo_token, $judul_notif, $pesan_notif);
        }
      }

      echo json_encode(['status' => true, 'message' => 'Pesanan selesai! Dana telah diteruskan ke saldo tabungan Penjual.']);
    }
  }

  // 10. Endpoint Batalkan Pesanan (Sistem Nego Ongkir)
  public function batalkan_pesanan()
  {
    if (ob_get_length()) ob_clean(); // 🔥 Mencegah error PHP merusak format JSON di aplikasi

    $request = json_decode($this->input->raw_input_stream, true);
    $id_pesanan = $request['id_pesanan'] ?? '';
    $id_pembeli = $request['id_pembeli'] ?? '';

    if (empty($id_pesanan) || empty($id_pembeli)) {
      echo json_encode(['status' => false, 'message' => 'Data tidak lengkap.']);
      return;
    }

    $this->db->trans_start();

    // 1. Cek Pesanan
    $pesanan = $this->db->get_where('tb_pesanan', ['id_pesanan' => $id_pesanan, 'id_pembeli' => $id_pembeli])->row_array();

    // Hanya boleh dibatalkan jika belum masuk tahap 'Diproses' (Belum dibayar)
    if (!$pesanan || ($pesanan['status_pesanan'] !== 'Menunggu Ongkir' && $pesanan['status_pesanan'] !== 'Menunggu Pembayaran')) {
      echo json_encode(['status' => false, 'message' => 'Pesanan sudah dibayar/diproses dan tidak bisa dibatalkan sendiri.']);
      return;
    }

    // 2. Ubah Status Pesanan menjadi Dibatalkan
    $this->db->where('id_pesanan', $id_pesanan);
    $this->db->update('tb_pesanan', ['status_pesanan' => 'Dibatalkan']);

    // 3. KEMBALIKAN STOK BARANG (Karena saat checkout awal stok sudah terpotong/dibooking)
    $detail_pesanan = $this->db->get_where('tb_pesanan_detail', ['id_pesanan' => $id_pesanan])->result_array();
    foreach ($detail_pesanan as $item) {
      $this->db->set('stok', 'stok + ' . (int)$item['jumlah'], FALSE);
      $this->db->where('id_produk', $item['id_produk']);
      $this->db->update('tb_produk');
    }

    $this->db->trans_complete();

    if ($this->db->trans_status() === FALSE) {
      echo json_encode(['status' => false, 'message' => 'Gagal membatalkan pesanan.']);
    } else {
      // 🔥 NOTIFIKASI KE PENJUAL BAHWA PESANAN DIBATALKAN PEMBELI (DIPERBAIKI)
      $this->db->select('tb_user.expo_token, tb_toko.id_user'); // Tambahkan tb_toko.id_user
      $this->db->from('tb_toko');
      $this->db->join('tb_user', 'tb_toko.id_user = tb_user.id');
      $this->db->where('tb_toko.id_toko', $pesanan['id_toko']);
      $penjual = $this->db->get()->row();

      if ($penjual) {
        $judul_notif = "❌ Pesanan Dibatalkan";
        $pesan_notif = "Pesanan " . $pesanan['invoice_pesanan'] . " baru saja dibatalkan oleh pembeli. Stok barang telah dikembalikan.";

        // Simpan ke Lonceng Notifikasi Penjual
        $this->db->insert('tb_notifikasi', [
          'id_user' => $penjual->id_user,
          'judul'   => $judul_notif,
          'pesan'   => $pesan_notif,
          'is_read' => 0,
          'tanggal' => date('Y-m-d H:i:s')
        ]);

        if (!empty($penjual->expo_token)) {
          $this->send_expo_push_notification($penjual->expo_token, $judul_notif, $pesan_notif);
        }
      }

      echo json_encode(['status' => true, 'message' => 'Pesanan berhasil dibatalkan. Stok barang telah dikembalikan ke toko.']);
    }
  }


  // 11. Endpoint Hapus Produk (Soft Delete)
  public function hapus_produk()
  {
    $request = json_decode($this->input->raw_input_stream, true);
    $id_produk = $request['id_produk'] ?? '';

    if (empty($id_produk)) {
      echo json_encode(['status' => false, 'message' => 'ID Produk tidak valid.']);
      return;
    }

    $this->db->where('id_produk', $id_produk);
    $update = $this->db->update('tb_produk', ['status_produk' => 'Arsip']);

    if ($update) {
      echo json_encode(['status' => true, 'message' => 'Produk berhasil dihapus dari etalase.']);
    } else {
      echo json_encode(['status' => false, 'message' => 'Gagal menghapus produk.']);
    }
  }


  // ==========================================
  // FITUR MARKETPLACE: SISI ADMIN (PUSAT KENDALI)
  // ==========================================

  // 12. Endpoint Admin: Ambil Semua Pesanan dari Semua Toko
  public function admin_get_semua_pesanan()
  {
    if (ob_get_length()) ob_clean(); // 🔥 PENGAMAN JSON

    $request = json_decode($this->input->raw_input_stream, true);
    $level = $request['level'] ?? '';

    if ($level !== 'Administrator' && $level !== 'Super Admin') {
      echo json_encode(['status' => false, 'message' => 'Akses ditolak. Khusus Admin.']);
      return;
    }

    $this->db->select('tb_pesanan.*, tb_user.nama as nama_pembeli, tb_toko.nama_toko');
    $this->db->from('tb_pesanan');
    $this->db->join('tb_user', 'tb_pesanan.id_pembeli = tb_user.id');
    $this->db->join('tb_toko', 'tb_pesanan.id_toko = tb_toko.id_toko');
    $this->db->order_by('tb_pesanan.id_pesanan', 'DESC');
    $pesanan = $this->db->get()->result_array();

    echo json_encode(['status' => true, 'data' => $pesanan]);
  }

  // 13. Endpoint Admin: Batalkan Paksa Pesanan & Refund
  public function admin_batalkan_pesanan()
  {
    if (ob_get_length()) ob_clean(); // 🔥 PENGAMAN JSON

    $request = json_decode($this->input->raw_input_stream, true);
    $id_pesanan = $request['id_pesanan'] ?? '';
    $level = $request['level'] ?? '';

    if (!in_array($level, ['Administrator', 'Super Admin']) || empty($id_pesanan)) {
      echo json_encode(['status' => false, 'message' => 'Akses ditolak atau data tidak valid.']);
      return;
    }

    $this->db->trans_start();

    // 1. Cek Pesanan
    $pesanan = $this->db->get_where('tb_pesanan', ['id_pesanan' => $id_pesanan])->row_array();

    if (!$pesanan || $pesanan['status_pesanan'] === 'Selesai' || $pesanan['status_pesanan'] === 'Dibatalkan') {
      echo json_encode(['status' => false, 'message' => 'Pesanan sudah selesai atau sudah dibatalkan sebelumnya.']);
      return;
    }

    // SIMPAN STATUS LAMA SEBELUM DIUBAH (Untuk Pengecekan Refund)
    $status_lama = $pesanan['status_pesanan'];

    // 2. Ubah Status Pesanan
    $this->db->where('id_pesanan', $id_pesanan);
    $this->db->update('tb_pesanan', ['status_pesanan' => 'Dibatalkan']);

    // 3. KEMBALIKAN STOK BARANG KE TOKO
    $detail_pesanan = $this->db->get_where('tb_pesanan_detail', ['id_pesanan' => $id_pesanan])->result_array();
    foreach ($detail_pesanan as $item) {
      $this->db->set('stok', 'stok + ' . (int)$item['jumlah'], FALSE);
      $this->db->where('id_produk', $item['id_produk']);
      $this->db->update('tb_produk');
    }

    // 4. LAKUKAN REFUND HANYA JIKA PEMBELI SUDAH BAYAR
    $is_refunded = false;
    if ($status_lama === 'Diproses' || $status_lama === 'Dikirim') {
      $grand_total = $pesanan['total_harga'] + $pesanan['ongkir']; // Refund Harga Barang + Ongkir

      $this->db->insert('tb_transaksi', [
        'idAdmin' => 0, // 0 karena otomatis
        'idNasabah' => $pesanan['id_pembeli'],
        'idPotongan' => 0,
        'tanggal' => date('Y-m-d'),
        'nominal' => $grand_total,
        'jenis' => 'Masuk',
        'keterangan' => 'Refund pembatalan Admin (INV: ' . $pesanan['invoice_pesanan'] . ')',
        'status_konfirmasi' => 'Sukses',
        'terdaftar' => date('Y-m-d H:i:s')
      ]);

      $is_refunded = true;
    }

    $this->db->trans_complete();

    if ($this->db->trans_status() === FALSE) {
      echo json_encode(['status' => false, 'message' => 'Gagal melakukan pembatalan pesanan.']);
    } else {

      // 🔥 1. NOTIFIKASI KE PEMBELI (DIPERBAIKI)
      $this->db->select('id, expo_token');
      $this->db->where('id', $pesanan['id_pembeli']);
      $pembeli = $this->db->get('tb_user')->row();

      if ($pembeli) {
        $teks_refund = $is_refunded ? " Dana Anda (termasuk ongkir) telah dikembalikan ke saldo tabungan." : "";
        $judul_notif = "⚠️ Pesanan Dibatalkan Admin";
        $pesan_notif = "Pesanan " . $pesanan['invoice_pesanan'] . " dibatalkan oleh Admin." . $teks_refund;

        // Simpan ke Lonceng Pembeli
        $this->db->insert('tb_notifikasi', [
          'id_user' => $pembeli->id,
          'judul'   => $judul_notif,
          'pesan'   => $pesan_notif,
          'is_read' => 0,
          'tanggal' => date('Y-m-d H:i:s')
        ]);

        if (!empty($pembeli->expo_token)) {
          $this->send_expo_push_notification($pembeli->expo_token, $judul_notif, $pesan_notif);
        }
      }

      // 🔥 2. NOTIFIKASI KE PENJUAL (DIPERBAIKI)
      $this->db->select('tb_user.expo_token, tb_toko.id_user'); // Ditambahkan tb_toko.id_user
      $this->db->from('tb_toko');
      $this->db->join('tb_user', 'tb_toko.id_user = tb_user.id');
      $this->db->where('tb_toko.id_toko', $pesanan['id_toko']);
      $penjual = $this->db->get()->row();

      if ($penjual) {
        $judul_notif_penjual = "⚠️ Pesanan Dibatalkan Admin";
        $pesan_notif_penjual = "Pesanan " . $pesanan['invoice_pesanan'] . " dibatalkan secara paksa oleh Admin. Stok barang telah dikembalikan ke etalase Anda.";

        // Simpan ke Lonceng Penjual
        $this->db->insert('tb_notifikasi', [
          'id_user' => $penjual->id_user,
          'judul'   => $judul_notif_penjual,
          'pesan'   => $pesan_notif_penjual,
          'is_read' => 0,
          'tanggal' => date('Y-m-d H:i:s')
        ]);

        if (!empty($penjual->expo_token)) {
          $this->send_expo_push_notification($penjual->expo_token, $judul_notif_penjual, $pesan_notif_penjual);
        }
      }

      $pesan_sukses = $is_refunded ? 'Pesanan berhasil dibatalkan secara paksa dan dana (termasuk ongkir) dikembalikan ke pembeli.' : 'Pesanan berhasil dibatalkan. (Tidak ada refund karena belum dibayar).';
      echo json_encode(['status' => true, 'message' => $pesan_sukses]);
    }
  }

  // 12. Endpoint Simpan Ulasan Pembeli
  public function simpan_ulasan()
  {
    $request = json_decode($this->input->raw_input_stream, true);

    $id_pesanan = $request['id_pesanan'] ?? '';
    $id_pembeli = $request['id_pembeli'] ?? '';
    $bintang = $request['bintang'] ?? 5;
    $komentar = $request['komentar'] ?? '';

    if (empty($id_pesanan) || empty($id_pembeli)) {
      echo json_encode(['status' => false, 'message' => 'Data tidak valid.']);
      return;
    }

    $this->db->trans_start();

    // 1. Tandai pesanan ini sudah dinilai
    $this->db->where('id_pesanan', $id_pesanan);
    $this->db->update('tb_pesanan', ['is_dinilai' => 1]);

    // 2. Ambil semua barang yang ada di dalam pesanan ini
    $items = $this->db->get_where('tb_pesanan_detail', ['id_pesanan' => $id_pesanan])->result_array();

    foreach ($items as $item) {
      // Masukkan ulasan ke tabel
      $this->db->insert('tb_ulasan', [
        'id_pesanan' => $id_pesanan,
        'id_produk'  => $item['id_produk'],
        'id_pembeli' => $id_pembeli,
        'bintang'    => $bintang,
        'komentar'   => $komentar,
        'tanggal'    => date('Y-m-d H:i:s')
      ]);

      // 3. Hitung ulang RATA-RATA bintang untuk produk ini
      $this->db->select_avg('bintang', 'rata_rata');
      $this->db->where('id_produk', $item['id_produk']);
      $avg_query = $this->db->get('tb_ulasan')->row();

      $rata_rata_baru = round($avg_query->rata_rata, 1); // Dibulatkan 1 angka di belakang koma (misal: 4.8)

      // 4. Update rating di tabel produk
      $this->db->where('id_produk', $item['id_produk']);
      $this->db->update('tb_produk', ['rating' => $rata_rata_baru]);
    }

    $this->db->trans_complete();

    if ($this->db->trans_status() === FALSE) {
      echo json_encode(['status' => false, 'message' => 'Gagal menyimpan ulasan.']);
    } else {
      echo json_encode(['status' => true, 'message' => 'Terima kasih! Ulasan Anda sangat membantu penjual.']);
    }
  }
  // 14. Endpoint Ambil Ulasan Produk (Untuk Detail Produk)
  public function get_ulasan_produk()
  {
    $request = json_decode($this->input->raw_input_stream, true);
    $id_produk = $request['id_produk'] ?? '';

    if (empty($id_produk)) {
      echo json_encode(['status' => false, 'message' => 'ID Produk tidak valid.']);
      return;
    }

    $this->db->select('tb_ulasan.*, tb_user.nama as nama_pembeli');
    $this->db->from('tb_ulasan');
    $this->db->join('tb_user', 'tb_ulasan.id_pembeli = tb_user.id');
    $this->db->where('tb_ulasan.id_produk', $id_produk);
    $this->db->order_by('tb_ulasan.id_ulasan', 'DESC'); // Ulasan terbaru di atas
    $ulasan = $this->db->get()->result_array();

    echo json_encode(['status' => true, 'data' => $ulasan]);
  }

  // 15. Endpoint Cek Status Wishlist di Detail Produk
  public function cek_wishlist()
  {
    $request = json_decode($this->input->raw_input_stream, true);
    $id_pembeli = $request['id_pembeli'] ?? '';
    $id_produk = $request['id_produk'] ?? '';

    if (empty($id_pembeli) || empty($id_produk)) {
      echo json_encode(['status' => false, 'is_wishlisted' => false]);
      return;
    }

    $cek = $this->db->get_where('tb_wishlist', ['id_pembeli' => $id_pembeli, 'id_produk' => $id_produk])->row();

    if ($cek) {
      echo json_encode(['status' => true, 'is_wishlisted' => true]);
    } else {
      echo json_encode(['status' => true, 'is_wishlisted' => false]);
    }
  }

  // 16. Endpoint Toggle Wishlist (Tambah / Hapus)
  public function toggle_wishlist()
  {
    $request = json_decode($this->input->raw_input_stream, true);
    $id_pembeli = $request['id_pembeli'] ?? '';
    $id_produk = $request['id_produk'] ?? '';

    if (empty($id_pembeli) || empty($id_produk)) {
      echo json_encode(['status' => false, 'message' => 'Data tidak valid.']);
      return;
    }

    $cek = $this->db->get_where('tb_wishlist', ['id_pembeli' => $id_pembeli, 'id_produk' => $id_produk])->row();

    if ($cek) {
      // Jika sudah ada, hapus dari wishlist
      $this->db->where('id_wishlist', $cek->id_wishlist);
      $this->db->delete('tb_wishlist');
      echo json_encode(['status' => true, 'action' => 'removed', 'message' => 'Dihapus dari favorit.']);
    } else {
      // Jika belum ada, tambahkan ke wishlist
      $this->db->insert('tb_wishlist', [
        'id_pembeli' => $id_pembeli,
        'id_produk' => $id_produk,
        'tanggal' => date('Y-m-d H:i:s')
      ]);
      echo json_encode(['status' => true, 'action' => 'added', 'message' => 'Ditambahkan ke favorit!']);
    }
  }

  // 17. Endpoint Ambil Daftar Wishlist Pembeli
  public function get_wishlist_pembeli()
  {
    $request = json_decode($this->input->raw_input_stream, true);
    $id_pembeli = $request['id_pembeli'] ?? '';

    if (empty($id_pembeli)) {
      echo json_encode(['status' => false, 'message' => 'ID Pembeli tidak valid.']);
      return;
    }

    $this->db->select('tb_wishlist.id_wishlist, tb_produk.*, tb_toko.nama_toko');
    $this->db->from('tb_wishlist');
    $this->db->join('tb_produk', 'tb_wishlist.id_produk = tb_produk.id_produk');
    $this->db->join('tb_toko', 'tb_produk.id_toko = tb_toko.id_toko');

    $this->db->where('tb_wishlist.id_pembeli', $id_pembeli);
    $this->db->where('tb_produk.status_produk', 'Tersedia');

    // 🔥 TAMBAHAN BARU: Sembunyikan juga dari daftar jika toko dinonaktifkan admin
    $this->db->where('tb_toko.status_toko', 'Aktif');

    $this->db->order_by('tb_wishlist.id_wishlist', 'DESC');

    $wishlist = $this->db->get()->result_array();

    if ($wishlist) {
      echo json_encode(['status' => true, 'data' => $wishlist]);
    } else {
      echo json_encode(['status' => true, 'data' => []]);
    }
  }

  // 18. Endpoint Hitung Jumlah Wishlist (Untuk Badge Notifikasi)
  public function count_wishlist()
  {
    $request = json_decode($this->input->raw_input_stream, true);
    $id_user = $request['id_user'] ?? '';

    if (empty($id_user)) {
      echo json_encode(['status' => false, 'count' => 0]);
      return;
    }

    // 🔥 PERBAIKAN: Harus join ke tabel produk dan toko untuk validasi status
    $this->db->from('tb_wishlist');
    $this->db->join('tb_produk', 'tb_wishlist.id_produk = tb_produk.id_produk');
    $this->db->join('tb_toko', 'tb_produk.id_toko = tb_toko.id_toko');

    $this->db->where('tb_wishlist.id_pembeli', $id_user);
    $this->db->where('tb_produk.status_produk', 'Tersedia'); // Jangan hitung jika diarsip
    $this->db->where('tb_toko.status_toko', 'Aktif');        // Jangan hitung jika toko dibekukan

    $count = $this->db->get()->num_rows();

    echo json_encode(['status' => true, 'count' => $count]);
  }

  // 19. Endpoint Ambil Daftar Notifikasi User
  public function get_notifikasi()
  {
    $request = json_decode($this->input->raw_input_stream, true);
    $id_user = $request['id_user'] ?? '';

    if (empty($id_user)) {
      echo json_encode(['status' => false, 'data' => []]);
      return;
    }

    $this->db->where('id_user', $id_user);
    $this->db->order_by('id_notifikasi', 'DESC');
    $notifikasi = $this->db->get('tb_notifikasi')->result_array();

    echo json_encode(['status' => true, 'data' => $notifikasi]);
  }

  // 20. Endpoint Tandai Notifikasi Telah Dibaca
  public function tandai_dibaca()
  {
    $request = json_decode($this->input->raw_input_stream, true);
    $id_notifikasi = $request['id_notifikasi'] ?? '';

    if (!empty($id_notifikasi)) {
      $this->db->where('id_notifikasi', $id_notifikasi);
      $this->db->update('tb_notifikasi', ['is_read' => 1]);
    }
    echo json_encode(['status' => true]);
  }

  // 21. Endpoint Hitung Notifikasi Belum Dibaca
  public function count_unread_notif()
  {
    $request = json_decode($this->input->raw_input_stream, true);
    $id_user = $request['id_user'] ?? '';

    if (empty($id_user)) {
      echo json_encode(['status' => false, 'count' => 0]);
      return;
    }

    $this->db->where('id_user', $id_user);
    $this->db->where('is_read', 0); // Hanya hitung yang belum dibaca
    $count = $this->db->get('tb_notifikasi')->num_rows();

    echo json_encode(['status' => true, 'count' => $count]);
  }

  // 22. Endpoint Hapus Semua Notifikasi User
  public function clear_notifikasi()
  {
    $request = json_decode($this->input->raw_input_stream, true);
    $id_user = $request['id_user'] ?? '';

    if (empty($id_user)) {
      echo json_encode(['status' => false, 'message' => 'ID User tidak valid.']);
      return;
    }

    $this->db->where('id_user', $id_user);
    $delete = $this->db->delete('tb_notifikasi');

    if ($delete) {
      echo json_encode(['status' => true, 'message' => 'Semua notifikasi berhasil dihapus.']);
    } else {
      echo json_encode(['status' => false, 'message' => 'Gagal menghapus notifikasi.']);
    }
  }

  // ==========================================
  // FITUR MARKETPLACE: BANNER DINAMIS
  // ==========================================

  // 1. Ambil Data Banner Marketplace
  public function get_banner_market()
  {
    $this->db->order_by('id', 'DESC');
    $data = $this->db->get('tb_banner_market')->result_array();
    echo json_encode(['status' => true, 'data' => $data]);
  }

  // 2. Upload Banner Marketplace (Bebas Cache + Push Notif)
  public function upload_banner_market()
  {
    if (ob_get_length()) ob_clean(); // Cegah error PHP merusak JSON
    header('Content-Type: application/json');
    header('Access-Control-Allow-Origin: *');

    $config['upload_path']   = FCPATH . 'assets/';
    $config['allowed_types'] = 'jpg|jpeg|png';
    $config['max_size']      = 5120;

    $config['file_name']     = 'banner_mkt_' . time() . '_' . rand(1000, 9999);

    $this->load->library('upload', $config);
    $this->upload->initialize($config);

    if (!$this->upload->do_upload('banner_image')) {
      $error = $this->upload->display_errors('', '');
      echo json_encode(['status' => false, 'message' => 'Gagal mengunggah: ' . $error]);
    } else {
      $upload_data = $this->upload->data();

      // Simpan nama file ke database
      $this->db->insert('tb_banner_market', [
        'gambar' => $upload_data['file_name'],
        'terdaftar' => date('Y-m-d H:i:s')
      ]);

      // ========================================================
      // 🔥 FITUR BARU: BROADCAST PUSH NOTIFIKASI KE SEMUA NASABAH
      // ========================================================
      $judul_notif = "🎉 Promo Baru di Marketplace!";
      $pesan_notif = "Admin baru saja menambahkan promo menarik. Yuk, cek sekarang di aplikasi sebelum kehabisan!";

      // Ambil semua Nasabah yang sudah memiliki expo_token
      $this->db->where('level', 'Nasabah');
      $nasabahs = $this->db->get('tb_user')->result();

      foreach ($nasabahs as $nsb) {
        // 1. Simpan ke database agar muncul di Lonceng Notifikasi aplikasi
        $this->db->insert('tb_notifikasi', [
          'id_user' => $nsb->id,
          'judul'   => $judul_notif,
          'pesan'   => $pesan_notif,
          'is_read' => 0,
          'tanggal' => date('Y-m-d H:i:s')
        ]);

        // 2. Tembakkan Pop-up Layar HP (Push Notif) jika tokennya tidak kosong
        if (!empty($nsb->expo_token)) {
          $this->send_expo_push_notification(
            $nsb->expo_token,
            $judul_notif,
            $pesan_notif
          );
        }
      }
      // ========================================================

      echo json_encode(['status' => true, 'message' => 'Banner berhasil dipublikasikan dan Notifikasi telah disebar ke Nasabah!']);
    }
    exit;
  }

  // 3. Hapus Banner Marketplace
  public function hapus_banner_market()
  {
    $input = json_decode(file_get_contents('php://input'), true);
    $id_banner = $input['id_banner'] ?? '';

    $banner = $this->db->get_where('tb_banner_market', ['id' => $id_banner])->row();

    if ($banner) {
      $file_path = FCPATH . 'assets/' . $banner->gambar;
      if (file_exists($file_path)) {
        unlink($file_path);
      } // Hapus file fisik

      $this->db->where('id', $id_banner);
      $this->db->delete('tb_banner_market'); // Hapus dari database
      echo json_encode(['status' => true, 'message' => 'Banner berhasil dihapus!']);
    } else {
      echo json_encode(['status' => false, 'message' => 'Data banner tidak ditemukan.']);
    }
  }

  public function simpan_emas()
  {
    $request = json_decode($this->input->raw_input_stream, true);

    if ($_SERVER['REQUEST_METHOD'] !== 'POST' || empty($request)) {
      echo json_encode(['status' => false, 'message' => 'Permintaan tidak valid.']);
      return;
    }

    $id_nasabah = $request['id_nasabah'] ?? 0;
    $nominal_rupiah = str_replace('.', '', $request['nominal'] ?? '0');
    $idAdmin = 0;

    if (empty($id_nasabah) || empty($nominal_rupiah)) {
      echo json_encode(['status' => false, 'message' => 'Data tidak lengkap!']);
      return;
    }

    $today = date('Y-m-d');

    // 🔥 REVISI: Selalu ambil harga acuan terbaru (baris terakhir) yang diinput Admin
    $this->db->order_by('id', 'DESC');
    $this->db->limit(1);
    $harga_emas = $this->db->get('tb_harga_emas')->row();

    if (!$harga_emas) {
      echo json_encode(['status' => false, 'message' => 'Harga emas acuan belum diatur oleh Admin.']);
      return;
    }

    $gram_didapat = $nominal_rupiah / $harga_emas->harga_beli;
    $gram_bulat = round($gram_didapat, 4);

    $file_name = null;
    // ... (Proses upload bukti transfer jika ada biarkan seperti aslinya)

    // 4. Siapkan Data Transaksi
    $data = [
      'idAdmin'           => $idAdmin,
      'idNasabah'         => $id_nasabah,
      'idPotongan'        => 0,
      'tanggal'           => $today,
      'nominal'           => $nominal_rupiah,
      'jenis'             => 'Keluar',
      'keterangan'        => 'Nabung Emas ' . $gram_bulat . ' Gram',
      'status_konfirmasi' => 'Sukses',
      'bukti_transfer'    => $file_name,
      'gram_emas'         => $gram_bulat,
      'terdaftar'         => date('Y-m-d H:i:s')
    ];

    $insert = $this->db->insert('tb_transaksi', $data);

    if ($insert) {
      $this->db->where('id', $id_nasabah);
      $nasabah = $this->db->get('tb_user')->row();
      $nama_nasabah = $nasabah ? $nasabah->nama : 'Nasabah';

      // NOTIFIKASI WA ADMIN
      $pesan_wa = "✨ *PEMBELIAN EMAS BARU*\n\n";
      $pesan_wa .= "Halo Admin, nasabah telah membeli emas (Selesai Otomatis):\n";
      $pesan_wa .= "👤 *Nama:* " . $nama_nasabah . "\n";
      $pesan_wa .= "💰 *Nominal:* Rp " . number_format($nominal_rupiah, 0, ',', '.') . "\n";
      $pesan_wa .= "⚖️ *Emas:* " . $gram_bulat . " Gram\n";

      $nomor_admin = '081234567890';
      $this->send_whatsapp($nomor_admin, $pesan_wa);

      // 1. SIMPAN RIWAYAT & PUSH NOTIFIKASI KE NASABAH
      $pesan_nasabah = "Selamat! Tabungan emas Anda bertambah " . $gram_bulat . " Gram. Saldo utama telah dipotong Rp " . number_format($nominal_rupiah, 0, ',', '.');

      $this->db->insert('tb_notifikasi', [
        'id_user' => $id_nasabah,
        'judul'   => '✨ Beli Emas Berhasil!',
        'pesan'   => $pesan_nasabah,
        'is_read' => 0,
        'tanggal' => date('Y-m-d H:i:s')
      ]);

      if (!empty($nasabah->expo_token)) {
        $this->send_expo_push_notification(
          $nasabah->expo_token,
          "✨ Beli Emas Berhasil!",
          $pesan_nasabah
        );
      }

      // 2. SIMPAN RIWAYAT & PUSH NOTIFIKASI KE SEMUA ADMIN
      $pesan_admin = "Nasabah " . $nama_nasabah . " telah membeli " . $gram_bulat . " Gram emas seharga Rp " . number_format($nominal_rupiah, 0, ',', '.');

      $admins = $this->db->where_in('level', ['Administrator', 'Super Admin'])->get('tb_user')->result();
      foreach ($admins as $admin) {

        $this->db->insert('tb_notifikasi', [
          'id_user' => $admin->id,
          'judul'   => '✨ Pembelian Emas Baru',
          'pesan'   => $pesan_admin,
          'is_read' => 0,
          'tanggal' => date('Y-m-d H:i:s')
        ]);

        if (!empty($admin->expo_token)) {
          $this->send_expo_push_notification(
            $admin->expo_token,
            "✨ Pembelian Emas Baru",
            $pesan_admin
          );
        }
      }

      echo json_encode([
        'status' => true,
        'message' => 'Pembelian Emas berhasil! Saldo utama Anda telah dipotong.',
        'gram_didapat' => $gram_bulat
      ]);
    } else {
      echo json_encode(['status' => false, 'message' => 'Gagal memproses transaksi emas.']);
    }
  }

  // ==========================================
  // API UNTUK MENGHITUNG TOTAL GRAM EMAS NASABAH
  // ==========================================
  public function get_saldo_emas()
  {
    $request = json_decode($this->input->raw_input_stream, true);
    $id_nasabah = $request['id_nasabah'] ?? 0;

    if (empty($id_nasabah)) {
      echo json_encode(['status' => false, 'total_gram' => '0.0000']);
      return;
    }

    // Hitung total gram dari semua transaksi emas (Beli yang positif, dan Jual yang negatif)
    $this->db->select_sum('gram_emas');
    $this->db->where('idNasabah', $id_nasabah);

    // 🔥 UBAH DI SINI: Gunakan != 0 agar angka minus (transaksi Buyback) ikut dijumlahkan
    $this->db->where('gram_emas !=', 0);

    $this->db->where('status_konfirmasi', 'Sukses');
    $query = $this->db->get('tb_transaksi')->row();

    // Pastikan mengembalikan 4 angka di belakang koma (contoh: 0.5000)
    $total_gram = $query->gram_emas ? number_format($query->gram_emas, 4, '.', '') : '0.0000';

    echo json_encode(['status' => true, 'total_gram' => $total_gram]);
  }

  public function tarik_emas()
  {
    $request = json_decode($this->input->raw_input_stream, true);

    if ($_SERVER['REQUEST_METHOD'] !== 'POST' || empty($request)) {
      echo json_encode(['status' => false, 'message' => 'Permintaan tidak valid.']);
      return;
    }

    $id_nasabah = $request['id_nasabah'] ?? 0;
    $gram_dijual = (float)($request['gram_ditarik'] ?? 0);

    if (empty($id_nasabah) || empty($gram_dijual) || $gram_dijual <= 0) {
      echo json_encode(['status' => false, 'message' => 'Jumlah gram tidak valid!']);
      return;
    }

    $today = date('Y-m-d');

    // 🔥 REVISI: Selalu ambil harga acuan terbaru
    $this->db->order_by('id', 'DESC');
    $this->db->limit(1);
    $harga_emas = $this->db->get('tb_harga_emas')->row();

    if (!$harga_emas) {
      echo json_encode(['status' => false, 'message' => 'Harga emas acuan belum tersedia di sistem.']);
      return;
    }

    // CEK SALDO EMAS NASABAH
    $this->db->select_sum('gram_emas');
    $this->db->where('idNasabah', $id_nasabah);
    $this->db->where('gram_emas !=', 0);
    $this->db->where('status_konfirmasi', 'Sukses');
    $total_emas_sekarang = (float)($this->db->get('tb_transaksi')->row()->gram_emas ?? 0);

    if (round($gram_dijual, 4) > round($total_emas_sekarang, 4)) {
      echo json_encode(['status' => false, 'message' => 'Saldo Tamas Anda tidak mencukupi! Sisa: ' . $total_emas_sekarang . ' Gram']);
      return;
    }

    // 🔥 REVISI: Hapus simulasi spread 3%. Langsung gunakan harga_jual murni dari database!
    $harga_jual_asli = (int)$harga_emas->harga_jual;
    $nominal_rupiah = round($gram_dijual * $harga_jual_asli);

    // 4. Siapkan Data Transaksi Ledger
    $data = [
      'idAdmin'           => 0,
      'idNasabah'         => $id_nasabah,
      'idPotongan'        => 0,
      'tanggal'           => $today,
      'nominal'           => $nominal_rupiah,
      'jenis'             => 'Masuk', // Menambah Saldo Utama
      'keterangan'        => 'Jual Emas ' . $gram_dijual . ' Gram',
      'status_konfirmasi' => 'Sukses',
      'gram_emas'         => -$gram_dijual, // Minus agar saldo gram berkurang
      'terdaftar'         => date('Y-m-d H:i:s')
    ];

    $insert = $this->db->insert('tb_transaksi', $data);

    if ($insert) {
      $this->db->where('id', $id_nasabah);
      $nasabah = $this->db->get('tb_user')->row();
      $nama_nasabah = $nasabah ? $nasabah->nama : 'Nasabah';

      $pesan_wa = "💰 *PENCAIRAN / JUAL EMAS (BUYBACK)*\n\n";
      $pesan_wa .= "Nasabah telah mencairkan emas menjadi Rupiah:\n";
      $pesan_wa .= "👤 *Nama:* " . $nama_nasabah . "\n";
      $pesan_wa .= "⚖️ *Emas Dijual:* " . $gram_dijual . " Gram\n";
      $pesan_wa .= "💵 *Uang Diterima:* Rp " . number_format($nominal_rupiah, 0, ',', '.') . "\n";
      $pesan_wa .= "Status: Selesai Otomatis & Saldo Utama bertambah.";

      $nomor_admin = '081234567890';
      $this->send_whatsapp($nomor_admin, $pesan_wa);

      // SIMPAN RIWAYAT & PUSH NOTIFIKASI KE NASABAH
      $pesan_nasabah = "Pencairan " . $gram_dijual . " Gram emas berhasil. Uang tunai Rp " . number_format($nominal_rupiah, 0, ',', '.') . " telah masuk ke Saldo Utama Anda.";

      $this->db->insert('tb_notifikasi', [
        'id_user' => $id_nasabah,
        'judul'   => '💰 Pencairan Emas Berhasil!',
        'pesan'   => $pesan_nasabah,
        'is_read' => 0,
        'tanggal' => date('Y-m-d H:i:s')
      ]);

      if (!empty($nasabah->expo_token)) {
        $this->send_expo_push_notification(
          $nasabah->expo_token,
          "💰 Pencairan Emas Berhasil!",
          $pesan_nasabah
        );
      }

      // SIMPAN RIWAYAT & PUSH NOTIFIKASI KE SEMUA ADMIN
      $pesan_admin = "Nasabah " . $nama_nasabah . " telah mencairkan " . $gram_dijual . " Gram emas. Saldo utama nasabah bertambah Rp " . number_format($nominal_rupiah, 0, ',', '.');

      $admins = $this->db->where_in('level', ['Administrator', 'Super Admin'])->get('tb_user')->result();
      foreach ($admins as $admin) {

        $this->db->insert('tb_notifikasi', [
          'id_user' => $admin->id,
          'judul'   => '💰 Pencairan Emas (Buyback)',
          'pesan'   => $pesan_admin,
          'is_read' => 0,
          'tanggal' => date('Y-m-d H:i:s')
        ]);

        if (!empty($admin->expo_token)) {
          $this->send_expo_push_notification(
            $admin->expo_token,
            "💰 Pencairan Emas (Buyback)",
            $pesan_admin
          );
        }
      }

      echo json_encode([
        'status' => true,
        'message' => 'Pencairan emas berhasil! Rp ' . number_format($nominal_rupiah, 0, ',', '.') . ' telah masuk ke saldo utama.'
      ]);
    } else {
      echo json_encode(['status' => false, 'message' => 'Gagal memproses penjualan emas.']);
    }
  }

  public function get_harga_emas_hari_ini()
  {
    // 🔥 REVISI: Ambil langsung baris terbaru dari tabel tanpa perlu melihat tanggal hari ini
    $this->db->order_by('id', 'DESC');
    $this->db->limit(1);
    $harga_emas = $this->db->get('tb_harga_emas')->row();

    if ($harga_emas) {
      echo json_encode([
        'status' => true,
        'harga_beli' => (int)$harga_emas->harga_beli,
        'harga_jual' => (int)$harga_emas->harga_jual, // 🔥 Langsung dilempar dari tabel
        'tanggal_update' => $harga_emas->tanggal
      ]);
    } else {
      echo json_encode(['status' => false, 'harga_beli' => 0, 'harga_jual' => 0, 'message' => 'Harga emas belum tersedia.']);
    }
  }


  public function update_harga_emas()
  {
    $request = json_decode($this->input->raw_input_stream, true);

    if ($_SERVER['REQUEST_METHOD'] !== 'POST' || empty($request)) {
      echo json_encode(['status' => false, 'message' => 'Permintaan tidak valid.']);
      return;
    }

    if (!empty($request['id_admin']) && !empty($request['harga_beli']) && !empty($request['harga_jual'])) {

      $today = date('Y-m-d');

      // 1. Cek apakah hari ini sudah ada harga yang diinput
      $cek_hari_ini = $this->db->get_where('tb_harga_emas', ['tanggal' => $today])->row();

      // 2. 🔥 MATIKAN SIFAT NGAMBEK CODEIGNITER (Supaya tidak membuang HTML saat error DB)
      $this->db->db_debug = FALSE;

      if ($cek_hari_ini) {
        // Jika hari ini sudah ada, kita UPDATE saja baris tersebut (Lebih aman)
        $this->db->where('id', $cek_hari_ini->id);
        $proses = $this->db->update('tb_harga_emas', [
          'harga_beli' => $request['harga_beli'],
          'harga_jual' => $request['harga_jual']
        ]);
      } else {
        // Jika belum ada baris untuk hari ini, baru kita INSERT
        $proses = $this->db->insert('tb_harga_emas', [
          'harga_beli' => $request['harga_beli'],
          'harga_jual' => $request['harga_jual'],
          'tanggal'    => $today
        ]);
      }

      // 3. Nyalakan lagi fitur debug-nya
      $this->db->db_debug = TRUE;

      // 4. Evaluasi hasil query
      if ($proses) {
        echo json_encode([
          'status' => true,
          'message' => "Harga acuan emas berhasil diperbarui."
        ]);
      } else {
        // 🔥 Jika masih error di database, tangkap pesan aslinya dan kirim sebagai teks biasa (JSON)
        $db_error = $this->db->error();
        echo json_encode([
          'status' => false,
          'message' => 'Gagal menyimpan ke database. Info Error: ' . $db_error['message']
        ]);
      }
    } else {
      echo json_encode([
        'status' => false,
        'message' => 'Data tidak lengkap. Harga beli dan harga jual wajib diisi.'
      ]);
    }
  }
  // ==========================================
  // H. Ambil Saldo Emas Seluruh Nasabah (Khusus Admin)
  // ==========================================
  public function admin_get_semua_emas()
  {
    $request = json_decode($this->input->raw_input_stream, true);
    $level = $request['level'] ?? '';

    if ($level !== 'Administrator' && $level !== 'Super Admin') {
      echo json_encode(['status' => false, 'message' => 'Akses ditolak.']);
      return;
    }

    // Ambil seluruh user dengan level Nasabah
    $this->db->where('level', 'Nasabah');
    $this->db->order_by('nama', 'ASC');
    $nasabah = $this->db->get('tb_user')->result_array();

    $data_emas = [];
    foreach ($nasabah as $row) {
      $id_user = $row['id'];

      // Kalkulasi total emas per nasabah
      $this->db->select_sum('gram_emas');
      $this->db->where('idNasabah', $id_user);
      $this->db->where('gram_emas !=', 0);
      $this->db->where('status_konfirmasi', 'Sukses');
      $query = $this->db->get('tb_transaksi')->row();

      $total_gram = $query->gram_emas ? number_format($query->gram_emas, 4, '.', '') : '0.0000';

      // Opsional: Jika Bapak hanya ingin menampilkan nasabah yang PUNYA emas, 
      // aktifkan IF di bawah ini. Jika ingin tampilkan semua (meski 0), biarkan.
      // if (parseFloat($total_gram) > 0) {
      $data_emas[] = [
        'id' => $id_user,
        'nama' => $row['nama'],
        'username' => $row['username'],
        'foto' => $row['foto'],
        'total_gram' => $total_gram
      ];
      // }
    }

    echo json_encode(['status' => true, 'data' => $data_emas]);
  }

  // ==========================================
  // FITUR UPDATE APLIKASI (OTA) BERDASARKAN TANGGAL
  // ==========================================

  // 1. Endpoint Cek Versi Aplikasi
  public function cek_versi_aplikasi()
  {
    $data = $this->db->get_where('tb_aplikasi', ['id' => 1])->row();
    if ($data) {
      echo json_encode([
        'status' => true,
        'data' => [
          'versi' => $data->versi_aplikasi ?? '1.0.1',
          'link_apk' => $data->link_apk ?? '',
          'tgl_update' => $data->tgl_update_apk ?? '2000-01-01 00:00:00' // 🔥 Kirim tanggal upload ke aplikasi
        ]
      ]);
    } else {
      echo json_encode(['status' => false]);
    }
  }

  // 2. Endpoint Upload Update APK Baru (Khusus Admin)
  public function upload_update_apk()
  {
    if (ob_get_length()) ob_clean();
    header('Content-Type: application/json');
    header('Access-Control-Allow-Origin: *');

    $id_admin = $this->input->post('id_admin');
    $versi_baru = $this->input->post('versi_baru');

    $admin = $this->db->get_where('tb_user', ['id' => $id_admin, 'level' => 'Super Admin'])->row();
    if (!$admin) {
      echo json_encode(['status' => false, 'message' => 'Akses ditolak! Khusus Super Admin.']);
      return;
    }

    if (empty($_FILES['file_apk']['name'])) {
      echo json_encode(['status' => false, 'message' => 'File APK belum dipilih.']);
      return;
    }

    // 🔥 PENGECEKAN MANUAL EKSTENSI FILE HARUS .APK 🔥
    $file_ext = pathinfo($_FILES['file_apk']['name'], PATHINFO_EXTENSION);
    if (strtolower($file_ext) !== 'apk') {
      echo json_encode(['status' => false, 'message' => 'Format file tidak diizinkan. Harus berupa .apk!']);
      return;
    }

    $upload_dir = FCPATH . 'assets/apk/';
    if (!is_dir($upload_dir)) {
      mkdir($upload_dir, 0755, true);
    }

    $config['upload_path']   = $upload_dir;
    $config['allowed_types'] = '*';      // 🔥 Ubah jadi bintang (*) agar sistem CI tidak menolak MIME type bawaan Android
    $config['max_size']      = 150000;   // 🔥 Ubah jadi 150.000 KB (150 MB) agar APK 89 MB bisa masuk
    $config['file_name']     = 'TabunganMakmur_v' . str_replace('.', '_', $versi_baru) . '_' . time() . '.apk'; // Tambahkan .apk di akhir

    $this->load->library('upload', $config);
    $this->upload->initialize($config);

    if (!$this->upload->do_upload('file_apk')) {
      $error = $this->upload->display_errors('', '');
      echo json_encode(['status' => false, 'message' => 'Gagal upload APK: ' . $error]);
    } else {
      $upload_data = $this->upload->data();
      $link_apk = 'https://kelolawarga.my.id/tabungan/assets/apk/' . $upload_data['file_name'];

      $waktu_upload = date('Y-m-d H:i:s'); // 🔥 Ambil waktu server saat ini

      $this->db->where('id', 1);
      $this->db->update('tb_aplikasi', [
        'versi_aplikasi' => $versi_baru,
        'link_apk' => $link_apk,
        'tgl_update_apk' => $waktu_upload // 🔥 Simpan waktu upload ke DB
      ]);

      echo json_encode(['status' => true, 'message' => "Aplikasi v{$versi_baru} berhasil dirilis!\nTanggal: {$waktu_upload}"]);
    }
    exit;
  }

  // ==========================================
  // ENDPOINT API: TARIK KAS ADMIN & SEMUA SALDO NASABAH
  // ==========================================
  public function get_semua_saldo_eksternal()
  {
    $request = json_decode($this->input->raw_input_stream, true);
    $api_key_valid = 'RAHASIA_MAKMUR_2026!';

    if (empty($request) || ($request['api_key'] ?? '') !== $api_key_valid) {
      echo json_encode(['status' => false, 'message' => 'API Key tidak valid!']);
      return;
    }

    // 1. HITUNG TOTAL KAS INSTITUSI (SUPER ADMIN / ADMIN)
    $tbMsk = $this->db->query('SELECT SUM(nominal) AS total FROM tb_transaksi WHERE jenis="Masuk" AND status_konfirmasi="Sukses"')->row()->total ?? 0;
    $tbKlr = $this->db->query('SELECT SUM(nominal) AS total FROM tb_transaksi WHERE jenis="Keluar" AND status_konfirmasi="Sukses"')->row()->total ?? 0;
    $tbTarget = $this->db->query('SELECT SUM(terkumpul) AS total FROM tb_target')->row()->total ?? 0;

    $kas_institusi = ($tbMsk - $tbKlr) + $tbTarget;

    // 2. HITUNG SALDO MASING-MASING NASABAH (QUERY SUPER CEPAT)
    $sql_nasabah = "
          SELECT 
              u.id, 
              u.nama, 
              u.username,
              (
                  (IFNULL((SELECT SUM(nominal) FROM tb_transaksi WHERE idNasabah = u.id AND jenis = 'Masuk' AND status_konfirmasi = 'Sukses'), 0) + 
                   IFNULL((SELECT SUM(nominal) FROM tb_transfer WHERE idPenerima = u.id), 0)) 
                  -
                  (IFNULL((SELECT SUM(nominal) FROM tb_transaksi WHERE idNasabah = u.id AND jenis = 'Keluar' AND status_konfirmasi = 'Sukses'), 0) + 
                   IFNULL((SELECT SUM(nominal) FROM tb_transfer WHERE idPengirim = u.id), 0))
              ) AS saldo_aktif
          FROM tb_user u
          WHERE u.level = 'Nasabah'
      ";

    $data_nasabah = $this->db->query($sql_nasabah)->result();
    $list_nasabah = [];

    foreach ($data_nasabah as $row) {
      $list_nasabah[] = [
        'id_user'      => $row->id,
        'nama'         => $row->nama,
        'username'     => $row->username,
        'saldo_angka'  => (int)$row->saldo_aktif,
        'saldo_format' => 'Rp ' . number_format((int)$row->saldo_aktif, 0, ',', '.')
      ];
    }

    // 3. KEMBALIKAN RESPONS JSON LENGKAP
    echo json_encode([
      'status' => true,
      'message' => 'Berhasil menarik data institusi dan nasabah',
      'data_institusi' => [
        'keterangan'   => 'Total Kas Keseluruhan (Termasuk Celengan)',
        'saldo_angka'  => $kas_institusi,
        'saldo_format' => 'Rp ' . number_format($kas_institusi, 0, ',', '.')
      ],
      'total_nasabah' => count($list_nasabah),
      'data_nasabah'  => $list_nasabah
    ]);
  }
  public function reset_pin_nasabah()
  {
    header("Access-Control-Allow-Origin: *");
    header("Content-Type: application/json; charset=UTF-8");
    header("Access-Control-Allow-Methods: POST");

    $json = file_get_contents('php://input');
    $data = json_decode($json, true);

    // Pastikan yang mengakses ini adalah Admin
    if (!empty($data['id_admin']) && !empty($data['id_nasabah'])) {

      // 1. Tentukan PIN Default
      $default_pin = '123456';

      // 🔥 PERBAIKAN: Langsung gunakan angka murni tanpa password_hash
      $hashed_pin = $default_pin;

      // Jika ternyata database Bapak menggunakan MD5, aktifkan baris di bawah ini dan matikan baris di atas:
      // $hashed_pin = md5($default_pin);

      // 2. Update PIN nasabah tersebut
      $this->db->where('id', $data['id_nasabah']);
      $update = $this->db->update('tb_user', ['pin' => $hashed_pin]);

      if ($update) {
        echo json_encode([
          'status' => true,
          'message' => "PIN berhasil direset ke default (123456)."
        ]);
      } else {
        echo json_encode([
          'status' => false,
          'message' => 'Gagal mereset PIN, terjadi kesalahan database.'
        ]);
      }
    } else {
      echo json_encode([
        'status' => false,
        'message' => 'Data tidak lengkap. ID Admin dan ID Nasabah wajib dikirim.'
      ]);
    }
  }
}
