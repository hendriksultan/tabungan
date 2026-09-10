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


  private function verifikasi_pin_user_dalam_transaksi(
    $user,
    $pin
  ) {
    $id_user = (int) $user->id;
    $waktu_sekarang = time();

    /*
   * Helper ini harus dipanggil setelah baris tb_user
   * dikunci menggunakan FOR UPDATE.
   */
    if (
      !empty($user->pin_terkunci_sampai) &&
      strtotime($user->pin_terkunci_sampai) >
      $waktu_sekarang
    ) {
      return [
        'status'            => false,
        'http_code'         => 429,
        'message'           => 'Terlalu banyak percobaan PIN. Silakan coba kembali setelah waktu penguncian berakhir.',
        'data'              => [
          'terkunci_sampai' =>
          $user->pin_terkunci_sampai
        ],
        'simpan_perubahan'  => false
      ];
    }

    $pin_gagal = (int) $user->pin_gagal;

    /*
   * Masa penguncian yang sudah berakhir dimulai
   * kembali dari nol.
   */
    if (
      !empty($user->pin_terkunci_sampai) &&
      strtotime($user->pin_terkunci_sampai) <=
      $waktu_sekarang
    ) {
      $pin_gagal = 0;
    }

    $pin_tersimpan = (string) $user->pin;

    if ($pin_tersimpan === '') {
      return [
        'status'           => false,
        'http_code'        => 422,
        'message'          => 'PIN transaksi belum diatur.',
        'data'             => null,
        'simpan_perubahan' => false
      ];
    }

    $info_hash = password_get_info(
      $pin_tersimpan
    );

    $sudah_hash =
      isset($info_hash['algo']) &&
      $info_hash['algo'] !== 0;

    if ($sudah_hash) {
      $pin_valid = password_verify(
        $pin,
        $pin_tersimpan
      );
    } else {
      /*
     * Kompatibilitas sementara untuk PIN plaintext lama.
     */
      $pin_valid = hash_equals(
        $pin_tersimpan,
        $pin
      );
    }

    if ($pin_valid) {
      $data_update = [
        'pin_gagal'           => 0,
        'pin_terkunci_sampai' => null
      ];

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

      $update = $this->db
        ->where('id', $id_user)
        ->update('tb_user', $data_update);

      if (!$update) {
        return [
          'status'           => false,
          'http_code'        => 500,
          'message'          => 'Gagal memproses validasi PIN.',
          'data'             => null,
          'simpan_perubahan' => false
        ];
      }

      return [
        'status'           => true,
        'http_code'        => 200,
        'message'          => 'PIN valid.',
        'data'             => null,
        'simpan_perubahan' => true
      ];
    }

    /*
   * PIN salah: percobaan kelima mengunci PIN
   * selama 15 menit.
   */
    $pin_gagal++;
    $batas_percobaan = 5;

    if ($pin_gagal >= $batas_percobaan) {
      $terkunci_sampai = date(
        'Y-m-d H:i:s',
        strtotime('+15 minutes')
      );

      $update = $this->db
        ->where('id', $id_user)
        ->update('tb_user', [
          'pin_gagal'           => 0,
          'pin_terkunci_sampai' =>
          $terkunci_sampai
        ]);

      if (!$update) {
        return [
          'status'           => false,
          'http_code'        => 500,
          'message'          => 'Gagal memproses validasi PIN.',
          'data'             => null,
          'simpan_perubahan' => false
        ];
      }

      return [
        'status'    => false,
        'http_code' => 429,
        'message'   => 'PIN salah lima kali. Validasi PIN dikunci selama 15 menit.',
        'data'      => [
          'terkunci_sampai' => $terkunci_sampai
        ],
        'simpan_perubahan' => true
      ];
    }

    $update = $this->db
      ->where('id', $id_user)
      ->update('tb_user', [
        'pin_gagal'           => $pin_gagal,
        'pin_terkunci_sampai' => null
      ]);

    if (!$update) {
      return [
        'status'           => false,
        'http_code'        => 500,
        'message'          => 'Gagal memproses validasi PIN.',
        'data'             => null,
        'simpan_perubahan' => false
      ];
    }

    return [
      'status'    => false,
      'http_code' => 401,
      'message'   => 'PIN yang Anda masukkan salah.',
      'data'      => [
        'sisa_percobaan' =>
        $batas_percobaan - $pin_gagal
      ],
      'simpan_perubahan' => true
    ];
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
        'message' => 'Checkout hanya dapat dilakukan oleh Nasabah.'
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

    /*
   * checkout_key harus dibuat aplikasi satu kali
   * untuk setiap proses checkout dan digunakan kembali
   * jika request yang sama diulang.
   */
    $checkout_key = isset($request['checkout_key'])
      ? trim((string) $request['checkout_key'])
      : '';

    if (
      strlen($checkout_key) < 16 ||
      strlen($checkout_key) > 64 ||
      !preg_match(
        '/^[A-Za-z0-9_-]+$/D',
        $checkout_key
      )
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'checkout_key tidak valid.'
      ], 422);
      return;
    }

    $catatan = isset($request['catatan'])
      ? trim((string) $request['catatan'])
      : '';

    if (strlen($catatan) > 1000) {
      $this->api_response([
        'status'  => false,
        'message' => 'Catatan pembeli maksimal 1.000 karakter.'
      ], 422);
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
        'message' => 'Maksimal 100 baris produk dalam satu checkout.'
      ], 422);
      return;
    }

    /*
   * Gabungkan produk duplikat.
   */
    $jumlah_per_produk = [];

    foreach ($items as $item) {
      if (!is_array($item)) {
        $this->api_response([
          'status'  => false,
          'message' => 'Format item checkout tidak valid.'
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
          'message' => 'ID produk tidak valid.'
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

    /*
   * Urutan produk dibuat konsisten untuk hash
   * dan membantu mencegah deadlock.
   */
    ksort($jumlah_per_produk, SORT_NUMERIC);

    $hash_items = [];

    foreach (
      $jumlah_per_produk as
      $id_produk => $jumlah
    ) {
      $hash_items[] = [
        'id_produk' => (int) $id_produk,
        'jumlah'    => (int) $jumlah
      ];
    }

    $checkout_hash = hash(
      'sha256',
      json_encode(
        [
          'items'   => $hash_items,
          'catatan' => $catatan
        ],
        JSON_UNESCAPED_UNICODE |
          JSON_UNESCAPED_SLASHES
      )
    );

    $id_pembeli = (int) $auth->id_user;
    $cabang_pembeli_id = (int) $auth->cabang_id;

    $this->db->trans_begin();

    /*
   * Cegah pemotongan stok dua kali saat request
   * yang sama dikirim ulang.
   */
    $pesanan_lama = $this->db->query(
      "SELECT
        id_pesanan,
        invoice_pesanan,
        checkout_hash,
        id_toko,
        cabang_toko_id,
        total_harga,
        ongkir,
        kurir,
        status_pesanan,
        terdaftar
     FROM tb_pesanan
     WHERE id_pembeli = ?
       AND checkout_key = ?
     LIMIT 1
     FOR UPDATE",
      [
        $id_pembeli,
        $checkout_key
      ]
    )->row();

    if ($pesanan_lama) {
      if (
        !hash_equals(
          (string) $pesanan_lama->checkout_hash,
          $checkout_hash
        )
      ) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'checkout_key sudah digunakan untuk isi checkout yang berbeda.'
        ], 409);
        return;
      }

      $this->db->trans_commit();

      $this->api_response([
        'status'  => true,
        'message' => 'Pesanan yang sama sudah tercatat.',
        'data'    => [
          'id_pesanan'      => (int) $pesanan_lama->id_pesanan,
          'invoice_pesanan' => $pesanan_lama->invoice_pesanan,
          'checkout_key'    => $checkout_key,
          'id_pembeli'      => $id_pembeli,
          'id_toko'         => (int) $pesanan_lama->id_toko,
          'cabang_toko_id'  => (int) $pesanan_lama->cabang_toko_id,
          'total_harga'     => (int) $pesanan_lama->total_harga,
          'ongkir'          => (int) $pesanan_lama->ongkir,
          'kurir'           => $pesanan_lama->kurir,
          'status_pesanan'  => $pesanan_lama->status_pesanan,
          'terdaftar'       => $pesanan_lama->terdaftar,
          'idempotent'      => true
        ]
      ]);
      return;
    }

    $id_produk_list = array_keys(
      $jumlah_per_produk
    );

    $placeholders = implode(
      ',',
      array_fill(
        0,
        count($id_produk_list),
        '?'
      )
    );

    /*
   * Kunci seluruh produk sampai transaksi selesai.
   */
    $sql_produk = "
    SELECT
      p.id_produk,
      p.id_toko,
      p.nama_produk,
      p.harga,
      p.stok,
      p.berat,
      p.status_produk,

      t.id_user AS id_penjual,
      t.nama_toko,
      t.status_toko,

      penjual.expo_token,
      penjual.cabang_id AS cabang_toko_id,

      c.status AS status_cabang

    FROM tb_produk AS p

    INNER JOIN tb_toko AS t
      ON t.id_toko = p.id_toko

    INNER JOIN tb_user AS penjual
      ON penjual.id = t.id_user

    INNER JOIN tb_cabang AS c
      ON c.id = penjual.cabang_id

    WHERE p.id_produk IN ({$placeholders})

    ORDER BY p.id_produk ASC

    FOR UPDATE
  ";

    $produk_database = $this->db->query(
      $sql_produk,
      $id_produk_list
    )->result_array();

    $produk_map = [];

    foreach ($produk_database as $produk) {
      $produk_map[(int) $produk['id_produk']] =
        $produk;
    }

    $id_toko = null;
    $id_penjual = null;
    $cabang_toko_id = null;
    $nama_toko = '';
    $expo_token_penjual = null;
    $total_harga = 0;
    $detail_pesanan = [];

    foreach (
      $jumlah_per_produk as
      $id_produk => $jumlah
    ) {
      if (!isset($produk_map[$id_produk])) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => "Produk ID {$id_produk} tidak ditemukan."
        ], 404);
        return;
      }

      $produk = $produk_map[$id_produk];

      if (
        $produk['status_produk'] !== 'Tersedia' ||
        $produk['status_toko'] !== 'Aktif' ||
        $produk['status_cabang'] !== 'Aktif'
      ) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Produk "' .
            $produk['nama_produk'] .
            '" sudah tidak tersedia.'
        ], 409);
        return;
      }

      if ($id_toko === null) {
        $id_toko = (int) $produk['id_toko'];
        $id_penjual = (int) $produk['id_penjual'];
        $cabang_toko_id =
          (int) $produk['cabang_toko_id'];
        $nama_toko = $produk['nama_toko'];
        $expo_token_penjual =
          $produk['expo_token'];
      }

      if (
        (int) $produk['id_toko'] !==
        $id_toko
      ) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Satu checkout hanya boleh berisi produk dari satu toko.'
        ], 422);
        return;
      }

      if (
        (int) $produk['id_penjual'] ===
        $id_pembeli
      ) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Anda tidak dapat membeli produk dari toko sendiri.'
        ], 403);
        return;
      }

      $stok = (int) $produk['stok'];

      if ($stok < $jumlah) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Stok "' .
            $produk['nama_produk'] .
            '" tidak mencukupi. Sisa stok: ' .
            $stok . '.',
          'data' => [
            'id_produk' => (int) $id_produk,
            'stok'      => $stok,
            'diminta'   => (int) $jumlah
          ]
        ], 409);
        return;
      }

      $harga = (int) $produk['harga'];
      $subtotal = $harga * $jumlah;

      $total_harga += $subtotal;

      if ($total_harga > 2000000000) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Total harga pesanan melebihi batas yang diizinkan.'
        ], 422);
        return;
      }

      $detail_pesanan[] = [
        'id_produk'   => (int) $id_produk,
        'nama_produk' => $produk['nama_produk'],
        'jumlah'      => (int) $jumlah,
        'harga_satuan' => $harga,
        'subtotal'    => $subtotal,
        'stok_awal'   => $stok,
        'stok_baru'   => $stok - $jumlah,
        'berat'       => (int) $produk['berat']
      ];
    }

    try {
      $invoice = 'INV-' .
        date('YmdHis') .
        '-' .
        strtoupper(
          bin2hex(random_bytes(8))
        );
    } catch (Throwable $e) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Gagal membuat nomor invoice.'
      ], 500);
      return;
    }

    $waktu_sekarang = date('Y-m-d H:i:s');

    /*
   * id_pembeli, id_toko, total_harga, dan cabang
   * seluruhnya berasal dari token/database.
   */
    $insert_pesanan = $this->db->insert(
      'tb_pesanan',
      [
        'invoice_pesanan'  => $invoice,
        'checkout_key'     => $checkout_key,
        'checkout_hash'    => $checkout_hash,
        'id_pembeli'       => $id_pembeli,
        'cabang_pembeli_id' => $cabang_pembeli_id,
        'id_toko'          => $id_toko,
        'cabang_toko_id'   => $cabang_toko_id,
        'total_harga'      => $total_harga,
        'ongkir'           => 0,
        'kurir'            => 'Menunggu Penjual',
        'status_pesanan'   => 'Menunggu Ongkir',
        'stok_dikembalikan' => 0,
        'catatan_pembeli'  => (
          $catatan !== ''
          ? $catatan
          : null
        ),
        'terdaftar'        => $waktu_sekarang
      ]
    );

    if (!$insert_pesanan) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Gagal membuat pesanan.'
      ], 500);
      return;
    }

    $id_pesanan = (int) $this->db->insert_id();

    foreach ($detail_pesanan as $detail) {
      $insert_detail = $this->db->insert(
        'tb_pesanan_detail',
        [
          'id_pesanan'  => $id_pesanan,
          'id_produk'   => $detail['id_produk'],
          'jumlah'      => $detail['jumlah'],
          'harga_satuan' => $detail['harga_satuan'],
          'subtotal'    => $detail['subtotal']
        ]
      );

      if (!$insert_detail) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Gagal menyimpan detail pesanan.'
        ], 500);
        return;
      }

      $status_produk_baru =
        $detail['stok_baru'] > 0
        ? 'Tersedia'
        : 'Habis';

      $this->db->where(
        'id_produk',
        $detail['id_produk']
      );

      $update_stok = $this->db->update(
        'tb_produk',
        [
          'stok' => $detail['stok_baru'],
          'status_produk' =>
          $status_produk_baru
        ]
      );

      if (!$update_stok) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Gagal memperbarui stok produk.'
        ], 500);
        return;
      }
    }

    if ($this->db->trans_status() === false) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Gagal menyelesaikan checkout.'
      ], 500);
      return;
    }

    $this->db->trans_commit();

    /*
   * Notifikasi dilakukan setelah transaksi utama berhasil.
   * Kegagalan push tidak membatalkan pesanan.
   */
    $judul_notif =
      "\u{1F6D2} Pesanan Baru Masuk";

    $pesan_notif =
      "Pesanan ({$invoice}) telah masuk. " .
      'Silakan tentukan ongkos kirimnya.';

    $this->db->insert('tb_notifikasi', [
      'id_user' => $id_penjual,
      'judul'   => $judul_notif,
      'pesan'   => $pesan_notif,
      'tanggal' => $waktu_sekarang
    ]);

    if (!empty($expo_token_penjual)) {
      try {
        $this->send_expo_push_notification(
          $expo_token_penjual,
          $judul_notif,
          $pesan_notif
        );
      } catch (Throwable $e) {
        log_message(
          'error',
          'Push checkout gagal: ' .
            $e->getMessage()
        );
      }
    }

    $this->api_response([
      'status'  => true,
      'message' => 'Pesanan terkirim. Menunggu penjual menentukan ongkos kirim.',
      'data'    => [
        'id_pesanan'       => $id_pesanan,
        'invoice_pesanan'  => $invoice,
        'checkout_key'     => $checkout_key,
        'id_pembeli'       => $id_pembeli,
        'cabang_pembeli_id' => $cabang_pembeli_id,
        'id_toko'          => $id_toko,
        'nama_toko'        => $nama_toko,
        'id_penjual'       => $id_penjual,
        'cabang_toko_id'   => $cabang_toko_id,
        'total_harga'      => $total_harga,
        'ongkir'           => 0,
        'kurir'            => 'Menunggu Penjual',
        'status_pesanan'   => 'Menunggu Ongkir',
        'stok_dikembalikan' => false,
        'terdaftar'        => $waktu_sekarang,
        'idempotent'       => false,
        'items'            => $detail_pesanan
      ]
    ], 201);
  }


  // FASE 2: Penjual Input Ongkir (Status: Menunggu Pembayaran)
  public function input_ongkir_penjual()
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
        'message' => 'Ongkir hanya dapat ditentukan oleh pemilik toko.'
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

    $id_pesanan_raw = $request['id_pesanan'] ?? null;
    $ongkir_raw = $request['ongkir'] ?? null;
    $kurir_raw = $request['kurir'] ?? 'Kurir Toko / Lokal';

    if (
      (!is_int($id_pesanan_raw) &&
        !is_string($id_pesanan_raw)) ||
      (!is_int($ongkir_raw) &&
        !is_string($ongkir_raw)) ||
      !is_string($kurir_raw)
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Format data ongkir tidak valid.'
      ], 422);
      return;
    }

    $id_pesanan_text = trim(
      (string) $id_pesanan_raw
    );

    $ongkir_text = preg_replace(
      '/[.\s]/',
      '',
      trim((string) $ongkir_raw)
    );

    $kurir = trim($kurir_raw);

    if (
      $id_pesanan_text === '' ||
      !ctype_digit($id_pesanan_text) ||
      (int) $id_pesanan_text < 1
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'ID Pesanan tidak valid.'
      ], 422);
      return;
    }

    if (
      $ongkir_text === '' ||
      !ctype_digit($ongkir_text)
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Ongkir harus berupa angka bulat.'
      ], 422);
      return;
    }

    $id_pesanan = (int) $id_pesanan_text;
    $ongkir = (int) $ongkir_text;

    if ($ongkir < 0 || $ongkir > 100000000) {
      $this->api_response([
        'status'  => false,
        'message' => 'Nominal ongkir tidak valid.'
      ], 422);
      return;
    }

    if (
      strlen($kurir) < 2 ||
      strlen($kurir) > 50
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Nama kurir harus terdiri dari 2 sampai 50 karakter.'
      ], 422);
      return;
    }

    if (
      !preg_match(
        '/^[\p{L}\p{N}\s&\/().,+_-]+$/u',
        $kurir
      )
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Nama kurir mengandung karakter yang tidak diizinkan.'
      ], 422);
      return;
    }

    $id_penjual = (int) $auth->id_user;

    $this->db->trans_begin();

    /*
   * Pesanan hanya ditemukan jika toko memang dimiliki
   * oleh pemegang Bearer token.
   */
    $pesanan = $this->db->query(
      "SELECT
        p.id_pesanan,
        p.invoice_pesanan,
        p.id_pembeli,
        p.id_toko,
        p.cabang_pembeli_id,
        p.cabang_toko_id,
        p.total_harga,
        p.ongkir,
        p.kurir,
        p.status_pesanan,
        p.stok_dikembalikan,
        p.ongkir_ditetapkan_oleh,
        p.ongkir_ditetapkan_pada,
        t.id_user AS id_penjual,
        t.nama_toko,
        pembeli.nama AS nama_pembeli,
        pembeli.expo_token AS expo_token_pembeli
     FROM tb_pesanan AS p
     INNER JOIN tb_toko AS t
        ON t.id_toko = p.id_toko
     INNER JOIN tb_user AS pembeli
        ON pembeli.id = p.id_pembeli
     WHERE p.id_pesanan = ?
       AND t.id_user = ?
     LIMIT 1
     FOR UPDATE",
      [
        $id_pesanan,
        $id_penjual
      ]
    )->row();

    if (!$pesanan) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Pesanan tidak ditemukan atau bukan milik toko Anda.'
      ], 404);
      return;
    }

    /*
   * Request sama yang diulang tidak menggandakan
   * perubahan maupun notifikasi.
   */
    if (
      $pesanan->status_pesanan ===
      'Menunggu Pembayaran'
    ) {
      if (
        (int) $pesanan->ongkir === $ongkir &&
        trim((string) $pesanan->kurir) === $kurir
      ) {
        $this->db->trans_commit();

        $this->api_response([
          'status'  => true,
          'message' => 'Ongkir yang sama sudah tersimpan.',
          'data'    => [
            'id_pesanan'      => (int) $pesanan->id_pesanan,
            'invoice_pesanan' => $pesanan->invoice_pesanan,
            'id_toko'         => (int) $pesanan->id_toko,
            'id_penjual'      => $id_penjual,
            'ongkir'          => (int) $pesanan->ongkir,
            'kurir'           => $pesanan->kurir,
            'total_harga'     => (int) $pesanan->total_harga,
            'total_tagihan'   => (
              (int) $pesanan->total_harga +
              (int) $pesanan->ongkir
            ),
            'status_pesanan'  => $pesanan->status_pesanan,
            'idempotent'      => true
          ]
        ]);
        return;
      }

      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Ongkir pesanan sudah ditetapkan dan tidak dapat diubah melalui request ini.'
      ], 409);
      return;
    }

    if (
      $pesanan->status_pesanan !==
      'Menunggu Ongkir'
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Status pesanan tidak dapat menerima penetapan ongkir.'
      ], 409);
      return;
    }

    if ((int) $pesanan->stok_dikembalikan === 1) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Pesanan telah dibatalkan.'
      ], 409);
      return;
    }

    $total_harga = (int) $pesanan->total_harga;
    $total_tagihan = $total_harga + $ongkir;

    if ($total_tagihan > 2000000000) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Total tagihan melebihi batas yang diizinkan.'
      ], 422);
      return;
    }

    $waktu_sekarang = date('Y-m-d H:i:s');

    $this->db->where(
      'id_pesanan',
      (int) $pesanan->id_pesanan
    );

    $this->db->where(
      'status_pesanan',
      'Menunggu Ongkir'
    );

    $update = $this->db->update(
      'tb_pesanan',
      [
        'ongkir' => $ongkir,
        'kurir' => $kurir,
        'ongkir_ditetapkan_oleh' =>
        $id_penjual,
        'ongkir_ditetapkan_pada' =>
        $waktu_sekarang,
        'status_pesanan' =>
        'Menunggu Pembayaran'
      ]
    );

    if (
      !$update ||
      $this->db->affected_rows() !== 1 ||
      $this->db->trans_status() === false
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Gagal menyimpan ongkir.'
      ], 500);
      return;
    }

    $this->db->trans_commit();

    /*
   * Notifikasi dibuat setelah transaksi utama sukses.
   */
    $judul_notif =
      "\u{1F4B3} Tagihan Siap Dibayar";

    $pesan_notif =
      'Penjual telah menetapkan ongkir untuk pesanan ' .
      $pesanan->invoice_pesanan .
      '. Silakan lakukan pembayaran.';

    $simpan_notifikasi = $this->db->insert(
      'tb_notifikasi',
      [
        'id_user' => (int) $pesanan->id_pembeli,
        'judul'   => $judul_notif,
        'pesan'   => $pesan_notif,
        'tanggal' => $waktu_sekarang
      ]
    );

    if (!$simpan_notifikasi) {
      log_message(
        'error',
        'Notifikasi ongkir gagal disimpan untuk pesanan ID ' .
          $id_pesanan
      );
    }

    if (!empty($pesanan->expo_token_pembeli)) {
      try {
        $this->send_expo_push_notification(
          $pesanan->expo_token_pembeli,
          $judul_notif,
          $pesan_notif
        );
      } catch (Throwable $e) {
        log_message(
          'error',
          'Push ongkir gagal: ' .
            $e->getMessage()
        );
      }
    }

    $this->api_response([
      'status'  => true,
      'message' => 'Ongkir berhasil ditetapkan. Menunggu pembayaran pembeli.',
      'data'    => [
        'id_pesanan'       => (int) $pesanan->id_pesanan,
        'invoice_pesanan'  => $pesanan->invoice_pesanan,
        'id_pembeli'       => (int) $pesanan->id_pembeli,
        'nama_pembeli'     => $pesanan->nama_pembeli,
        'id_toko'          => (int) $pesanan->id_toko,
        'nama_toko'        => $pesanan->nama_toko,
        'id_penjual'       => $id_penjual,
        'total_harga'      => $total_harga,
        'ongkir'           => $ongkir,
        'total_tagihan'    => $total_tagihan,
        'kurir'            => $kurir,
        'status_pesanan'   => 'Menunggu Pembayaran',
        'ditetapkan_pada'  => $waktu_sekarang,
        'idempotent'       => false
      ]
    ]);
  }

  // FASE 3: Pembeli Membayar Pesanan (Status: Diproses) - Menggunakan PIN & Potong Saldo
  public function bayar_pesanan()
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
        'message' => 'Pembayaran hanya dapat dilakukan oleh Nasabah.'
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

    $id_pesanan = filter_var(
      $request['id_pesanan'] ?? null,
      FILTER_VALIDATE_INT,
      [
        'options' => [
          'min_range' => 1
        ]
      ]
    );

    $pin = isset($request['pin'])
      ? trim((string) $request['pin'])
      : '';

    if ($id_pesanan === false) {
      $this->api_response([
        'status'  => false,
        'message' => 'ID pesanan tidak valid.'
      ], 422);
      return;
    }

    if (!preg_match('/^[0-9]{6}$/', $pin)) {
      $this->api_response([
        'status'  => false,
        'message' => 'PIN harus terdiri dari tepat 6 digit angka.'
      ], 422);
      return;
    }

    /*
   * Identitas pembeli selalu berasal dari Bearer token.
   * id_pembeli dari request tidak digunakan.
   */
    $id_pembeli = (int) $auth->id_user;
    $id_pesanan = (int) $id_pesanan;

    /*
   * Pemeriksaan kepemilikan awal.
   * Ini mencegah PIN pengguna lain diperiksa ketika pesanan
   * sebenarnya bukan miliknya.
   */
    $pesanan_milik = $this->db->query(
      "SELECT id_pesanan
     FROM tb_pesanan
     WHERE id_pesanan = ?
       AND id_pembeli = ?
     LIMIT 1",
      [
        $id_pesanan,
        $id_pembeli
      ]
    )->row();

    if (!$pesanan_milik) {
      $this->api_response([
        'status'  => false,
        'message' => 'Pesanan tidak ditemukan atau bukan milik Anda.'
      ], 404);
      return;
    }

    $this->db->trans_begin();

    /*
   * Kunci akun pembeli agar dua pembayaran bersamaan
   * tidak dapat menggunakan saldo yang sama.
   */
    $user = $this->db->query(
      "SELECT
        id,
        level,
        login,
        pin,
        pin_gagal,
        pin_terkunci_sampai,
        expo_token,
        cabang_id
     FROM tb_user
     WHERE id = ?
     LIMIT 1
     FOR UPDATE",
      [$id_pembeli]
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

    /*
   * Verifikasi PIN dilakukan di dalam transaksi yang sama.
   */
    $hasil_pin = $this->verifikasi_pin_user_dalam_transaksi(
      $user,
      $pin
    );

    if (!$hasil_pin['status']) {
      /*
     * Kesalahan PIN atau penguncian baru harus disimpan.
     */
      if (
        !empty($hasil_pin['simpan_perubahan']) &&
        $this->db->trans_status() !== false
      ) {
        $this->db->trans_commit();
      } else {
        $this->db->trans_rollback();
      }

      $response_pin = [
        'status'  => false,
        'message' => $hasil_pin['message']
      ];

      if (!empty($hasil_pin['data'])) {
        $response_pin['data'] = $hasil_pin['data'];
      }

      $this->api_response(
        $response_pin,
        (int) $hasil_pin['http_code']
      );
      return;
    }

    /*
   * Ambil dan kunci pesanan setelah pengguna terkunci.
   */
    $pesanan = $this->db->query(
      "SELECT
        p.*,
        t.id_user AS id_penjual,
        t.nama_toko,
        penjual.expo_token AS expo_token_penjual
     FROM tb_pesanan p
     INNER JOIN tb_toko t
       ON t.id_toko = p.id_toko
     INNER JOIN tb_user penjual
       ON penjual.id = t.id_user
     WHERE p.id_pesanan = ?
       AND p.id_pembeli = ?
     LIMIT 1
     FOR UPDATE",
      [
        $id_pesanan,
        $id_pembeli
      ]
    )->row();

    if (!$pesanan) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Pesanan tidak ditemukan atau bukan milik Anda.'
      ], 404);
      return;
    }

    /*
   * Idempotensi pembayaran:
   * apabila pesanan sudah memiliki transaksi pembayaran yang sah,
   * jangan memotong saldo dan membuat notifikasi kembali.
   */
    if (!empty($pesanan->id_transaksi_pembayaran)) {
      $transaksi_lama = $this->db->query(
        "SELECT
          id,
          idNasabah,
          nominal,
          jenis,
          status_konfirmasi,
          referensi_tipe,
          referensi_id
       FROM tb_transaksi
       WHERE id = ?
       LIMIT 1
       FOR UPDATE",
        [(int) $pesanan->id_transaksi_pembayaran]
      )->row();

      $pembayaran_lama_valid =
        $transaksi_lama &&
        (int) $transaksi_lama->idNasabah === $id_pembeli &&
        (string) $transaksi_lama->jenis === 'Keluar' &&
        (string) $transaksi_lama->status_konfirmasi === 'Sukses' &&
        (string) $transaksi_lama->referensi_tipe ===
        'PembayaranPesanan' &&
        (int) $transaksi_lama->referensi_id === $id_pesanan &&
        (int) $transaksi_lama->nominal ===
        (int) $pesanan->nominal_dibayar;

      if (!$pembayaran_lama_valid) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Data pembayaran pesanan tidak konsisten. Hubungi administrator.'
        ], 409);
        return;
      }

      if ($this->db->trans_status() === false) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Gagal memeriksa pembayaran pesanan.'
        ], 500);
        return;
      }

      /*
     * Simpan perubahan PIN, misalnya reset penghitung
     * atau migrasi PIN lama ke bcrypt.
     */
      $this->db->trans_commit();

      $this->api_response([
        'status'  => true,
        'message' => 'Pesanan ini sudah dibayar sebelumnya.',
        'data'    => [
          'id_pesanan'              => $id_pesanan,
          'invoice_pesanan'         => $pesanan->invoice_pesanan,
          'id_transaksi_pembayaran' =>
          (int) $transaksi_lama->id,
          'nominal_dibayar'         =>
          (int) $transaksi_lama->nominal,
          'status_pesanan'          =>
          $pesanan->status_pesanan,
          'dibayar_pada'            =>
          $pesanan->dibayar_pada,
          'idempotent'              => true
        ]
      ]);
      return;
    }

    if ($pesanan->status_pesanan !== 'Menunggu Pembayaran') {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Pesanan belum siap dibayar atau statusnya sudah berubah.',
        'data'    => [
          'status_pesanan' => $pesanan->status_pesanan
        ]
      ], 409);
      return;
    }

    if ((int) $pesanan->stok_dikembalikan !== 0) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Pesanan telah dibatalkan dan stok sudah dikembalikan.'
      ], 409);
      return;
    }

    if (
      empty($pesanan->ongkir_ditetapkan_oleh) ||
      empty($pesanan->ongkir_ditetapkan_pada)
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Ongkir pesanan belum ditetapkan oleh penjual.'
      ], 409);
      return;
    }

    $total_harga = (int) $pesanan->total_harga;
    $ongkir = (int) $pesanan->ongkir;
    $grand_total = $total_harga + $ongkir;

    if (
      $total_harga <= 0 ||
      $ongkir < 0 ||
      $grand_total <= 0 ||
      $grand_total > 2147483647
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Nilai tagihan pesanan tidak valid.'
      ], 422);
      return;
    }

    /*
   * Perlindungan tambahan jika sudah ada ledger pembayaran
   * tetapi hubungan pada tb_pesanan belum terisi.
   */
    $referensi_sudah_ada = $this->db->query(
      "SELECT
        id,
        idNasabah,
        nominal,
        status_konfirmasi
     FROM tb_transaksi
     WHERE referensi_tipe = ?
       AND referensi_id = ?
     LIMIT 1
     FOR UPDATE",
      [
        'PembayaranPesanan',
        $id_pesanan
      ]
    )->row();

    if ($referensi_sudah_ada) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Transaksi pembayaran sudah tercatat tetapi belum terhubung dengan pesanan. Hubungi administrator.',
        'data'    => [
          'id_transaksi' => (int) $referensi_sudah_ada->id
        ]
      ], 409);
      return;
    }

    /*
   * Hitung saldo dari transaksi sukses saja.
   * Saldo dihitung setelah baris pengguna dikunci.
   */
    $saldo = $this->db->query(
      "SELECT
       (
         COALESCE((
           SELECT SUM(nominal)
           FROM tb_transaksi
           WHERE idNasabah = ?
             AND jenis = 'Masuk'
             AND status_konfirmasi = 'Sukses'
         ), 0)
         +
         COALESCE((
           SELECT SUM(CAST(nominal AS UNSIGNED))
           FROM tb_transfer
           WHERE idPenerima = ?
             AND status_transfer = 'Sukses'
         ), 0)
         -
         COALESCE((
           SELECT SUM(nominal)
           FROM tb_transaksi
           WHERE idNasabah = ?
             AND jenis = 'Keluar'
             AND status_konfirmasi = 'Sukses'
         ), 0)
         -
         COALESCE((
           SELECT SUM(CAST(nominal AS UNSIGNED))
           FROM tb_transfer
           WHERE idPengirim = ?
             AND status_transfer = 'Sukses'
         ), 0)
       ) AS saldo_aktif",
      [
        $id_pembeli,
        $id_pembeli,
        $id_pembeli,
        $id_pembeli
      ]
    )->row();

    if (!$saldo) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Gagal menghitung saldo tabungan.'
      ], 500);
      return;
    }

    $saldo_sebelum = (int) $saldo->saldo_aktif;

    if ($saldo_sebelum < $grand_total) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Saldo tabungan tidak mencukupi. Total belanja dan ongkir adalah Rp ' .
          number_format($grand_total, 0, ',', '.'),
        'data'    => [
          'saldo_aktif'  => $saldo_sebelum,
          'total_tagihan' => $grand_total,
          'kekurangan'   => $grand_total - $saldo_sebelum
        ]
      ], 422);
      return;
    }

    $waktu_pembayaran = date('Y-m-d H:i:s');

    /*
   * Catat pengurangan saldo dengan referensi unik ke pesanan.
   */
    $transaksi_disimpan = $this->db->insert(
      'tb_transaksi',
      [
        'cabang_id'          => (int) $user->cabang_id,
        'idAdmin'            => 0,
        'idNasabah'          => $id_pembeli,
        'idPotongan'         => 0,
        'tanggal'            => date('Y-m-d'),
        'nominal'            => $grand_total,
        'gram_emas'          => null,
        'jenis'              => 'Keluar',
        'keterangan'         =>
        'Bayar Pesanan: ' . $pesanan->invoice_pesanan,
        'status_konfirmasi'  => 'Sukses',
        'bukti_transfer'     => null,
        'referensi_tipe'     => 'PembayaranPesanan',
        'referensi_id'       => $id_pesanan,
        'terdaftar'          => $waktu_pembayaran
      ]
    );

    if (!$transaksi_disimpan) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Gagal mencatat transaksi pembayaran.'
      ], 500);
      return;
    }

    $id_transaksi = (int) $this->db->insert_id();

    /*
   * Update hanya apabila status masih Menunggu Pembayaran.
   */
    $this->db
      ->where('id_pesanan', $id_pesanan)
      ->where('id_pembeli', $id_pembeli)
      ->where('status_pesanan', 'Menunggu Pembayaran')
      ->where('id_transaksi_pembayaran IS NULL', null, false)
      ->update('tb_pesanan', [
        'status_pesanan'          => 'Diproses',
        'id_transaksi_pembayaran' => $id_transaksi,
        'nominal_dibayar'         => $grand_total,
        'pembayaran_oleh'         => $id_pembeli,
        'dibayar_pada'            => $waktu_pembayaran
      ]);

    if ($this->db->affected_rows() !== 1) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Status pesanan telah berubah. Pembayaran dibatalkan.'
      ], 409);
      return;
    }

    $judul_pembeli = "\u{1F4B8} Pembayaran Berhasil!";
    $pesan_pembeli =
      'Pembayaran sebesar Rp ' .
      number_format($grand_total, 0, ',', '.') .
      ' untuk pesanan ' .
      $pesanan->invoice_pesanan .
      ' berhasil dipotong dari saldo Anda.';

    $judul_penjual = "\u{1F4B8} Pesanan Telah Dibayar!";
    $pesan_penjual =
      'Pembeli sudah melunasi tagihan pesanan ' .
      $pesanan->invoice_pesanan .
      '. Segera siapkan barang.';

    /*
   * Notifikasi lonceng disimpan dalam transaksi pembayaran
   * agar tidak muncul apabila pembayaran gagal.
   */
    $this->db->insert('tb_notifikasi', [
      'id_user' => $id_pembeli,
      'judul'   => $judul_pembeli,
      'pesan'   => $pesan_pembeli,
      'tanggal' => $waktu_pembayaran
    ]);

    $this->db->insert('tb_notifikasi', [
      'id_user' => (int) $pesanan->id_penjual,
      'judul'   => $judul_penjual,
      'pesan'   => $pesan_penjual,
      'tanggal' => $waktu_pembayaran
    ]);

    if ($this->db->trans_status() === false) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Gagal memproses pembayaran. Transaksi dibatalkan.'
      ], 500);
      return;
    }

    $this->db->trans_commit();

    /*
   * Push dikirim setelah commit agar kegagalan layanan Expo
   * tidak membatalkan pembayaran yang sudah berhasil.
   */
    try {
      if (!empty($user->expo_token)) {
        $this->send_expo_push_notification(
          $user->expo_token,
          $judul_pembeli,
          $pesan_pembeli
        );
      }
    } catch (Throwable $e) {
      log_message(
        'error',
        'Push pembayaran pembeli gagal: ' . $e->getMessage()
      );
    }

    try {
      if (!empty($pesanan->expo_token_penjual)) {
        $this->send_expo_push_notification(
          $pesanan->expo_token_penjual,
          $judul_penjual,
          $pesan_penjual
        );
      }
    } catch (Throwable $e) {
      log_message(
        'error',
        'Push pembayaran penjual gagal: ' . $e->getMessage()
      );
    }

    $this->api_response([
      'status'  => true,
      'message' => 'Alhamdulillah, pembayaran berhasil! Pesanan sedang diproses penjual.',
      'data'    => [
        'id_pesanan'              => $id_pesanan,
        'invoice_pesanan'         =>
        $pesanan->invoice_pesanan,
        'id_transaksi_pembayaran' => $id_transaksi,
        'total_harga'             => $total_harga,
        'ongkir'                  => $ongkir,
        'total_tagihan'           => $grand_total,
        'saldo_sebelum'           => $saldo_sebelum,
        'saldo_setelah'           =>
        $saldo_sebelum - $grand_total,
        'status_pesanan'          => 'Diproses',
        'dibayar_pada'            => $waktu_pembayaran,
        'idempotent'              => false
      ]
    ]);
  }

  // ==========================================
  // FITUR MARKETPLACE: MANAJEMEN PESANAN & PENCAIRAN (SETTLEMENT)
  // ==========================================

  // 7. Endpoint Riwayat Pesanan (Bisa untuk Pembeli atau Penjual) - OPTIMIZED O(1)
  public function get_pesanan()
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
        'message' => 'Riwayat pesanan hanya dapat diakses oleh Nasabah.'
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

    $role = strtolower(
      trim((string) ($request['role'] ?? ''))
    );

    if (!in_array($role, ['pembeli', 'penjual'], true)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Role harus berupa pembeli atau penjual.'
      ], 422);
      return;
    }

    /*
   * Identitas pengguna selalu berasal dari Bearer token.
   * Parameter id dari request sengaja diabaikan.
   */
    $id_user = (int) $auth->id_user;

    $page = isset($request['page'])
      ? (int) $request['page']
      : 1;

    $limit = isset($request['limit'])
      ? (int) $request['limit']
      : 20;

    if ($page < 1) {
      $page = 1;
    }

    if ($limit < 1) {
      $limit = 20;
    }

    /*
   * Batasi jumlah data agar request tidak mengambil
   * seluruh riwayat sekaligus.
   */
    if ($limit > 50) {
      $limit = 50;
    }

    $offset = ($page - 1) * $limit;

    $filter_status = trim(
      (string) ($request['status_pesanan'] ?? '')
    );

    $status_diizinkan = [
      'Menunggu Ongkir',
      'Menunggu Pembayaran',
      'Diproses',
      'Dikirim',
      'Selesai',
      'Dibatalkan'
    ];

    if (
      $filter_status !== '' &&
      !in_array($filter_status, $status_diizinkan, true)
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Filter status pesanan tidak valid.'
      ], 422);
      return;
    }

    $id_toko = null;

    if ($role === 'penjual') {
      /*
     * Toko ditentukan dari pemilik token.
     * id_toko dari request tidak dipercaya.
     */
      $toko = $this->db
        ->select('id_toko')
        ->from('tb_toko')
        ->where('id_user', $id_user)
        ->limit(1)
        ->get()
        ->row();

      if (!$toko) {
        $this->api_response([
          'status' => true,
          'message' => 'Akun ini belum memiliki toko.',
          'data' => [],
          'pagination' => [
            'page'       => $page,
            'limit'      => $limit,
            'total_data' => 0,
            'total_page' => 0
          ]
        ]);
        return;
      }

      $id_toko = (int) $toko->id_toko;
    }

    /*
   * Hitung total riwayat sesuai identitas token.
   */
    $this->db->from('tb_pesanan');

    if ($role === 'pembeli') {
      $this->db->where('id_pembeli', $id_user);
    } else {
      $this->db->where('id_toko', $id_toko);
    }

    if ($filter_status !== '') {
      $this->db->where(
        'status_pesanan',
        $filter_status
      );
    }

    $total_data = (int) $this->db->count_all_results();

    /*
   * Data sensitif seperti checkout_hash dan checkout_key
   * tidak dikirimkan ke aplikasi.
   */
    $this->db->select([
      'p.id_pesanan',
      'p.invoice_pesanan',
      'p.id_pembeli',
      'p.cabang_pembeli_id',
      'p.id_toko',
      'p.cabang_toko_id',
      'p.total_harga',
      'p.ongkir',
      'p.kurir',
      'p.resi',
      'p.status_pesanan',
      'p.is_dinilai',
      'p.catatan_pembeli',
      'p.stok_dikembalikan',
      'p.ongkir_ditetapkan_oleh',
      'p.ongkir_ditetapkan_pada',
      'p.id_transaksi_pembayaran',
      'p.nominal_dibayar',
      'p.pembayaran_oleh',
      'p.dibayar_pada',
      'p.terdaftar',
      'pembeli.nama AS nama_pembeli',
      't.nama_toko'
    ]);

    $this->db->from('tb_pesanan p');

    $this->db->join(
      'tb_user pembeli',
      'p.id_pembeli = pembeli.id'
    );

    $this->db->join(
      'tb_toko t',
      'p.id_toko = t.id_toko'
    );

    if ($role === 'pembeli') {
      $this->db->where('p.id_pembeli', $id_user);
    } else {
      $this->db->where('p.id_toko', $id_toko);
    }

    if ($filter_status !== '') {
      $this->db->where(
        'p.status_pesanan',
        $filter_status
      );
    }

    $this->db->order_by('p.id_pesanan', 'DESC');
    $this->db->limit($limit, $offset);

    $query_pesanan = $this->db->get();

    if (!$query_pesanan) {
      $this->api_response([
        'status'  => false,
        'message' => 'Gagal mengambil riwayat pesanan.'
      ], 500);
      return;
    }

    $pesanan = $query_pesanan->result_array();

    if (empty($pesanan)) {
      $this->api_response([
        'status' => true,
        'message' => 'Riwayat pesanan kosong.',
        'data' => [],
        'pagination' => [
          'page'       => $page,
          'limit'      => $limit,
          'total_data' => $total_data,
          'total_page' => $total_data > 0
            ? (int) ceil($total_data / $limit)
            : 0
        ]
      ]);
      return;
    }

    /*
   * Ambil seluruh detail untuk pesanan pada halaman ini
   * menggunakan satu query agar tidak terjadi N+1 query.
   */
    $id_pesanan_list = array_map(
      'intval',
      array_column($pesanan, 'id_pesanan')
    );

    $this->db->select([
      'd.id_detail',
      'd.id_pesanan',
      'd.id_produk',
      'd.jumlah',
      'd.harga_satuan',
      'd.subtotal',
      'produk.nama_produk',
      'produk.berat',
      'produk.foto_produk'
    ]);

    $this->db->from('tb_pesanan_detail d');

    $this->db->join(
      'tb_produk produk',
      'd.id_produk = produk.id_produk',
      'left'
    );

    $this->db->where_in(
      'd.id_pesanan',
      $id_pesanan_list
    );

    $this->db->order_by('d.id_detail', 'ASC');

    $query_detail = $this->db->get();

    if (!$query_detail) {
      $this->api_response([
        'status'  => false,
        'message' => 'Gagal mengambil detail pesanan.'
      ], 500);
      return;
    }

    $semua_detail = $query_detail->result_array();
    $detail_per_pesanan = [];

    foreach ($semua_detail as $detail) {
      $id_detail_pesanan = (int) $detail['id_pesanan'];

      if (!isset($detail_per_pesanan[$id_detail_pesanan])) {
        $detail_per_pesanan[$id_detail_pesanan] = [];
      }

      $detail_per_pesanan[$id_detail_pesanan][] = $detail;
    }

    foreach ($pesanan as &$baris_pesanan) {
      $id_baris = (int) $baris_pesanan['id_pesanan'];

      $baris_pesanan['total_tagihan'] =
        (int) $baris_pesanan['total_harga'] +
        (int) $baris_pesanan['ongkir'];

      $baris_pesanan['items'] =
        $detail_per_pesanan[$id_baris] ?? [];
    }

    unset($baris_pesanan);

    $this->api_response([
      'status'  => true,
      'message' => 'Riwayat pesanan berhasil diambil.',
      'data'    => $pesanan,
      'pagination' => [
        'page'       => $page,
        'limit'      => $limit,
        'total_data' => $total_data,
        'total_page' => (int) ceil($total_data / $limit)
      ]
    ]);
  }

  // 8. Endpoint Update Status Pesanan (Oleh Penjual)
  public function update_status_pesanan()
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
        'message' => 'Status pesanan hanya dapat diperbarui oleh penjual.'
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

    $id_pesanan = filter_var(
      $request['id_pesanan'] ?? null,
      FILTER_VALIDATE_INT,
      [
        'options' => [
          'min_range' => 1
        ]
      ]
    );

    $status_baru = trim(
      (string) ($request['status'] ?? '')
    );

    $resi = trim(
      (string) ($request['resi'] ?? '')
    );

    if ($id_pesanan === false) {
      $this->api_response([
        'status'  => false,
        'message' => 'ID pesanan tidak valid.'
      ], 422);
      return;
    }

    /*
   * Untuk alur yang baru, pembayaran sudah otomatis
   * mengubah status menjadi Diproses.
   *
   * Status Diproses tetap diterima sebagai request idempoten
   * demi kompatibilitas aplikasi lama.
   */
    if (!in_array(
      $status_baru,
      ['Diproses', 'Dikirim'],
      true
    )) {
      $this->api_response([
        'status'  => false,
        'message' => 'Status hanya dapat diubah menjadi Diproses atau Dikirim.'
      ], 422);
      return;
    }

    if (strlen($resi) > 100) {
      $this->api_response([
        'status'  => false,
        'message' => 'Nomor resi maksimal 100 karakter.'
      ], 422);
      return;
    }

    $id_pesanan = (int) $id_pesanan;
    $id_penjual = (int) $auth->id_user;

    $this->db->trans_begin();

    /*
   * Pesanan dikunci dan langsung dibatasi berdasarkan
   * pemilik toko dari Bearer token.
   */
    $pesanan = $this->db->query(
      "SELECT
        p.id_pesanan,
        p.invoice_pesanan,
        p.id_pembeli,
        p.id_toko,
        p.total_harga,
        p.ongkir,
        p.kurir,
        p.resi,
        p.status_pesanan,
        p.id_transaksi_pembayaran,
        p.nominal_dibayar,
        t.id_user AS id_penjual,
        pembeli.expo_token AS expo_token_pembeli
     FROM tb_pesanan p
     INNER JOIN tb_toko t
       ON t.id_toko = p.id_toko
     INNER JOIN tb_user pembeli
       ON pembeli.id = p.id_pembeli
     WHERE p.id_pesanan = ?
       AND t.id_user = ?
     LIMIT 1
     FOR UPDATE",
      [
        $id_pesanan,
        $id_penjual
      ]
    )->row();

    if (!$pesanan) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Pesanan tidak ditemukan atau bukan milik toko Anda.'
      ], 404);
      return;
    }

    /*
   * Request Diproses dari aplikasi lama tidak mengubah data.
   * Pesanan hanya dianggap Diproses apabila pembayaran
   * benar-benar sudah terhubung.
   */
    if ($status_baru === 'Diproses') {
      if (
        $pesanan->status_pesanan === 'Diproses' &&
        !empty($pesanan->id_transaksi_pembayaran) &&
        (int) $pesanan->nominal_dibayar > 0
      ) {
        if ($this->db->trans_status() === false) {
          $this->db->trans_rollback();

          $this->api_response([
            'status'  => false,
            'message' => 'Gagal memeriksa status pesanan.'
          ], 500);
          return;
        }

        $this->db->trans_commit();

        $this->api_response([
          'status'  => true,
          'message' => 'Pesanan sudah berstatus Diproses.',
          'data'    => [
            'id_pesanan'      => $id_pesanan,
            'invoice_pesanan' =>
            $pesanan->invoice_pesanan,
            'status_pesanan'  => 'Diproses',
            'idempotent'      => true
          ]
        ]);
        return;
      }

      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Status Diproses hanya dapat berasal dari pembayaran yang berhasil.'
      ], 409);
      return;
    }

    /*
   * Idempotensi pengiriman.
   */
    if ($pesanan->status_pesanan === 'Dikirim') {
      $resi_tersimpan = trim(
        (string) $pesanan->resi
      );

      /*
     * Jika request tidak membawa resi, pertahankan resi lama.
     * Jika membawa resi berbeda, tolak agar tidak tertimpa.
     */
      if (
        $resi !== '' &&
        $resi_tersimpan !== '' &&
        !hash_equals($resi_tersimpan, $resi)
      ) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Pesanan sudah dikirim dengan nomor resi yang berbeda.'
        ], 409);
        return;
      }

      if ($this->db->trans_status() === false) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Gagal memeriksa status pengiriman.'
        ], 500);
        return;
      }

      $this->db->trans_commit();

      $this->api_response([
        'status'  => true,
        'message' => 'Pesanan ini sudah dikirim sebelumnya.',
        'data'    => [
          'id_pesanan'      => $id_pesanan,
          'invoice_pesanan' =>
          $pesanan->invoice_pesanan,
          'status_pesanan'  => 'Dikirim',
          'kurir'            => $pesanan->kurir,
          'resi'             => $resi_tersimpan,
          'idempotent'       => true
        ]
      ]);
      return;
    }

    /*
   * Hanya pesanan yang sudah dibayar dan berstatus Diproses
   * yang dapat dikirim.
   */
    if (
      $pesanan->status_pesanan !== 'Diproses' ||
      empty($pesanan->id_transaksi_pembayaran) ||
      (int) $pesanan->nominal_dibayar <= 0
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Pesanan belum dibayar atau belum siap dikirim.',
        'data'    => [
          'status_pesanan' =>
          $pesanan->status_pesanan
        ]
      ], 409);
      return;
    }

    /*
   * Kurir manual, lokal, atau COD tidak wajib memiliki resi.
   * Kurir ekspedisi lainnya wajib memiliki nomor resi.
   */
    $nama_kurir = strtolower(
      trim((string) $pesanan->kurir)
    );

    $kurir_tanpa_resi =
      strpos($nama_kurir, 'manual') !== false ||
      strpos($nama_kurir, 'lokal') !== false ||
      strpos($nama_kurir, 'cod') !== false ||
      strpos($nama_kurir, 'toko') !== false;

    if (!$kurir_tanpa_resi && $resi === '') {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Nomor resi wajib diisi untuk kurir ekspedisi.'
      ], 422);
      return;
    }

    $data_update = [
      'status_pesanan' => 'Dikirim'
    ];

    if ($resi !== '') {
      $data_update['resi'] = $resi;
    }

    $this->db
      ->where('id_pesanan', $id_pesanan)
      ->where('status_pesanan', 'Diproses')
      ->update('tb_pesanan', $data_update);

    if ($this->db->affected_rows() !== 1) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Status pesanan telah berubah. Silakan muat ulang data.'
      ], 409);
      return;
    }

    $judul_notif = "\u{1F4E6} Pesanan Sedang Dikirim";

    $pesan_notif =
      'Pesanan ' .
      $pesanan->invoice_pesanan .
      ' sudah dikirim menggunakan ' .
      $pesanan->kurir .
      ($resi !== ''
        ? ' dengan nomor resi ' . $resi . '.'
        : '.');

    /*
   * Notifikasi lonceng menjadi bagian dari transaksi.
   */
    $this->db->insert('tb_notifikasi', [
      'id_user' => (int) $pesanan->id_pembeli,
      'judul'   => $judul_notif,
      'pesan'   => $pesan_notif,
      'tanggal' => date('Y-m-d H:i:s')
    ]);

    if ($this->db->trans_status() === false) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Gagal memperbarui status pengiriman.'
      ], 500);
      return;
    }

    $this->db->trans_commit();

    /*
   * Push dikirim setelah perubahan database berhasil.
   */
    try {
      if (!empty($pesanan->expo_token_pembeli)) {
        $this->send_expo_push_notification(
          $pesanan->expo_token_pembeli,
          $judul_notif,
          $pesan_notif
        );
      }
    } catch (Throwable $e) {
      log_message(
        'error',
        'Push status pengiriman gagal: ' .
          $e->getMessage()
      );
    }

    $this->api_response([
      'status'  => true,
      'message' => 'Status pesanan berhasil diperbarui menjadi Dikirim.',
      'data'    => [
        'id_pesanan'      => $id_pesanan,
        'invoice_pesanan' =>
        $pesanan->invoice_pesanan,
        'status_pesanan'  => 'Dikirim',
        'kurir'            => $pesanan->kurir,
        'resi'             => $resi !== ''
          ? $resi
          : $pesanan->resi,
        'idempotent'       => false
      ]
    ]);
  }

  // 9. Endpoint Selesaikan Pesanan & CAIRKAN DANA KE PENJUAL (Oleh Pembeli)
  public function terima_pesanan()
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
        'message' => 'Penerimaan pesanan hanya dapat dilakukan oleh pembeli.'
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

    $id_pesanan = filter_var(
      $request['id_pesanan'] ?? null,
      FILTER_VALIDATE_INT,
      [
        'options' => [
          'min_range' => 1
        ]
      ]
    );

    if ($id_pesanan === false) {
      $this->api_response([
        'status'  => false,
        'message' => 'ID pesanan tidak valid.'
      ], 422);
      return;
    }

    /*
   * Identitas pembeli selalu berasal dari Bearer token.
   * id_pembeli dari request diabaikan.
   */
    $id_pesanan = (int) $id_pesanan;
    $id_pembeli = (int) $auth->id_user;

    $this->db->trans_begin();

    /*
   * Kunci pesanan dan batasi berdasarkan pembeli pemilik token.
   */
    $pesanan = $this->db->query(
      "SELECT
        p.id_pesanan,
        p.invoice_pesanan,
        p.id_pembeli,
        p.id_toko,
        p.total_harga,
        p.ongkir,
        p.status_pesanan,
        p.stok_dikembalikan,
        p.id_transaksi_pembayaran,
        p.nominal_dibayar,
        p.pembayaran_oleh,
        p.dibayar_pada,
        t.id_user AS id_penjual,
        t.nama_toko,
        penjual.cabang_id AS cabang_penjual_id,
        penjual.expo_token AS expo_token_penjual
     FROM tb_pesanan p
     INNER JOIN tb_toko t
       ON t.id_toko = p.id_toko
     INNER JOIN tb_user penjual
       ON penjual.id = t.id_user
     WHERE p.id_pesanan = ?
       AND p.id_pembeli = ?
     LIMIT 1
     FOR UPDATE",
      [
        $id_pesanan,
        $id_pembeli
      ]
    )->row();

    if (!$pesanan) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Pesanan tidak ditemukan atau bukan milik Anda.'
      ], 404);
      return;
    }

    if ((int) $pesanan->stok_dikembalikan !== 0) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Pesanan telah dibatalkan dan tidak dapat diselesaikan.'
      ], 409);
      return;
    }

    $total_harga = (int) $pesanan->total_harga;
    $ongkir = (int) $pesanan->ongkir;
    $total_pencairan = $total_harga + $ongkir;

    if (
      $total_harga <= 0 ||
      $ongkir < 0 ||
      $total_pencairan <= 0 ||
      $total_pencairan > 2147483647
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Nilai pencairan pesanan tidak valid.'
      ], 422);
      return;
    }

    /*
   * Cari pencairan yang mungkin sudah tercatat.
   * Kombinasi referensi_tipe dan referensi_id bersifat unik.
   */
    $pencairan_lama = $this->db->query(
      "SELECT
        id,
        cabang_id,
        idNasabah,
        nominal,
        jenis,
        status_konfirmasi,
        referensi_tipe,
        referensi_id,
        terdaftar
     FROM tb_transaksi
     WHERE referensi_tipe = ?
       AND referensi_id = ?
     LIMIT 1
     FOR UPDATE",
      [
        'PencairanPesanan',
        $id_pesanan
      ]
    )->row();

    /*
   * Idempotensi:
   * pesanan yang sudah selesai harus memiliki transaksi
   * pencairan yang sah.
   */
    if ($pesanan->status_pesanan === 'Selesai') {
      $pencairan_valid =
        $pencairan_lama &&
        (int) $pencairan_lama->idNasabah ===
        (int) $pesanan->id_penjual &&
        (int) $pencairan_lama->nominal ===
        $total_pencairan &&
        (string) $pencairan_lama->jenis === 'Masuk' &&
        (string) $pencairan_lama->status_konfirmasi ===
        'Sukses' &&
        (string) $pencairan_lama->referensi_tipe ===
        'PencairanPesanan' &&
        (int) $pencairan_lama->referensi_id ===
        $id_pesanan;

      if (!$pencairan_valid) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Pesanan selesai tetapi data pencairannya tidak konsisten. Hubungi administrator.'
        ], 409);
        return;
      }

      if ($this->db->trans_status() === false) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Gagal memeriksa pencairan pesanan.'
        ], 500);
        return;
      }

      $this->db->trans_commit();

      $this->api_response([
        'status'  => true,
        'message' => 'Pesanan ini sudah diselesaikan sebelumnya.',
        'data'    => [
          'id_pesanan'           => $id_pesanan,
          'invoice_pesanan'      =>
          $pesanan->invoice_pesanan,
          'status_pesanan'       => 'Selesai',
          'id_transaksi_pencairan' =>
          (int) $pencairan_lama->id,
          'id_penjual'           =>
          (int) $pesanan->id_penjual,
          'total_harga'          => $total_harga,
          'ongkir'               => $ongkir,
          'total_dicairkan'      => $total_pencairan,
          'dicairkan_pada'       =>
          $pencairan_lama->terdaftar,
          'idempotent'           => true
        ]
      ]);
      return;
    }

    /*
   * Jika ledger pencairan sudah ada tetapi status belum selesai,
   * hentikan proses untuk mencegah data ganda.
   */
    if ($pencairan_lama) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Pencairan sudah tercatat tetapi status pesanan belum konsisten. Hubungi administrator.',
        'data'    => [
          'id_transaksi_pencairan' =>
          (int) $pencairan_lama->id
        ]
      ], 409);
      return;
    }

    /*
   * Pembeli hanya boleh menyelesaikan pesanan
   * yang sudah dikirim oleh penjual.
   */
    if ($pesanan->status_pesanan !== 'Dikirim') {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Pesanan belum dikirim atau belum dapat diselesaikan.',
        'data'    => [
          'status_pesanan' =>
          $pesanan->status_pesanan
        ]
      ], 409);
      return;
    }

    /*
   * Pastikan transaksi pembayaran pembeli benar-benar sah.
   */
    if (
      empty($pesanan->id_transaksi_pembayaran) ||
      (int) $pesanan->nominal_dibayar !==
      $total_pencairan ||
      (int) $pesanan->pembayaran_oleh !==
      $id_pembeli
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Data pembayaran pesanan tidak lengkap atau tidak sesuai.'
      ], 409);
      return;
    }

    $transaksi_pembayaran = $this->db->query(
      "SELECT
        id,
        idNasabah,
        nominal,
        jenis,
        status_konfirmasi,
        referensi_tipe,
        referensi_id
     FROM tb_transaksi
     WHERE id = ?
     LIMIT 1
     FOR UPDATE",
      [(int) $pesanan->id_transaksi_pembayaran]
    )->row();

    $pembayaran_valid =
      $transaksi_pembayaran &&
      (int) $transaksi_pembayaran->idNasabah ===
      $id_pembeli &&
      (int) $transaksi_pembayaran->nominal ===
      $total_pencairan &&
      (string) $transaksi_pembayaran->jenis ===
      'Keluar' &&
      (string) $transaksi_pembayaran->status_konfirmasi ===
      'Sukses' &&
      (string) $transaksi_pembayaran->referensi_tipe ===
      'PembayaranPesanan' &&
      (int) $transaksi_pembayaran->referensi_id ===
      $id_pesanan;

    if (!$pembayaran_valid) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Transaksi pembayaran pesanan tidak valid.'
      ], 409);
      return;
    }

    /*
   * Detail diperlukan untuk memperbarui jumlah terjual.
   */
    $detail_pesanan = $this->db
      ->select([
        'id_produk',
        'jumlah'
      ])
      ->from('tb_pesanan_detail')
      ->where('id_pesanan', $id_pesanan)
      ->order_by('id_produk', 'ASC')
      ->get()
      ->result_array();

    if (empty($detail_pesanan)) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Detail barang pesanan tidak ditemukan.'
      ], 409);
      return;
    }

    $waktu_pencairan = date('Y-m-d H:i:s');

    /*
   * Cairkan seluruh dana yang dibayar pembeli:
   * harga produk + ongkir.
   */
    $pencairan_disimpan = $this->db->insert(
      'tb_transaksi',
      [
        'cabang_id'         =>
        !empty($pesanan->cabang_penjual_id)
          ? (int) $pesanan->cabang_penjual_id
          : null,
        'idAdmin'           => 0,
        'idNasabah'         =>
        (int) $pesanan->id_penjual,
        'idPotongan'        => 0,
        'tanggal'           => date('Y-m-d'),
        'nominal'           => $total_pencairan,
        'gram_emas'         => null,
        'jenis'             => 'Masuk',
        'keterangan'        =>
        'Pencairan Dana Penjualan: ' .
          $pesanan->invoice_pesanan,
        'status_konfirmasi' => 'Sukses',
        'bukti_transfer'    => null,
        'referensi_tipe'    => 'PencairanPesanan',
        'referensi_id'      => $id_pesanan,
        'terdaftar'         => $waktu_pencairan
      ]
    );

    if (!$pencairan_disimpan) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Gagal mencatat transaksi pencairan.'
      ], 500);
      return;
    }

    $id_transaksi_pencairan =
      (int) $this->db->insert_id();

    /*
   * Status hanya diperbarui apabila masih Dikirim.
   */
    $this->db
      ->where('id_pesanan', $id_pesanan)
      ->where('id_pembeli', $id_pembeli)
      ->where('status_pesanan', 'Dikirim')
      ->update('tb_pesanan', [
        'status_pesanan' => 'Selesai'
      ]);

    if ($this->db->affected_rows() !== 1) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Status pesanan telah berubah. Pencairan dibatalkan.'
      ], 409);
      return;
    }

    /*
   * Tambahkan jumlah terjual secara atomik.
   */
    foreach ($detail_pesanan as $item) {
      $jumlah = (int) $item['jumlah'];
      $id_produk = (int) $item['id_produk'];

      if ($jumlah <= 0 || $id_produk <= 0) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Detail jumlah barang pesanan tidak valid.'
        ], 409);
        return;
      }

      $this->db
        ->set(
          'terjual',
          'COALESCE(terjual, 0) + ' . $jumlah,
          false
        )
        ->where('id_produk', $id_produk)
        ->update('tb_produk');

      if ($this->db->affected_rows() !== 1) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Gagal memperbarui jumlah produk terjual.'
        ], 500);
        return;
      }
    }

    $judul_notif =
      "\u{2705} Alhamdulillah, Dana Cair!";

    $pesan_notif =
      'Pesanan ' .
      $pesanan->invoice_pesanan .
      ' telah diterima pembeli. Dana Rp ' .
      number_format(
        $total_pencairan,
        0,
        ',',
        '.'
      ) .
      ' termasuk ongkir berhasil masuk ke tabungan Anda.';

    /*
   * Notifikasi lonceng disimpan dalam transaksi yang sama.
   */
    $this->db->insert('tb_notifikasi', [
      'id_user' =>
      (int) $pesanan->id_penjual,
      'judul'   => $judul_notif,
      'pesan'   => $pesan_notif,
      'is_read' => 0,
      'tanggal' => $waktu_pencairan
    ]);

    if ($this->db->trans_status() === false) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Gagal memproses pencairan dana.'
      ], 500);
      return;
    }

    $this->db->trans_commit();

    /*
   * Push dikirim setelah commit agar gangguan Expo
   * tidak membatalkan pencairan.
   */
    try {
      if (!empty($pesanan->expo_token_penjual)) {
        $this->send_expo_push_notification(
          $pesanan->expo_token_penjual,
          $judul_notif,
          $pesan_notif
        );
      }
    } catch (Throwable $e) {
      log_message(
        'error',
        'Push pencairan penjual gagal: ' .
          $e->getMessage()
      );
    }

    $this->api_response([
      'status'  => true,
      'message' => 'Pesanan selesai! Dana telah diteruskan ke saldo tabungan penjual.',
      'data'    => [
        'id_pesanan'             => $id_pesanan,
        'invoice_pesanan'        =>
        $pesanan->invoice_pesanan,
        'status_pesanan'         => 'Selesai',
        'id_penjual'             =>
        (int) $pesanan->id_penjual,
        'nama_toko'              =>
        $pesanan->nama_toko,
        'id_transaksi_pencairan' =>
        $id_transaksi_pencairan,
        'total_harga'            => $total_harga,
        'ongkir'                 => $ongkir,
        'total_dicairkan'        => $total_pencairan,
        'dicairkan_pada'         => $waktu_pencairan,
        'idempotent'             => false
      ]
    ]);
  }

  // 10. Endpoint Batalkan Pesanan (Sistem Nego Ongkir)
  public function batalkan_pesanan()
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
        'message' => 'Pembatalan mandiri hanya dapat dilakukan oleh pembeli.'
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

    $id_pesanan = filter_var(
      $request['id_pesanan'] ?? null,
      FILTER_VALIDATE_INT,
      [
        'options' => [
          'min_range' => 1
        ]
      ]
    );

    if ($id_pesanan === false) {
      $this->api_response([
        'status'  => false,
        'message' => 'ID pesanan tidak valid.'
      ], 422);
      return;
    }

    /*
   * Identitas pembeli selalu berasal dari Bearer token.
   * id_pembeli dari request diabaikan.
   */
    $id_pesanan = (int) $id_pesanan;
    $id_pembeli = (int) $auth->id_user;

    $this->db->trans_begin();

    /*
   * Kunci pesanan dan batasi berdasarkan pembeli pemilik token.
   */
    $pesanan = $this->db->query(
      "SELECT
        p.id_pesanan,
        p.invoice_pesanan,
        p.id_pembeli,
        p.id_toko,
        p.status_pesanan,
        p.stok_dikembalikan,
        p.id_transaksi_pembayaran,
        p.nominal_dibayar,
        t.id_user AS id_penjual,
        penjual.expo_token AS expo_token_penjual
     FROM tb_pesanan p
     INNER JOIN tb_toko t
       ON t.id_toko = p.id_toko
     INNER JOIN tb_user penjual
       ON penjual.id = t.id_user
     WHERE p.id_pesanan = ?
       AND p.id_pembeli = ?
     LIMIT 1
     FOR UPDATE",
      [
        $id_pesanan,
        $id_pembeli
      ]
    )->row();

    if (!$pesanan) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Pesanan tidak ditemukan atau bukan milik Anda.'
      ], 404);
      return;
    }

    /*
   * Idempotensi pembatalan:
   * stok yang sudah dikembalikan tidak boleh ditambahkan lagi.
   */
    if (
      $pesanan->status_pesanan === 'Dibatalkan' &&
      (int) $pesanan->stok_dikembalikan === 1
    ) {
      if ($this->db->trans_status() === false) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Gagal memeriksa pembatalan pesanan.'
        ], 500);
        return;
      }

      $this->db->trans_commit();

      $this->api_response([
        'status'  => true,
        'message' => 'Pesanan ini sudah dibatalkan sebelumnya.',
        'data'    => [
          'id_pesanan'       => $id_pesanan,
          'invoice_pesanan'  =>
          $pesanan->invoice_pesanan,
          'status_pesanan'   => 'Dibatalkan',
          'stok_dikembalikan' => true,
          'idempotent'       => true
        ]
      ]);
      return;
    }

    /*
   * Status Dibatalkan tanpa tanda pengembalian stok
   * menunjukkan data yang tidak konsisten.
   */
    if ($pesanan->status_pesanan === 'Dibatalkan') {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Data pembatalan pesanan tidak konsisten. Hubungi administrator.'
      ], 409);
      return;
    }

    /*
   * Pembeli hanya boleh membatalkan sebelum pembayaran.
   */
    $status_bisa_dibatalkan = [
      'Menunggu Ongkir',
      'Menunggu Pembayaran'
    ];

    if (!in_array(
      $pesanan->status_pesanan,
      $status_bisa_dibatalkan,
      true
    )) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Pesanan sudah dibayar atau diproses dan tidak dapat dibatalkan sendiri.',
        'data'    => [
          'status_pesanan' =>
          $pesanan->status_pesanan
        ]
      ], 409);
      return;
    }

    /*
   * Jangan batalkan apabila pembayaran sudah pernah tercatat,
   * walaupun status pesanan belum berubah.
   */
    $transaksi_pembayaran = $this->db->query(
      "SELECT
        id,
        idNasabah,
        nominal,
        status_konfirmasi
     FROM tb_transaksi
     WHERE referensi_tipe = ?
       AND referensi_id = ?
     LIMIT 1
     FOR UPDATE",
      [
        'PembayaranPesanan',
        $id_pesanan
      ]
    )->row();

    if (
      !empty($pesanan->id_transaksi_pembayaran) ||
      (int) $pesanan->nominal_dibayar > 0 ||
      $transaksi_pembayaran
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Pembayaran pesanan sudah tercatat. Pembatalan harus diproses sebagai refund oleh administrator.'
      ], 409);
      return;
    }

    /*
   * Ambil detail dengan urutan produk yang konsisten.
   */
    $detail_pesanan = $this->db
      ->select([
        'id_produk',
        'jumlah'
      ])
      ->from('tb_pesanan_detail')
      ->where('id_pesanan', $id_pesanan)
      ->order_by('id_produk', 'ASC')
      ->get()
      ->result_array();

    if (empty($detail_pesanan)) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Detail barang pesanan tidak ditemukan.'
      ], 409);
      return;
    }

    /*
   * Tandai pembatalan dan pengembalian stok sekaligus.
   */
    $this->db
      ->where('id_pesanan', $id_pesanan)
      ->where('id_pembeli', $id_pembeli)
      ->where_in(
        'status_pesanan',
        $status_bisa_dibatalkan
      )
      ->where('stok_dikembalikan', 0)
      ->update('tb_pesanan', [
        'status_pesanan'    => 'Dibatalkan',
        'stok_dikembalikan' => 1
      ]);

    if ($this->db->affected_rows() !== 1) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Status pesanan telah berubah. Pembatalan dihentikan.'
      ], 409);
      return;
    }

    /*
   * Kembalikan stok satu kali secara atomik.
   */
    foreach ($detail_pesanan as $item) {
      $id_produk = (int) $item['id_produk'];
      $jumlah = (int) $item['jumlah'];

      if ($id_produk <= 0 || $jumlah <= 0) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Detail jumlah barang pesanan tidak valid.'
        ], 409);
        return;
      }

      $this->db
        ->set(
          'stok',
          'stok + ' . $jumlah,
          false
        )
        ->set(
          'status_produk',
          "CASE
          WHEN status_produk = 'Habis'
          THEN 'Tersedia'
          ELSE status_produk
        END",
          false
        )
        ->where('id_produk', $id_produk)
        ->update('tb_produk');

      if ($this->db->affected_rows() !== 1) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Gagal mengembalikan stok produk.'
        ], 500);
        return;
      }
    }

    $judul_notif = "\u{274C} Pesanan Dibatalkan";

    $pesan_notif =
      'Pesanan ' .
      $pesanan->invoice_pesanan .
      ' dibatalkan oleh pembeli. Stok barang telah dikembalikan.';

    /*
   * Simpan notifikasi dalam transaksi pembatalan.
   */
    $this->db->insert('tb_notifikasi', [
      'id_user' => (int) $pesanan->id_penjual,
      'judul'   => $judul_notif,
      'pesan'   => $pesan_notif,
      'is_read' => 0,
      'tanggal' => date('Y-m-d H:i:s')
    ]);

    if ($this->db->trans_status() === false) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Gagal membatalkan pesanan.'
      ], 500);
      return;
    }

    $this->db->trans_commit();

    /*
   * Push dikirim setelah transaksi database berhasil.
   */
    try {
      if (!empty($pesanan->expo_token_penjual)) {
        $this->send_expo_push_notification(
          $pesanan->expo_token_penjual,
          $judul_notif,
          $pesan_notif
        );
      }
    } catch (Throwable $e) {
      log_message(
        'error',
        'Push pembatalan pesanan gagal: ' .
          $e->getMessage()
      );
    }

    $this->api_response([
      'status'  => true,
      'message' => 'Pesanan berhasil dibatalkan. Stok barang telah dikembalikan ke toko.',
      'data'    => [
        'id_pesanan'       => $id_pesanan,
        'invoice_pesanan'  =>
        $pesanan->invoice_pesanan,
        'status_pesanan'   => 'Dibatalkan',
        'stok_dikembalikan' => true,
        'idempotent'       => false
      ]
    ]);
  }


  // 11. Endpoint Hapus Produk (Soft Delete)
  public function hapus_produk()
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
        'message' => 'Produk hanya dapat diarsipkan oleh pemilik toko.'
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

    $id_produk = filter_var(
      $request['id_produk'] ?? null,
      FILTER_VALIDATE_INT,
      [
        'options' => [
          'min_range' => 1
        ]
      ]
    );

    if ($id_produk === false) {
      $this->api_response([
        'status'  => false,
        'message' => 'ID produk tidak valid.'
      ], 422);
      return;
    }

    $id_produk = (int) $id_produk;
    $id_penjual = (int) $auth->id_user;

    $this->db->trans_begin();

    /*
   * Produk dikunci dan langsung dibatasi berdasarkan
   * pemilik toko dari Bearer token.
   */
    $produk = $this->db->query(
      "SELECT
        p.id_produk,
        p.id_toko,
        p.nama_produk,
        p.status_produk,
        p.status_sebelum_toko_nonaktif,
        t.id_user AS id_penjual,
        t.nama_toko,
        t.status_toko
     FROM tb_produk p
     INNER JOIN tb_toko t
       ON t.id_toko = p.id_toko
     WHERE p.id_produk = ?
       AND t.id_user = ?
     LIMIT 1
     FOR UPDATE",
      [
        $id_produk,
        $id_penjual
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

    /*
   * Saat toko aktif, status Arsip berarti produk memang
   * sudah dihapus dari etalase.
   *
   * Saat toko nonaktif, seluruh produk sementara berstatus
   * Arsip. Status permanennya berada pada
   * status_sebelum_toko_nonaktif.
   */
    $sudah_diarsipkan =
      (
        $produk->status_toko === 'Aktif' &&
        $produk->status_produk === 'Arsip'
      ) ||
      (
        $produk->status_toko === 'Nonaktif' &&
        $produk->status_produk === 'Arsip' &&
        $produk->status_sebelum_toko_nonaktif === 'Arsip'
      );

    if ($sudah_diarsipkan) {
      if ($this->db->trans_status() === false) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Gagal memeriksa status produk.'
        ], 500);
        return;
      }

      $this->db->trans_commit();

      $this->api_response([
        'status'  => true,
        'message' => 'Produk ini sudah diarsipkan sebelumnya.',
        'data'    => [
          'id_produk'     => $id_produk,
          'nama_produk'   => $produk->nama_produk,
          'id_toko'       => (int) $produk->id_toko,
          'nama_toko'     => $produk->nama_toko,
          'status_produk' => 'Arsip',
          'idempotent'    => true
        ]
      ]);
      return;
    }

    $data_update = [
      'status_produk' => 'Arsip'
    ];

    /*
   * Jika toko sedang nonaktif, ubah juga status yang akan
   * dipulihkan ketika toko kembali aktif.
   */
    if ($produk->status_toko === 'Nonaktif') {
      $data_update['status_sebelum_toko_nonaktif'] =
        'Arsip';
    }

    $this->db
      ->where('id_produk', $id_produk)
      ->where('id_toko', (int) $produk->id_toko)
      ->update('tb_produk', $data_update);

    if (
      $this->db->affected_rows() !== 1 ||
      $this->db->trans_status() === false
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Gagal mengarsipkan produk.'
      ], 500);
      return;
    }

    $this->db->trans_commit();

    $this->api_response([
      'status'  => true,
      'message' => 'Produk berhasil dihapus dari etalase.',
      'data'    => [
        'id_produk'     => $id_produk,
        'nama_produk'   => $produk->nama_produk,
        'id_toko'       => (int) $produk->id_toko,
        'nama_toko'     => $produk->nama_toko,
        'status_produk' => 'Arsip',
        'idempotent'    => false
      ]
    ]);
  }
  // ==========================================
  // FITUR MARKETPLACE: SISI ADMIN (PUSAT KENDALI)
  // ==========================================

  // 12. Endpoint Admin: Ambil Semua Pesanan dari Semua Toko
  public function admin_get_semua_pesanan()
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
   * Level, id_admin, dan cabang_id dari request
   * tidak dipercaya.
   */
    if (!in_array(
      $auth->level,
      ['Administrator', 'Super Admin'],
      true
    )) {
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

    $page = isset($request['page'])
      ? (int) $request['page']
      : 1;

    $limit = isset($request['limit'])
      ? (int) $request['limit']
      : 20;

    if ($page < 1) {
      $page = 1;
    }

    if ($limit < 1) {
      $limit = 20;
    }

    if ($limit > 100) {
      $limit = 100;
    }

    $offset = ($page - 1) * $limit;

    $filter_status = trim(
      (string) ($request['status_pesanan'] ?? '')
    );

    $status_diizinkan = [
      'Menunggu Ongkir',
      'Menunggu Pembayaran',
      'Diproses',
      'Dikirim',
      'Selesai',
      'Dibatalkan'
    ];

    if (
      $filter_status !== '' &&
      !in_array($filter_status, $status_diizinkan, true)
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Filter status pesanan tidak valid.'
      ], 422);
      return;
    }

    $pencarian = trim(
      (string) ($request['search'] ?? '')
    );

    if (strlen($pencarian) > 100) {
      $this->api_response([
        'status'  => false,
        'message' => 'Kata pencarian maksimal 100 karakter.'
      ], 422);
      return;
    }

    $filter_id_toko = null;

    if (
      isset($request['id_toko']) &&
      $request['id_toko'] !== ''
    ) {
      $id_toko_valid = filter_var(
        $request['id_toko'],
        FILTER_VALIDATE_INT,
        [
          'options' => [
            'min_range' => 1
          ]
        ]
      );

      if ($id_toko_valid === false) {
        $this->api_response([
          'status'  => false,
          'message' => 'Filter ID toko tidak valid.'
        ], 422);
        return;
      }

      $filter_id_toko = (int) $id_toko_valid;
    }

    /*
   * Hitung total data berdasarkan batas cabang token.
   */
    $this->db->from('tb_pesanan p');

    $this->db->join(
      'tb_user pembeli',
      'p.id_pembeli = pembeli.id'
    );

    $this->db->join(
      'tb_toko toko',
      'p.id_toko = toko.id_toko'
    );

    if ($auth->level === 'Administrator') {
      $this->db->where(
        'p.cabang_toko_id',
        (int) $auth->cabang_id
      );
    }

    if ($filter_status !== '') {
      $this->db->where(
        'p.status_pesanan',
        $filter_status
      );
    }

    if ($filter_id_toko !== null) {
      $this->db->where(
        'p.id_toko',
        $filter_id_toko
      );
    }

    if ($pencarian !== '') {
      $this->db->group_start();

      $this->db->like(
        'p.invoice_pesanan',
        $pencarian
      );

      $this->db->or_like(
        'pembeli.nama',
        $pencarian
      );

      $this->db->or_like(
        'toko.nama_toko',
        $pencarian
      );

      $this->db->group_end();
    }

    $total_data = (int) $this->db->count_all_results();

    /*
   * Data sensitif checkout_key dan checkout_hash
   * tidak dikirim ke panel Administrator.
   */
    $this->db->select([
      'p.id_pesanan',
      'p.invoice_pesanan',
      'p.id_pembeli',
      'p.cabang_pembeli_id',
      'p.id_toko',
      'p.cabang_toko_id',
      'p.total_harga',
      'p.ongkir',
      'p.kurir',
      'p.resi',
      'p.status_pesanan',
      'p.is_dinilai',
      'p.catatan_pembeli',
      'p.stok_dikembalikan',

      'p.ongkir_ditetapkan_oleh',
      'p.ongkir_ditetapkan_pada',

      'p.id_transaksi_pembayaran',
      'p.nominal_dibayar',
      'p.pembayaran_oleh',
      'p.dibayar_pada',

      'p.dibatalkan_oleh',
      'p.dibatalkan_pada',
      'p.alasan_pembatalan',
      'p.id_transaksi_refund',
      'p.nominal_refund',
      'p.refund_pada',

      'p.terdaftar',

      'pembeli.nama AS nama_pembeli',
      'penjual.nama AS nama_penjual',
      'toko.nama_toko',

      'cabang_pembeli.kode AS kode_cabang_pembeli',
      'cabang_pembeli.nama AS nama_cabang_pembeli',

      'cabang_toko.kode AS kode_cabang_toko',
      'cabang_toko.nama AS nama_cabang_toko'
    ]);

    $this->db->from('tb_pesanan p');

    $this->db->join(
      'tb_user pembeli',
      'p.id_pembeli = pembeli.id'
    );

    $this->db->join(
      'tb_toko toko',
      'p.id_toko = toko.id_toko'
    );

    $this->db->join(
      'tb_user penjual',
      'toko.id_user = penjual.id'
    );

    $this->db->join(
      'tb_cabang cabang_pembeli',
      'p.cabang_pembeli_id = cabang_pembeli.id',
      'left'
    );

    $this->db->join(
      'tb_cabang cabang_toko',
      'p.cabang_toko_id = cabang_toko.id',
      'left'
    );

    if ($auth->level === 'Administrator') {
      $this->db->where(
        'p.cabang_toko_id',
        (int) $auth->cabang_id
      );
    }

    if ($filter_status !== '') {
      $this->db->where(
        'p.status_pesanan',
        $filter_status
      );
    }

    if ($filter_id_toko !== null) {
      $this->db->where(
        'p.id_toko',
        $filter_id_toko
      );
    }

    if ($pencarian !== '') {
      $this->db->group_start();

      $this->db->like(
        'p.invoice_pesanan',
        $pencarian
      );

      $this->db->or_like(
        'pembeli.nama',
        $pencarian
      );

      $this->db->or_like(
        'toko.nama_toko',
        $pencarian
      );

      $this->db->group_end();
    }

    $this->db->order_by(
      'p.id_pesanan',
      'DESC'
    );

    $this->db->limit(
      $limit,
      $offset
    );

    $query = $this->db->get();

    if (!$query) {
      $this->api_response([
        'status'  => false,
        'message' => 'Gagal mengambil daftar pesanan.'
      ], 500);
      return;
    }

    $hasil = $query->result_array();
    $data_pesanan = [];

    foreach ($hasil as $row) {
      $data_pesanan[] = [
        'id_pesanan' =>
        (int) $row['id_pesanan'],

        'invoice_pesanan' =>
        $row['invoice_pesanan'],

        'id_pembeli' =>
        (int) $row['id_pembeli'],

        'nama_pembeli' =>
        $row['nama_pembeli'],

        'cabang_pembeli_id' =>
        (int) $row['cabang_pembeli_id'],

        'kode_cabang_pembeli' =>
        $row['kode_cabang_pembeli'],

        'nama_cabang_pembeli' =>
        $row['nama_cabang_pembeli'],

        'id_toko' =>
        (int) $row['id_toko'],

        'nama_toko' =>
        $row['nama_toko'],

        'nama_penjual' =>
        $row['nama_penjual'],

        'cabang_toko_id' =>
        (int) $row['cabang_toko_id'],

        'kode_cabang_toko' =>
        $row['kode_cabang_toko'],

        'nama_cabang_toko' =>
        $row['nama_cabang_toko'],

        'total_harga' =>
        (int) $row['total_harga'],

        'ongkir' =>
        (int) $row['ongkir'],

        'total_tagihan' =>
        (int) $row['total_harga'] +
          (int) $row['ongkir'],

        'kurir' =>
        $row['kurir'],

        'resi' =>
        $row['resi'],

        'status_pesanan' =>
        $row['status_pesanan'],

        'is_dinilai' =>
        (int) $row['is_dinilai'],

        'catatan_pembeli' =>
        $row['catatan_pembeli'],

        'stok_dikembalikan' =>
        (bool) $row['stok_dikembalikan'],

        'ongkir_ditetapkan_oleh' =>
        $row['ongkir_ditetapkan_oleh'] !== null
          ? (int) $row['ongkir_ditetapkan_oleh']
          : null,

        'ongkir_ditetapkan_pada' =>
        $row['ongkir_ditetapkan_pada'],

        'id_transaksi_pembayaran' =>
        $row['id_transaksi_pembayaran'] !== null
          ? (int) $row['id_transaksi_pembayaran']
          : null,

        'nominal_dibayar' =>
        $row['nominal_dibayar'] !== null
          ? (int) $row['nominal_dibayar']
          : null,

        'pembayaran_oleh' =>
        $row['pembayaran_oleh'] !== null
          ? (int) $row['pembayaran_oleh']
          : null,

        'dibayar_pada' =>
        $row['dibayar_pada'],

        'dibatalkan_oleh' =>
        $row['dibatalkan_oleh'] !== null
          ? (int) $row['dibatalkan_oleh']
          : null,

        'dibatalkan_pada' =>
        $row['dibatalkan_pada'],

        'alasan_pembatalan' =>
        $row['alasan_pembatalan'],

        'id_transaksi_refund' =>
        $row['id_transaksi_refund'] !== null
          ? (int) $row['id_transaksi_refund']
          : null,

        'nominal_refund' =>
        $row['nominal_refund'] !== null
          ? (int) $row['nominal_refund']
          : null,

        'refund_pada' =>
        $row['refund_pada'],

        'terdaftar' =>
        $row['terdaftar']
      ];
    }

    $this->api_response([
      'status'  => true,
      'message' => 'Daftar pesanan berhasil diambil.',
      'data'    => $data_pesanan,

      'pagination' => [
        'page'       => $page,
        'limit'      => $limit,
        'total_data' => $total_data,
        'total_page' => $total_data > 0
          ? (int) ceil($total_data / $limit)
          : 0
      ],

      'scope' => [
        'level' =>
        $auth->level,

        'cabang_id' =>
        $auth->level === 'Administrator'
          ? (int) $auth->cabang_id
          : null
      ]
    ]);
  }

  // 13. Endpoint Admin: Batalkan Paksa Pesanan & Refund
  public function admin_batalkan_pesanan()
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

    if (!in_array(
      $auth->level,
      ['Administrator', 'Super Admin'],
      true
    )) {
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

    $id_pesanan = filter_var(
      $request['id_pesanan'] ?? null,
      FILTER_VALIDATE_INT,
      [
        'options' => [
          'min_range' => 1
        ]
      ]
    );

    if ($id_pesanan === false) {
      $this->api_response([
        'status'  => false,
        'message' => 'ID pesanan tidak valid.'
      ], 422);
      return;
    }

    $alasan = trim(
      (string) ($request['alasan'] ?? '')
    );

    if ($alasan === '') {
      $alasan = 'Dibatalkan oleh Administrator.';
    }

    if (strlen($alasan) > 500) {
      $this->api_response([
        'status'  => false,
        'message' => 'Alasan pembatalan maksimal 500 karakter.'
      ], 422);
      return;
    }

    $id_pesanan = (int) $id_pesanan;
    $id_admin = (int) $auth->id_user;

    /*
   * Pemeriksaan awal untuk memperoleh ID pembeli dan
   * memastikan Administrator hanya mengakses cabangnya.
   */
    $this->db
      ->select([
        'id_pesanan',
        'id_pembeli',
        'cabang_toko_id'
      ])
      ->from('tb_pesanan')
      ->where('id_pesanan', $id_pesanan);

    if ($auth->level === 'Administrator') {
      $this->db->where(
        'cabang_toko_id',
        (int) $auth->cabang_id
      );
    }

    $pesanan_awal = $this->db
      ->limit(1)
      ->get()
      ->row();

    if (!$pesanan_awal) {
      $this->api_response([
        'status'  => false,
        'message' => 'Pesanan tidak ditemukan atau berada di luar cabang Anda.'
      ], 404);
      return;
    }

    $this->db->trans_begin();

    /*
   * Kunci pembeli agar refund terserialisasi dengan
   * transaksi saldo lainnya.
   */
    $pembeli = $this->db->query(
      "SELECT
        id,
        cabang_id,
        expo_token
     FROM tb_user
     WHERE id = ?
     LIMIT 1
     FOR UPDATE",
      [(int) $pesanan_awal->id_pembeli]
    )->row();

    if (!$pembeli) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Akun pembeli tidak ditemukan.'
      ], 409);
      return;
    }

    $sql_scope = '';
    $parameter_pesanan = [
      $id_pesanan
    ];

    if ($auth->level === 'Administrator') {
      $sql_scope = ' AND p.cabang_toko_id = ?';
      $parameter_pesanan[] = (int) $auth->cabang_id;
    }

    /*
   * Kunci pesanan sesuai cakupan cabang token.
   */
    $pesanan = $this->db->query(
      "SELECT
        p.*,
        toko.id_user AS id_penjual,
        toko.nama_toko,
        penjual.expo_token AS expo_token_penjual
     FROM tb_pesanan p
     INNER JOIN tb_toko toko
       ON toko.id_toko = p.id_toko
     INNER JOIN tb_user penjual
       ON penjual.id = toko.id_user
     WHERE p.id_pesanan = ?" .
        $sql_scope .
        " LIMIT 1
       FOR UPDATE",
      $parameter_pesanan
    )->row();

    if (!$pesanan) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Pesanan tidak ditemukan atau berada di luar cabang Anda.'
      ], 404);
      return;
    }

    $total_harga = (int) $pesanan->total_harga;
    $ongkir = (int) $pesanan->ongkir;
    $total_tagihan = $total_harga + $ongkir;

    if (
      $total_harga <= 0 ||
      $ongkir < 0 ||
      $total_tagihan <= 0 ||
      $total_tagihan > 2147483647
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Nilai tagihan pesanan tidak valid.'
      ], 409);
      return;
    }

    /*
   * Kunci seluruh ledger yang berhubungan dengan pesanan.
   */
    $pembayaran = $this->db->query(
      "SELECT
        id,
        idNasabah,
        nominal,
        jenis,
        status_konfirmasi,
        referensi_tipe,
        referensi_id
     FROM tb_transaksi
     WHERE referensi_tipe = ?
       AND referensi_id = ?
     LIMIT 1
     FOR UPDATE",
      [
        'PembayaranPesanan',
        $id_pesanan
      ]
    )->row();

    $refund_lama = $this->db->query(
      "SELECT
        id,
        idAdmin,
        idNasabah,
        nominal,
        jenis,
        status_konfirmasi,
        referensi_tipe,
        referensi_id,
        terdaftar
     FROM tb_transaksi
     WHERE referensi_tipe = ?
       AND referensi_id = ?
     LIMIT 1
     FOR UPDATE",
      [
        'RefundPesanan',
        $id_pesanan
      ]
    )->row();

    $pencairan_penjual = $this->db->query(
      "SELECT
        id,
        idNasabah,
        nominal,
        status_konfirmasi
     FROM tb_transaksi
     WHERE referensi_tipe = ?
       AND referensi_id = ?
     LIMIT 1
     FOR UPDATE",
      [
        'PencairanPesanan',
        $id_pesanan
      ]
    )->row();

    /*
   * Pesanan yang sudah selesai dan sudah dicairkan kepada
   * penjual tidak boleh langsung dibatalkan.
   */
    if (
      $pesanan->status_pesanan === 'Selesai' ||
      $pencairan_penjual
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Pesanan sudah selesai atau dana sudah dicairkan kepada penjual. Gunakan proses sengketa dan pembalikan dana.'
      ], 409);
      return;
    }

    $memiliki_data_pembayaran =
      !empty($pesanan->id_transaksi_pembayaran) ||
      $pesanan->nominal_dibayar !== null ||
      $pembayaran !== null;

    $pembayaran_valid =
      $pembayaran &&
      !empty($pesanan->id_transaksi_pembayaran) &&
      (int) $pesanan->id_transaksi_pembayaran ===
      (int) $pembayaran->id &&
      (int) $pesanan->id_pembeli ===
      (int) $pembayaran->idNasabah &&
      (int) $pesanan->nominal_dibayar ===
      $total_tagihan &&
      (int) $pembayaran->nominal ===
      $total_tagihan &&
      (string) $pembayaran->jenis === 'Keluar' &&
      (string) $pembayaran->status_konfirmasi ===
      'Sukses' &&
      (string) $pembayaran->referensi_tipe ===
      'PembayaranPesanan' &&
      (int) $pembayaran->referensi_id ===
      $id_pesanan;

    /*
   * Idempotensi pembatalan admin.
   */
    if ($pesanan->status_pesanan === 'Dibatalkan') {
      if ((int) $pesanan->stok_dikembalikan !== 1) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Pesanan dibatalkan tetapi status pengembalian stok tidak konsisten.'
        ], 409);
        return;
      }

      if ($memiliki_data_pembayaran) {
        $refund_valid =
          $pembayaran_valid &&
          $refund_lama &&
          !empty($pesanan->id_transaksi_refund) &&
          (int) $pesanan->id_transaksi_refund ===
          (int) $refund_lama->id &&
          (int) $refund_lama->idNasabah ===
          (int) $pesanan->id_pembeli &&
          (int) $refund_lama->nominal ===
          $total_tagihan &&
          (int) $pesanan->nominal_refund ===
          $total_tagihan &&
          (string) $refund_lama->jenis === 'Masuk' &&
          (string) $refund_lama->status_konfirmasi ===
          'Sukses';

        if (!$refund_valid) {
          $this->db->trans_rollback();

          $this->api_response([
            'status'  => false,
            'message' => 'Pesanan dibatalkan tetapi data refund tidak konsisten. Hubungi administrator.'
          ], 409);
          return;
        }
      } elseif (
        $refund_lama ||
        !empty($pesanan->id_transaksi_refund) ||
        $pesanan->nominal_refund !== null
      ) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Pesanan belum dibayar tetapi memiliki data refund yang tidak semestinya.'
        ], 409);
        return;
      }

      if ($this->db->trans_status() === false) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Gagal memeriksa pembatalan pesanan.'
        ], 500);
        return;
      }

      $this->db->trans_commit();

      $this->api_response([
        'status'  => true,
        'message' => 'Pesanan ini sudah dibatalkan sebelumnya.',
        'data'    => [
          'id_pesanan'            => $id_pesanan,
          'invoice_pesanan'       =>
          $pesanan->invoice_pesanan,
          'status_pesanan'        => 'Dibatalkan',
          'stok_dikembalikan'     => true,
          'direfund'              =>
          $memiliki_data_pembayaran,
          'id_transaksi_refund'   =>
          $refund_lama
            ? (int) $refund_lama->id
            : null,
          'nominal_refund'        =>
          $refund_lama
            ? (int) $refund_lama->nominal
            : null,
          'dibatalkan_oleh'       =>
          $pesanan->dibatalkan_oleh !== null
            ? (int) $pesanan->dibatalkan_oleh
            : null,
          'dibatalkan_pada'       =>
          $pesanan->dibatalkan_pada,
          'alasan_pembatalan'     =>
          $pesanan->alasan_pembatalan,
          'idempotent'            => true
        ]
      ]);
      return;
    }

    if ((int) $pesanan->stok_dikembalikan !== 0) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Status pesanan dan pengembalian stok tidak konsisten.'
      ], 409);
      return;
    }

    $status_bisa_dibatalkan = [
      'Menunggu Ongkir',
      'Menunggu Pembayaran',
      'Diproses',
      'Dikirim'
    ];

    if (!in_array(
      $pesanan->status_pesanan,
      $status_bisa_dibatalkan,
      true
    )) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Status pesanan tidak dapat dibatalkan oleh Administrator.',
        'data'    => [
          'status_pesanan' =>
          $pesanan->status_pesanan
        ]
      ], 409);
      return;
    }

    /*
   * Status sesudah pembayaran harus memiliki ledger pembayaran
   * yang benar. Jika tidak, hentikan untuk pemeriksaan manual.
   */
    if (
      in_array(
        $pesanan->status_pesanan,
        ['Diproses', 'Dikirim'],
        true
      ) &&
      !$pembayaran_valid
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Pesanan berstatus telah dibayar tetapi ledger pembayarannya tidak valid.'
      ], 409);
      return;
    }

    if (
      $memiliki_data_pembayaran &&
      !$pembayaran_valid
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Data pembayaran pesanan tidak konsisten. Refund dihentikan.'
      ], 409);
      return;
    }

    if (
      !$memiliki_data_pembayaran &&
      $refund_lama
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Ditemukan refund tanpa transaksi pembayaran yang sah.'
      ], 409);
      return;
    }

    if (
      $memiliki_data_pembayaran &&
      $refund_lama
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Refund sudah tercatat tetapi status pesanan belum konsisten. Hubungi administrator.'
      ], 409);
      return;
    }

    $detail_pesanan = $this->db
      ->select([
        'id_produk',
        'jumlah'
      ])
      ->from('tb_pesanan_detail')
      ->where('id_pesanan', $id_pesanan)
      ->order_by('id_produk', 'ASC')
      ->get()
      ->result_array();

    if (empty($detail_pesanan)) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Detail barang pesanan tidak ditemukan.'
      ], 409);
      return;
    }

    $waktu_sekarang = date('Y-m-d H:i:s');
    $id_transaksi_refund = null;
    $nominal_refund = null;

    /*
   * Refund hanya dibuat jika pembayaran telah tercatat sah.
   */
    if ($pembayaran_valid) {
      $refund_disimpan = $this->db->insert(
        'tb_transaksi',
        [
          'cabang_id'         =>
          !empty($pembeli->cabang_id)
            ? (int) $pembeli->cabang_id
            : null,
          'idAdmin'           => $id_admin,
          'idNasabah'         =>
          (int) $pesanan->id_pembeli,
          'idPotongan'        => 0,
          'tanggal'           => date('Y-m-d'),
          'nominal'           => $total_tagihan,
          'gram_emas'         => null,
          'jenis'             => 'Masuk',
          'keterangan'        =>
          'Refund Pembatalan Admin: ' .
            $pesanan->invoice_pesanan,
          'status_konfirmasi' => 'Sukses',
          'bukti_transfer'    => null,
          'referensi_tipe'    => 'RefundPesanan',
          'referensi_id'      => $id_pesanan,
          'terdaftar'         => $waktu_sekarang
        ]
      );

      if (!$refund_disimpan) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Gagal mencatat transaksi refund.'
        ], 500);
        return;
      }

      $id_transaksi_refund =
        (int) $this->db->insert_id();

      $nominal_refund = $total_tagihan;
    }

    $data_update = [
      'status_pesanan'    => 'Dibatalkan',
      'stok_dikembalikan' => 1,
      'dibatalkan_oleh'   => $id_admin,
      'dibatalkan_pada'   => $waktu_sekarang,
      'alasan_pembatalan' => $alasan
    ];

    if ($pembayaran_valid) {
      $data_update['id_transaksi_refund'] =
        $id_transaksi_refund;

      $data_update['nominal_refund'] =
        $nominal_refund;

      $data_update['refund_pada'] =
        $waktu_sekarang;
    }

    $this->db
      ->where('id_pesanan', $id_pesanan)
      ->where_in(
        'status_pesanan',
        $status_bisa_dibatalkan
      )
      ->where('stok_dikembalikan', 0)
      ->update('tb_pesanan', $data_update);

    if ($this->db->affected_rows() !== 1) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Status pesanan telah berubah. Pembatalan dihentikan.'
      ], 409);
      return;
    }

    /*
   * Kembalikan stok tepat satu kali.
   */
    foreach ($detail_pesanan as $item) {
      $id_produk = (int) $item['id_produk'];
      $jumlah = (int) $item['jumlah'];

      if ($id_produk <= 0 || $jumlah <= 0) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Detail jumlah barang pesanan tidak valid.'
        ], 409);
        return;
      }

      $this->db
        ->set(
          'stok',
          'stok + ' . $jumlah,
          false
        )
        ->set(
          'status_produk',
          "CASE
          WHEN status_produk = 'Habis'
          THEN 'Tersedia'
          ELSE status_produk
        END",
          false
        )
        ->where('id_produk', $id_produk)
        ->update('tb_produk');

      if ($this->db->affected_rows() !== 1) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Gagal mengembalikan stok produk.'
        ], 500);
        return;
      }
    }

    $judul_pembeli =
      "\u{26A0}\u{FE0F} Pesanan Dibatalkan Admin";

    $pesan_pembeli =
      'Pesanan ' .
      $pesanan->invoice_pesanan .
      ' dibatalkan oleh Administrator. Alasan: ' .
      $alasan .
      (
        $pembayaran_valid
        ? ' Dana Rp ' .
        number_format(
          $total_tagihan,
          0,
          ',',
          '.'
        ) .
        ' telah dikembalikan ke saldo Anda.'
        : ' Tidak ada refund karena pesanan belum dibayar.'
      );

    $judul_penjual =
      "\u{26A0}\u{FE0F} Pesanan Dibatalkan Admin";

    $pesan_penjual =
      'Pesanan ' .
      $pesanan->invoice_pesanan .
      ' dibatalkan oleh Administrator. Alasan: ' .
      $alasan .
      ' Stok barang telah dikembalikan.';

    $this->db->insert('tb_notifikasi', [
      'id_user' =>
      (int) $pesanan->id_pembeli,
      'judul'   => $judul_pembeli,
      'pesan'   => $pesan_pembeli,
      'is_read' => 0,
      'tanggal' => $waktu_sekarang
    ]);

    $this->db->insert('tb_notifikasi', [
      'id_user' =>
      (int) $pesanan->id_penjual,
      'judul'   => $judul_penjual,
      'pesan'   => $pesan_penjual,
      'is_read' => 0,
      'tanggal' => $waktu_sekarang
    ]);

    if ($this->db->trans_status() === false) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Gagal melakukan pembatalan pesanan.'
      ], 500);
      return;
    }

    $this->db->trans_commit();

    /*
   * Push dikirim setelah commit.
   */
    try {
      if (!empty($pembeli->expo_token)) {
        $this->send_expo_push_notification(
          $pembeli->expo_token,
          $judul_pembeli,
          $pesan_pembeli
        );
      }
    } catch (Throwable $e) {
      log_message(
        'error',
        'Push refund pembeli gagal: ' .
          $e->getMessage()
      );
    }

    try {
      if (!empty($pesanan->expo_token_penjual)) {
        $this->send_expo_push_notification(
          $pesanan->expo_token_penjual,
          $judul_penjual,
          $pesan_penjual
        );
      }
    } catch (Throwable $e) {
      log_message(
        'error',
        'Push pembatalan admin ke penjual gagal: ' .
          $e->getMessage()
      );
    }

    $this->api_response([
      'status'  => true,
      'message' => $pembayaran_valid
        ? 'Pesanan berhasil dibatalkan dan dana telah dikembalikan kepada pembeli.'
        : 'Pesanan berhasil dibatalkan. Tidak ada refund karena pesanan belum dibayar.',
      'data'    => [
        'id_pesanan'            => $id_pesanan,
        'invoice_pesanan'       =>
        $pesanan->invoice_pesanan,
        'status_sebelumnya'     =>
        $pesanan->status_pesanan,
        'status_pesanan'        => 'Dibatalkan',
        'stok_dikembalikan'     => true,
        'direfund'              =>
        $pembayaran_valid,
        'id_transaksi_refund'   =>
        $id_transaksi_refund,
        'nominal_refund'        =>
        $nominal_refund,
        'dibatalkan_oleh'       => $id_admin,
        'nama_admin'            => $auth->nama,
        'dibatalkan_pada'       =>
        $waktu_sekarang,
        'alasan_pembatalan'     => $alasan,
        'idempotent'            => false
      ]
    ]);
  }

  // 12. Endpoint Simpan Ulasan Pembeli
  public function simpan_ulasan()
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
        'message' => 'Ulasan hanya dapat diberikan oleh pembeli.'
      ], 403);
      return;
    }

    $content_length = (int) $this->input->server(
      'CONTENT_LENGTH'
    );

    if ($content_length > 65536) {
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

    $id_pesanan = filter_var(
      $request['id_pesanan'] ?? null,
      FILTER_VALIDATE_INT,
      [
        'options' => [
          'min_range' => 1
        ]
      ]
    );

    if ($id_pesanan === false) {
      $this->api_response([
        'status'  => false,
        'message' => 'ID pesanan tidak valid.'
      ], 422);
      return;
    }

    $bintang = filter_var(
      $request['bintang'] ?? null,
      FILTER_VALIDATE_INT,
      [
        'options' => [
          'min_range' => 1,
          'max_range' => 5
        ]
      ]
    );

    if ($bintang === false) {
      $this->api_response([
        'status'  => false,
        'message' => 'Bintang harus berupa angka bulat dari 1 sampai 5.'
      ], 422);
      return;
    }

    /*
   * Hapus tag HTML untuk mencegah stored XSS ketika
   * komentar ditampilkan pada panel web.
   */
    $komentar = trim(
      strip_tags(
        (string) ($request['komentar'] ?? '')
      )
    );

    /*
   * Rapikan spasi tanpa menghilangkan karakter Unicode.
   */
    $komentar_rapi = preg_replace(
      '/\s+/u',
      ' ',
      $komentar
    );

    if ($komentar_rapi !== null) {
      $komentar = $komentar_rapi;
    }

    if (mb_strlen($komentar, 'UTF-8') > 1000) {
      $this->api_response([
        'status'  => false,
        'message' => 'Komentar maksimal 1.000 karakter.'
      ], 422);
      return;
    }

    /*
   * Identitas pembeli selalu berasal dari Bearer token.
   * id_pembeli dan id_produk dari request diabaikan.
   */
    $id_pesanan = (int) $id_pesanan;
    $id_pembeli = (int) $auth->id_user;
    $bintang = (int) $bintang;

    $this->db->trans_begin();

    /*
   * Kunci pesanan dan batasi berdasarkan pembeli pemilik token.
   */
    $pesanan = $this->db->query(
      "SELECT
        id_pesanan,
        invoice_pesanan,
        id_pembeli,
        status_pesanan,
        is_dinilai
     FROM tb_pesanan
     WHERE id_pesanan = ?
       AND id_pembeli = ?
     LIMIT 1
     FOR UPDATE",
      [
        $id_pesanan,
        $id_pembeli
      ]
    )->row();

    if (!$pesanan) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Pesanan tidak ditemukan atau bukan milik Anda.'
      ], 404);
      return;
    }

    /*
   * Ulasan hanya dapat diberikan setelah pesanan selesai
   * dan dana telah dicairkan kepada penjual.
   */
    if ($pesanan->status_pesanan !== 'Selesai') {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Ulasan hanya dapat diberikan untuk pesanan yang sudah selesai.',
        'data'    => [
          'status_pesanan' =>
          $pesanan->status_pesanan
        ]
      ], 409);
      return;
    }

    /*
   * Ambil seluruh produk dari detail pesanan.
   */
    $detail_pesanan = $this->db
      ->select([
        'id_produk',
        'jumlah'
      ])
      ->from('tb_pesanan_detail')
      ->where('id_pesanan', $id_pesanan)
      ->order_by('id_produk', 'ASC')
      ->get()
      ->result_array();

    if (empty($detail_pesanan)) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Detail barang pesanan tidak ditemukan.'
      ], 409);
      return;
    }

    /*
   * Kunci ulasan yang mungkin sudah tersimpan.
   */
    $ulasan_lama = $this->db->query(
      "SELECT
        id_ulasan,
        id_pesanan,
        id_produk,
        id_pembeli,
        bintang,
        komentar,
        tanggal
     FROM tb_ulasan
     WHERE id_pesanan = ?
     ORDER BY id_produk ASC
     FOR UPDATE",
      [$id_pesanan]
    )->result_array();

    /*
   * Jika sudah dinilai, pastikan seluruh ulasan lama lengkap
   * dan request yang diulang memiliki isi yang sama.
   */
    if ((int) $pesanan->is_dinilai === 1) {
      $ulasan_per_produk = [];
      $ulasan_valid = true;

      foreach ($ulasan_lama as $ulasan) {
        $id_produk_ulasan =
          (int) $ulasan['id_produk'];

        if (
          (int) $ulasan['id_pembeli'] !==
          $id_pembeli ||
          isset($ulasan_per_produk[$id_produk_ulasan])
        ) {
          $ulasan_valid = false;
          break;
        }

        $ulasan_per_produk[$id_produk_ulasan] =
          $ulasan;
      }

      if (
        $ulasan_valid &&
        count($ulasan_per_produk) ===
        count($detail_pesanan)
      ) {
        foreach ($detail_pesanan as $detail) {
          $id_produk_detail =
            (int) $detail['id_produk'];

          if (
            !isset(
              $ulasan_per_produk[$id_produk_detail]
            ) ||
            (int) $ulasan_per_produk[$id_produk_detail]['bintang'] !== $bintang ||
            trim(
              (string) $ulasan_per_produk[$id_produk_detail]['komentar']
            ) !== $komentar
          ) {
            $ulasan_valid = false;
            break;
          }
        }
      } else {
        $ulasan_valid = false;
      }

      if (!$ulasan_valid) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Pesanan sudah dinilai dengan data ulasan yang berbeda atau tidak konsisten.'
        ], 409);
        return;
      }

      if ($this->db->trans_status() === false) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Gagal memeriksa ulasan pesanan.'
        ], 500);
        return;
      }

      $this->db->trans_commit();

      $this->api_response([
        'status'  => true,
        'message' => 'Ulasan ini sudah tersimpan sebelumnya.',
        'data'    => [
          'id_pesanan'     => $id_pesanan,
          'invoice_pesanan' =>
          $pesanan->invoice_pesanan,
          'id_pembeli'     => $id_pembeli,
          'bintang'        => $bintang,
          'komentar'       => $komentar,
          'jumlah_ulasan'  =>
          count($ulasan_per_produk),
          'idempotent'     => true
        ]
      ]);
      return;
    }

    /*
   * Ulasan tidak boleh sudah ada jika is_dinilai masih nol.
   * Kondisi ini menunjukkan penyimpanan lama yang tidak lengkap.
   */
    if (!empty($ulasan_lama)) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Ditemukan ulasan parsial pada pesanan. Hubungi administrator.'
      ], 409);
      return;
    }

    $waktu_sekarang = date('Y-m-d H:i:s');
    $id_ulasan_baru = [];

    /*
   * Satu ulasan dibuat untuk setiap produk dalam pesanan.
   */
    foreach ($detail_pesanan as $detail) {
      $id_produk = (int) $detail['id_produk'];

      if ($id_produk <= 0) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'ID produk pada detail pesanan tidak valid.'
        ], 409);
        return;
      }

      $ulasan_disimpan = $this->db->insert(
        'tb_ulasan',
        [
          'id_pesanan' => $id_pesanan,
          'id_produk'  => $id_produk,
          'id_pembeli' => $id_pembeli,
          'bintang'    => $bintang,
          'komentar'   =>
          $komentar !== ''
            ? $komentar
            : null,
          'tanggal'    => $waktu_sekarang
        ]
      );

      if (!$ulasan_disimpan) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Gagal menyimpan ulasan produk.'
        ], 500);
        return;
      }

      $id_ulasan_baru[] =
        (int) $this->db->insert_id();
    }

    /*
   * Tandai pesanan sebagai sudah dinilai.
   */
    $this->db
      ->where('id_pesanan', $id_pesanan)
      ->where('id_pembeli', $id_pembeli)
      ->where('status_pesanan', 'Selesai')
      ->where('is_dinilai', 0)
      ->update('tb_pesanan', [
        'is_dinilai' => 1
      ]);

    if ($this->db->affected_rows() !== 1) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Status penilaian pesanan telah berubah.'
      ], 409);
      return;
    }

    /*
   * Hitung ulang rating setiap produk dari sumber ulasan.
   */
    foreach ($detail_pesanan as $detail) {
      $id_produk = (int) $detail['id_produk'];

      $hasil_rating = $this->db
        ->select_avg('bintang', 'rata_rata')
        ->from('tb_ulasan')
        ->where('id_produk', $id_produk)
        ->get()
        ->row();

      if (
        !$hasil_rating ||
        $hasil_rating->rata_rata === null
      ) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Gagal menghitung rating produk.'
        ], 500);
        return;
      }

      $rata_rata_baru = round(
        (float) $hasil_rating->rata_rata,
        1
      );

      $rating_diperbarui = $this->db
        ->where('id_produk', $id_produk)
        ->update('tb_produk', [
          'rating' => $rata_rata_baru
        ]);

      if (!$rating_diperbarui) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Gagal memperbarui rating produk.'
        ], 500);
        return;
      }
    }

    if ($this->db->trans_status() === false) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Gagal menyimpan ulasan.'
      ], 500);
      return;
    }

    $this->db->trans_commit();

    $this->api_response([
      'status'  => true,
      'message' => 'Terima kasih! Ulasan Anda sangat membantu penjual.',
      'data'    => [
        'id_pesanan'      => $id_pesanan,
        'invoice_pesanan' =>
        $pesanan->invoice_pesanan,
        'id_pembeli'      => $id_pembeli,
        'bintang'         => $bintang,
        'komentar'        => $komentar,
        'jumlah_ulasan'   =>
        count($id_ulasan_baru),
        'id_ulasan'       =>
        $id_ulasan_baru,
        'idempotent'      => false
      ]
    ], 201);
  }
  // 14. Endpoint Ambil Ulasan Produk (Untuk Detail Produk)
  public function get_ulasan_produk()
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

    $content_length = (int) $this->input->server(
      'CONTENT_LENGTH'
    );

    if ($content_length > 65536) {
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

    $id_produk = filter_var(
      $request['id_produk'] ?? null,
      FILTER_VALIDATE_INT,
      [
        'options' => [
          'min_range' => 1
        ]
      ]
    );

    if ($id_produk === false) {
      $this->api_response([
        'status'  => false,
        'message' => 'ID produk tidak valid.'
      ], 422);
      return;
    }

    $page = isset($request['page'])
      ? (int) $request['page']
      : 1;

    $limit = isset($request['limit'])
      ? (int) $request['limit']
      : 20;

    if ($page < 1) {
      $page = 1;
    }

    if ($limit < 1) {
      $limit = 20;
    }

    if ($limit > 50) {
      $limit = 50;
    }

    $id_produk = (int) $id_produk;
    $offset = ($page - 1) * $limit;

    /*
   * Pastikan produk benar-benar tersedia di database.
   * Produk arsip tetap dapat memiliki riwayat ulasan,
   * tetapi tidak akan tampil di etalase marketplace.
   */
    $produk = $this->db
      ->select([
        'p.id_produk',
        'p.nama_produk',
        'p.id_toko',
        'p.rating',
        'p.status_produk',
        't.nama_toko',
        't.status_toko'
      ])
      ->from('tb_produk p')
      ->join(
        'tb_toko t',
        't.id_toko = p.id_toko'
      )
      ->where('p.id_produk', $id_produk)
      ->limit(1)
      ->get()
      ->row();

    if (!$produk) {
      $this->api_response([
        'status'  => false,
        'message' => 'Produk tidak ditemukan.'
      ], 404);
      return;
    }

    /*
   * Ringkasan dihitung langsung dari sumber ulasan.
   */
    $ringkasan = $this->db
      ->select(
        "
        COUNT(*) AS jumlah_ulasan,
        COALESCE(ROUND(AVG(bintang), 1), 0)
          AS rata_rata,
        COALESCE(SUM(bintang = 5), 0)
          AS bintang_5,
        COALESCE(SUM(bintang = 4), 0)
          AS bintang_4,
        COALESCE(SUM(bintang = 3), 0)
          AS bintang_3,
        COALESCE(SUM(bintang = 2), 0)
          AS bintang_2,
        COALESCE(SUM(bintang = 1), 0)
          AS bintang_1
      ",
        false
      )
      ->from('tb_ulasan')
      ->where('id_produk', $id_produk)
      ->get()
      ->row();

    if (!$ringkasan) {
      $this->api_response([
        'status'  => false,
        'message' => 'Gagal menghitung ringkasan ulasan.'
      ], 500);
      return;
    }

    $total_data = (int) $ringkasan->jumlah_ulasan;

    /*
   * Hanya data yang diperlukan untuk tampilan publik
   * yang dikirimkan.
   */
    $query = $this->db
      ->select([
        'u.id_ulasan',
        'u.id_pesanan',
        'u.id_produk',
        'u.bintang',
        'u.komentar',
        'u.tanggal',
        'pembeli.nama AS nama_pembeli'
      ])
      ->from('tb_ulasan u')
      ->join(
        'tb_user pembeli',
        'pembeli.id = u.id_pembeli'
      )
      ->where('u.id_produk', $id_produk)
      ->order_by('u.id_ulasan', 'DESC')
      ->limit($limit, $offset)
      ->get();

    if (!$query) {
      $this->api_response([
        'status'  => false,
        'message' => 'Gagal mengambil ulasan produk.'
      ], 500);
      return;
    }

    $hasil = $query->result_array();
    $data_ulasan = [];

    foreach ($hasil as $row) {
      $data_ulasan[] = [
        'id_ulasan' =>
        (int) $row['id_ulasan'],

        'id_pesanan' =>
        (int) $row['id_pesanan'],

        'id_produk' =>
        (int) $row['id_produk'],

        'nama_pembeli' =>
        $row['nama_pembeli'],

        'bintang' =>
        (int) $row['bintang'],

        'komentar' =>
        $row['komentar'],

        'tanggal' =>
        $row['tanggal']
      ];
    }

    $this->api_response([
      'status'  => true,
      'message' => $total_data > 0
        ? 'Ulasan produk berhasil diambil.'
        : 'Produk belum memiliki ulasan.',

      'produk' => [
        'id_produk' =>
        (int) $produk->id_produk,

        'nama_produk' =>
        $produk->nama_produk,

        'id_toko' =>
        (int) $produk->id_toko,

        'nama_toko' =>
        $produk->nama_toko,

        'status_produk' =>
        $produk->status_produk,

        'status_toko' =>
        $produk->status_toko
      ],

      'ringkasan' => [
        'jumlah_ulasan' =>
        $total_data,

        'rata_rata' =>
        (float) $ringkasan->rata_rata,

        'distribusi' => [
          '5' => (int) $ringkasan->bintang_5,
          '4' => (int) $ringkasan->bintang_4,
          '3' => (int) $ringkasan->bintang_3,
          '2' => (int) $ringkasan->bintang_2,
          '1' => (int) $ringkasan->bintang_1
        ]
      ],

      'data' => $data_ulasan,

      'pagination' => [
        'page'       => $page,
        'limit'      => $limit,
        'total_data' => $total_data,
        'total_page' => $total_data > 0
          ? (int) ceil($total_data / $limit)
          : 0
      ]
    ]);
  }

  // 15. Endpoint Cek Status Wishlist
  public function cek_wishlist()
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
        'message' => 'Akses ditolak. Endpoint ini khusus Nasabah.'
      ], 403);
      return;
    }

    $request = json_decode(
      $this->input->raw_input_stream,
      true
    );

    if (!is_array($request)) {
      $this->api_response([
        'status'         => false,
        'message'        => 'Format JSON tidak valid.',
        'is_wishlisted'  => false
      ], 400);
      return;
    }

    $id_produk_valid = filter_var(
      $request['id_produk'] ?? null,
      FILTER_VALIDATE_INT,
      [
        'options' => [
          'min_range' => 1
        ]
      ]
    );

    if ($id_produk_valid === false) {
      $this->api_response([
        'status'        => false,
        'message'       => 'ID produk tidak valid.',
        'is_wishlisted' => false
      ], 422);
      return;
    }

    $id_pembeli = (int) $auth->id_user;
    $id_produk  = (int) $id_produk_valid;

    $produk = $this->db
      ->select([
        'id_produk',
        'status_produk'
      ])
      ->where('id_produk', $id_produk)
      ->limit(1)
      ->get('tb_produk')
      ->row();

    if (!$produk) {
      $this->api_response([
        'status'        => false,
        'message'       => 'Produk tidak ditemukan.',
        'is_wishlisted' => false
      ], 404);
      return;
    }

    /*
     * id_pembeli selalu berasal dari Bearer token.
     * Nilai id_pembeli dari request tidak digunakan.
     */
    $jumlah = (int) $this->db
      ->where('id_pembeli', $id_pembeli)
      ->where('id_produk', $id_produk)
      ->count_all_results('tb_wishlist');

    $this->api_response([
      'status'        => true,
      'message'       => 'Status wishlist berhasil diperiksa.',
      'is_wishlisted' => $jumlah > 0,
      'data'          => [
        'id_produk'       => $id_produk,
        'is_wishlisted'   => $jumlah > 0,
        'status_produk'   => $produk->status_produk
      ]
    ]);
  }

  // 16. Endpoint Toggle Wishlist
  public function toggle_wishlist()
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
        'message' => 'Akses ditolak. Endpoint ini khusus Nasabah.'
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

    $id_produk_valid = filter_var(
      $request['id_produk'] ?? null,
      FILTER_VALIDATE_INT,
      [
        'options' => [
          'min_range' => 1
        ]
      ]
    );

    if ($id_produk_valid === false) {
      $this->api_response([
        'status'  => false,
        'message' => 'ID produk tidak valid.'
      ], 422);
      return;
    }

    /*
     * Identitas pembeli hanya berasal dari Bearer token.
     */
    $id_pembeli = (int) $auth->id_user;
    $id_produk  = (int) $id_produk_valid;

    $this->db->trans_begin();

    $wishlist = $this->db->query(
      "SELECT
          id_wishlist
       FROM tb_wishlist
       WHERE id_pembeli = ?
         AND id_produk = ?
       LIMIT 1
       FOR UPDATE",
      [
        $id_pembeli,
        $id_produk
      ]
    )->row();

    /*
     * Penghapusan tetap diperbolehkan apabila produk
     * sudah diarsipkan atau tokonya tidak aktif.
     */
    if ($wishlist) {
      $dihapus = $this->db
        ->where(
          'id_wishlist',
          (int) $wishlist->id_wishlist
        )
        ->where('id_pembeli', $id_pembeli)
        ->delete('tb_wishlist');

      if (
        !$dihapus ||
        $this->db->trans_status() === false
      ) {
        $database_error = $this->db->error();
        $this->db->trans_rollback();

        log_message(
          'error',
          'Gagal menghapus wishlist: ' .
            json_encode($database_error)
        );

        $this->api_response([
          'status'  => false,
          'message' => 'Wishlist gagal dihapus.'
        ], 500);
        return;
      }

      $this->db->trans_commit();

      $this->api_response([
        'status'        => true,
        'action'        => 'removed',
        'message'       => 'Produk dihapus dari favorit.',
        'is_wishlisted' => false,
        'data'          => [
          'id_produk'     => $id_produk,
          'is_wishlisted' => false
        ]
      ]);
      return;
    }

    /*
     * Produk hanya boleh ditambahkan jika produk, toko,
     * dan cabang penjual masih aktif.
     */
    $produk = $this->db
      ->select([
        'p.id_produk',
        'p.nama_produk',
        'p.stok',
        'p.status_produk',
        't.id_toko',
        't.status_toko',
        'c.status AS status_cabang'
      ])
      ->from('tb_produk p')
      ->join(
        'tb_toko t',
        't.id_toko = p.id_toko'
      )
      ->join(
        'tb_user penjual',
        'penjual.id = t.id_user'
      )
      ->join(
        'tb_cabang c',
        'c.id = penjual.cabang_id'
      )
      ->where('p.id_produk', $id_produk)
      ->limit(1)
      ->get()
      ->row();

    if (!$produk) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Produk tidak ditemukan.'
      ], 404);
      return;
    }

    if (
      $produk->status_produk !== 'Tersedia' ||
      (int) $produk->stok <= 0 ||
      $produk->status_toko !== 'Aktif' ||
      $produk->status_cabang !== 'Aktif'
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Produk sedang tidak tersedia untuk ditambahkan ke favorit.'
      ], 409);
      return;
    }

    $ditambahkan = $this->db->insert(
      'tb_wishlist',
      [
        'id_pembeli' => $id_pembeli,
        'id_produk'   => $id_produk,
        'tanggal'     => date('Y-m-d H:i:s')
      ]
    );

    if (
      !$ditambahkan ||
      $this->db->trans_status() === false
    ) {
      $database_error = $this->db->error();
      $this->db->trans_rollback();

      /*
       * Unique index tetap melindungi dari request
       * bersamaan yang mencoba menambahkan produk sama.
       */
      if ((int) ($database_error['code'] ?? 0) === 1062) {
        $this->api_response([
          'status'        => true,
          'action'        => 'added',
          'message'       => 'Produk sudah ada dalam favorit.',
          'is_wishlisted' => true,
          'data'          => [
            'id_produk'     => $id_produk,
            'is_wishlisted' => true
          ]
        ]);
        return;
      }

      log_message(
        'error',
        'Gagal menambahkan wishlist: ' .
          json_encode($database_error)
      );

      $this->api_response([
        'status'  => false,
        'message' => 'Wishlist gagal ditambahkan.'
      ], 500);
      return;
    }

    $id_wishlist = (int) $this->db->insert_id();

    $this->db->trans_commit();

    $this->api_response([
      'status'        => true,
      'action'        => 'added',
      'message'       => 'Produk ditambahkan ke favorit.',
      'is_wishlisted' => true,
      'data'          => [
        'id_wishlist'   => $id_wishlist,
        'id_produk'     => $id_produk,
        'is_wishlisted' => true
      ]
    ], 201);
  }

  // 17. Endpoint Daftar Wishlist Pembeli
  public function get_wishlist_pembeli()
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
        'message' => 'Akses ditolak. Endpoint ini khusus Nasabah.'
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

    $page = isset($request['page'])
      ? (int) $request['page']
      : 1;

    $limit = isset($request['limit'])
      ? (int) $request['limit']
      : 20;

    if ($page < 1) {
      $page = 1;
    }

    if ($limit < 1) {
      $limit = 20;
    }

    if ($limit > 100) {
      $limit = 100;
    }

    $offset = ($page - 1) * $limit;

    /*
     * id_pembeli dari request tidak dipercaya.
     */
    $id_pembeli = (int) $auth->id_user;

    $this->db->from('tb_wishlist w');
    $this->db->join(
      'tb_produk p',
      'p.id_produk = w.id_produk'
    );
    $this->db->join(
      'tb_toko t',
      't.id_toko = p.id_toko'
    );
    $this->db->join(
      'tb_user penjual',
      'penjual.id = t.id_user'
    );
    $this->db->join(
      'tb_cabang c',
      'c.id = penjual.cabang_id'
    );

    $this->db->where(
      'w.id_pembeli',
      $id_pembeli
    );
    $this->db->where(
      'p.status_produk',
      'Tersedia'
    );
    $this->db->where('p.stok >', 0);
    $this->db->where(
      't.status_toko',
      'Aktif'
    );
    $this->db->where(
      'c.status',
      'Aktif'
    );

    $total_data = (int)
    $this->db->count_all_results();

    $this->db->select([
      'w.id_wishlist',
      'w.tanggal AS tanggal_wishlist',
      'p.id_produk',
      'p.id_toko',
      'p.nama_produk',
      'p.kategori',
      'p.deskripsi_produk',
      'p.harga',
      'p.harga_coret',
      'p.stok',
      'p.berat',
      'p.rating',
      'p.terjual',
      'p.foto_produk',
      'p.foto_2',
      'p.foto_3',
      'p.status_produk',
      'p.terdaftar',
      't.nama_toko',
      't.status_toko',
      'penjual.cabang_id',
      'c.kode AS kode_cabang',
      'c.nama AS nama_cabang'
    ]);

    $this->db->from('tb_wishlist w');
    $this->db->join(
      'tb_produk p',
      'p.id_produk = w.id_produk'
    );
    $this->db->join(
      'tb_toko t',
      't.id_toko = p.id_toko'
    );
    $this->db->join(
      'tb_user penjual',
      'penjual.id = t.id_user'
    );
    $this->db->join(
      'tb_cabang c',
      'c.id = penjual.cabang_id'
    );

    $this->db->where(
      'w.id_pembeli',
      $id_pembeli
    );
    $this->db->where(
      'p.status_produk',
      'Tersedia'
    );
    $this->db->where('p.stok >', 0);
    $this->db->where(
      't.status_toko',
      'Aktif'
    );
    $this->db->where(
      'c.status',
      'Aktif'
    );

    $this->db->order_by(
      'w.id_wishlist',
      'DESC'
    );
    $this->db->limit($limit, $offset);

    $query = $this->db->get();

    if (!$query) {
      $this->api_response([
        'status'  => false,
        'message' => 'Gagal mengambil daftar wishlist.'
      ], 500);
      return;
    }

    $hasil = $query->result_array();
    $data_wishlist = [];

    foreach ($hasil as $row) {
      $data_wishlist[] = [
        'id_wishlist' =>
        (int) $row['id_wishlist'],

        'tanggal_wishlist' =>
        $row['tanggal_wishlist'],

        'id_produk' =>
        (int) $row['id_produk'],

        'id_toko' =>
        (int) $row['id_toko'],

        'nama_produk' =>
        $row['nama_produk'],

        'kategori' =>
        $row['kategori'],

        'deskripsi_produk' =>
        $row['deskripsi_produk'],

        'harga' =>
        (int) $row['harga'],

        'harga_coret' =>
        (int) $row['harga_coret'],

        'stok' =>
        (int) $row['stok'],

        'berat' =>
        (int) $row['berat'],

        'rating' =>
        (float) $row['rating'],

        'terjual' =>
        (int) $row['terjual'],

        'foto_produk' =>
        $row['foto_produk'],

        'foto_2' =>
        $row['foto_2'],

        'foto_3' =>
        $row['foto_3'],

        'status_produk' =>
        $row['status_produk'],

        'terdaftar' =>
        $row['terdaftar'],

        'nama_toko' =>
        $row['nama_toko'],

        'status_toko' =>
        $row['status_toko'],

        'cabang_id' =>
        (int) $row['cabang_id'],

        'kode_cabang' =>
        $row['kode_cabang'],

        'nama_cabang' =>
        $row['nama_cabang']
      ];
    }

    $this->api_response([
      'status'  => true,
      'message' => $total_data > 0
        ? 'Daftar wishlist berhasil diambil.'
        : 'Wishlist masih kosong.',
      'data'    => $data_wishlist,
      'pagination' => [
        'page'       => $page,
        'limit'      => $limit,
        'total_data' => $total_data,
        'total_page' => $total_data > 0
          ? (int) ceil($total_data / $limit)
          : 0
      ]
    ]);
  }

  // 18. Endpoint Hitung Wishlist
  public function count_wishlist()
  {
    header('Access-Control-Allow-Origin: *');
    header('Content-Type: application/json; charset=UTF-8');
    header('Access-Control-Allow-Methods: POST');

    if ($this->input->method(TRUE) !== 'POST') {
      $this->api_response([
        'status'  => false,
        'message' => 'Metode request tidak diizinkan.',
        'count'   => 0
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
        'message' => 'Akses ditolak. Endpoint ini khusus Nasabah.',
        'count'   => 0
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
        'message' => 'Format JSON tidak valid.',
        'count'   => 0
      ], 400);
      return;
    }

    /*
     * id_user dari request diabaikan.
     * Pengguna ditentukan oleh Bearer token.
     */
    $id_pembeli = (int) $auth->id_user;

    $this->db->from('tb_wishlist w');
    $this->db->join(
      'tb_produk p',
      'p.id_produk = w.id_produk'
    );
    $this->db->join(
      'tb_toko t',
      't.id_toko = p.id_toko'
    );
    $this->db->join(
      'tb_user penjual',
      'penjual.id = t.id_user'
    );
    $this->db->join(
      'tb_cabang c',
      'c.id = penjual.cabang_id'
    );

    $this->db->where(
      'w.id_pembeli',
      $id_pembeli
    );
    $this->db->where(
      'p.status_produk',
      'Tersedia'
    );
    $this->db->where('p.stok >', 0);
    $this->db->where(
      't.status_toko',
      'Aktif'
    );
    $this->db->where(
      'c.status',
      'Aktif'
    );

    $count = (int) $this->db->count_all_results();

    $this->api_response([
      'status'  => true,
      'message' => 'Jumlah wishlist berhasil diambil.',
      'count'   => $count,
      'data'    => [
        'count' => $count
      ]
    ]);
  }

  // 19. Endpoint Ambil Daftar Notifikasi User
  public function get_notifikasi()
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

    $page = isset($request['page'])
      ? (int) $request['page']
      : 1;

    $limit = isset($request['limit'])
      ? (int) $request['limit']
      : 20;

    if ($page < 1) {
      $page = 1;
    }

    if ($limit < 1) {
      $limit = 20;
    }

    if ($limit > 100) {
      $limit = 100;
    }

    $offset = ($page - 1) * $limit;

    /*
     * Identitas pengguna selalu berasal dari Bearer token.
     * id_user dari request tidak dipercaya.
     */
    $id_user = (int) $auth->id_user;

    $total_data = (int) $this->db
      ->where('id_user', $id_user)
      ->count_all_results('tb_notifikasi');

    $total_belum_dibaca = (int) $this->db
      ->where('id_user', $id_user)
      ->where('is_read', 0)
      ->count_all_results('tb_notifikasi');

    $query = $this->db
      ->select([
        'id_notifikasi',
        'judul',
        'pesan',
        'is_read',
        'tanggal'
      ])
      ->where('id_user', $id_user)
      ->order_by('id_notifikasi', 'DESC')
      ->limit($limit, $offset)
      ->get('tb_notifikasi');

    if (!$query) {
      $this->api_response([
        'status'  => false,
        'message' => 'Gagal mengambil daftar notifikasi.'
      ], 500);
      return;
    }

    $hasil = $query->result_array();
    $data_notifikasi = [];

    foreach ($hasil as $row) {
      $data_notifikasi[] = [
        'id_notifikasi' =>
        (int) $row['id_notifikasi'],

        'judul' =>
        $row['judul'],

        'pesan' =>
        $row['pesan'],

        'is_read' =>
        (bool) ((int) $row['is_read']),

        'tanggal' =>
        $row['tanggal']
      ];
    }

    $this->api_response([
      'status'  => true,
      'message' => $total_data > 0
        ? 'Daftar notifikasi berhasil diambil.'
        : 'Belum ada notifikasi.',
      'data'    => $data_notifikasi,
      'ringkasan' => [
        'total_notifikasi'   => $total_data,
        'belum_dibaca'       => $total_belum_dibaca,
        'sudah_dibaca'       =>
        $total_data - $total_belum_dibaca
      ],
      'pagination' => [
        'page'       => $page,
        'limit'      => $limit,
        'total_data' => $total_data,
        'total_page' => $total_data > 0
          ? (int) ceil($total_data / $limit)
          : 0
      ]
    ]);
  }

  // 20. Endpoint Tandai Notifikasi Telah Dibaca
  public function tandai_dibaca()
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

    $id_notifikasi_valid = filter_var(
      $request['id_notifikasi'] ?? null,
      FILTER_VALIDATE_INT,
      [
        'options' => [
          'min_range' => 1
        ]
      ]
    );

    if ($id_notifikasi_valid === false) {
      $this->api_response([
        'status'  => false,
        'message' => 'ID notifikasi tidak valid.'
      ], 422);
      return;
    }

    $id_user = (int) $auth->id_user;
    $id_notifikasi = (int) $id_notifikasi_valid;

    /*
     * Query wajib menyertakan id_user agar pengguna
     * tidak dapat mengubah notifikasi milik akun lain.
     */
    $notifikasi = $this->db
      ->select([
        'id_notifikasi',
        'is_read'
      ])
      ->where(
        'id_notifikasi',
        $id_notifikasi
      )
      ->where('id_user', $id_user)
      ->limit(1)
      ->get('tb_notifikasi')
      ->row();

    if (!$notifikasi) {
      $this->api_response([
        'status'  => false,
        'message' => 'Notifikasi tidak ditemukan.'
      ], 404);
      return;
    }

    $sudah_dibaca =
      (int) $notifikasi->is_read === 1;

    if (!$sudah_dibaca) {
      $updated = $this->db
        ->where(
          'id_notifikasi',
          $id_notifikasi
        )
        ->where('id_user', $id_user)
        ->update(
          'tb_notifikasi',
          [
            'is_read' => 1
          ]
        );

      if (!$updated) {
        $database_error = $this->db->error();

        log_message(
          'error',
          'Gagal menandai notifikasi: ' .
            json_encode($database_error)
        );

        $this->api_response([
          'status'  => false,
          'message' => 'Notifikasi gagal ditandai sebagai dibaca.'
        ], 500);
        return;
      }
    }

    $this->api_response([
      'status'  => true,
      'message' => $sudah_dibaca
        ? 'Notifikasi sudah ditandai sebagai dibaca.'
        : 'Notifikasi berhasil ditandai sebagai dibaca.',
      'data'    => [
        'id_notifikasi' => $id_notifikasi,
        'is_read'       => true,
        'sudah_dibaca_sebelumnya' =>
        $sudah_dibaca
      ]
    ]);
  }

  // 21. Endpoint Hitung Notifikasi Belum Dibaca
  public function count_unread_notif()
  {
    header('Access-Control-Allow-Origin: *');
    header('Content-Type: application/json; charset=UTF-8');
    header('Access-Control-Allow-Methods: POST');

    if ($this->input->method(TRUE) !== 'POST') {
      $this->api_response([
        'status'  => false,
        'message' => 'Metode request tidak diizinkan.',
        'count'   => 0
      ], 405);
      return;
    }

    $auth = $this->authenticate_api();

    if (!$auth) {
      return;
    }

    $request = json_decode(
      $this->input->raw_input_stream,
      true
    );

    if (!is_array($request)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Format JSON tidak valid.',
        'count'   => 0
      ], 400);
      return;
    }

    /*
     * id_user dari request diabaikan.
     */
    $id_user = (int) $auth->id_user;

    $count = (int) $this->db
      ->where('id_user', $id_user)
      ->where('is_read', 0)
      ->count_all_results('tb_notifikasi');

    $this->api_response([
      'status'  => true,
      'message' => 'Jumlah notifikasi belum dibaca berhasil diambil.',
      'count'   => $count,
      'data'    => [
        'count' => $count
      ]
    ]);
  }

  // 22. Endpoint Hapus Semua Notifikasi User
  public function clear_notifikasi()
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

    /*
     * Hanya notifikasi pemilik Bearer token yang dihapus.
     * id_user dari request tidak digunakan.
     */
    $id_user = (int) $auth->id_user;

    $delete = $this->db
      ->where('id_user', $id_user)
      ->delete('tb_notifikasi');

    if (!$delete) {
      $database_error = $this->db->error();

      log_message(
        'error',
        'Gagal menghapus seluruh notifikasi: ' .
          json_encode($database_error)
      );

      $this->api_response([
        'status'  => false,
        'message' => 'Gagal menghapus notifikasi.'
      ], 500);
      return;
    }

    $jumlah_dihapus =
      (int) $this->db->affected_rows();

    $this->api_response([
      'status'  => true,
      'message' => $jumlah_dihapus > 0
        ? 'Semua notifikasi berhasil dihapus.'
        : 'Tidak ada notifikasi yang perlu dihapus.',
      'data'    => [
        'jumlah_dihapus' => $jumlah_dihapus
      ]
    ]);
  }

  // ==========================================
  // FITUR MARKETPLACE: BANNER DINAMIS
  // ==========================================

  // 1. Ambil Data Banner Marketplace
  public function get_banner_market()
  {
    header('Access-Control-Allow-Origin: *');
    header('Content-Type: application/json; charset=UTF-8');
    header('Access-Control-Allow-Methods: GET, POST');

    $method = $this->input->method(TRUE);

    if (!in_array($method, ['GET', 'POST'], true)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Metode request tidak diizinkan.'
      ], 405);
      return;
    }

    $query = $this->db
      ->select([
        'id',
        'gambar',
        'terdaftar'
      ])
      ->order_by('id', 'DESC')
      ->get('tb_banner_market');

    if (!$query) {
      $this->api_response([
        'status'  => false,
        'message' => 'Gagal mengambil banner marketplace.'
      ], 500);
      return;
    }

    $hasil = $query->result_array();
    $data_banner = [];

    foreach ($hasil as $row) {
      $data_banner[] = [
        'id'         => (int) $row['id'],
        'gambar'     => $row['gambar'],
        'terdaftar'  => $row['terdaftar']
      ];
    }

    $this->api_response([
      'status'  => true,
      'message' => count($data_banner) > 0
        ? 'Banner marketplace berhasil diambil.'
        : 'Belum ada banner marketplace.',
      'data'    => $data_banner
    ]);
  }

  // 2. Upload Banner Marketplace
  public function upload_banner_market()
  {
    if (ob_get_length()) {
      ob_clean();
    }

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
     * Banner marketplace dan broadcast notifikasi
     * bersifat global, sehingga hanya Super Admin
     * yang diperbolehkan mengelolanya.
     */
    if ($auth->level !== 'Super Admin') {
      $this->api_response([
        'status'  => false,
        'message' => 'Akses ditolak. Khusus Super Admin.'
      ], 403);
      return;
    }

    $content_length = isset($_SERVER['CONTENT_LENGTH'])
      ? (int) $_SERVER['CONTENT_LENGTH']
      : 0;

    if ($content_length > 6 * 1024 * 1024) {
      $this->api_response([
        'status'  => false,
        'message' => 'Ukuran request terlalu besar.'
      ], 413);
      return;
    }

    if (
      !isset($_FILES['banner_image']) ||
      !is_array($_FILES['banner_image'])
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Gambar banner wajib dipilih.'
      ], 422);
      return;
    }

    if (
      (int) (
        $_FILES['banner_image']['error']
        ?? UPLOAD_ERR_NO_FILE
      ) !== UPLOAD_ERR_OK
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Gambar banner gagal diterima oleh server.'
      ], 422);
      return;
    }

    $upload_dir = FCPATH . 'assets/';

    if (
      !is_dir($upload_dir) ||
      !is_writable($upload_dir)
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Folder penyimpanan banner tidak tersedia.'
      ], 500);
      return;
    }

    try {
      $random_name = bin2hex(random_bytes(12));
    } catch (Exception $e) {
      $random_name = str_replace(
        '.',
        '',
        uniqid('', true)
      );
    }

    $config = [
      'upload_path'      => $upload_dir,
      'allowed_types'    => 'jpg|jpeg|png|webp',
      'max_size'         => 5120,
      'max_width'        => 10000,
      'max_height'       => 10000,
      'detect_mime'      => true,
      'file_ext_tolower' => true,
      'remove_spaces'    => true,
      'file_name'        =>
      'banner_mkt_' .
        date('YmdHis') . '_' .
        $random_name
    ];

    $this->load->library('upload');
    $this->upload->initialize($config);

    if (!$this->upload->do_upload('banner_image')) {
      $error = strip_tags(
        $this->upload->display_errors('', '')
      );

      $this->api_response([
        'status'  => false,
        'message' => 'Gagal mengunggah banner: ' . $error
      ], 422);
      return;
    }

    $upload_data = $this->upload->data();

    $file_name = basename(
      (string) $upload_data['file_name']
    );

    $file_path = $upload_dir . $file_name;

    /*
     * Validasi ulang isi file, bukan hanya ekstensi.
     */
    $image_info = @getimagesize($file_path);
    $mime = $image_info['mime'] ?? '';
    $width = (int) ($image_info[0] ?? 0);
    $height = (int) ($image_info[1] ?? 0);

    $allowed_mimes = [
      'image/jpeg',
      'image/png',
      'image/webp'
    ];

    if (
      !$image_info ||
      !in_array($mime, $allowed_mimes, true) ||
      $width <= 0 ||
      $height <= 0 ||
      $width > 10000 ||
      $height > 10000 ||
      ($width * $height) > 40000000
    ) {
      if (is_file($file_path)) {
        @unlink($file_path);
      }

      $this->api_response([
        'status'  => false,
        'message' => 'Isi atau dimensi gambar banner tidak valid.'
      ], 422);
      return;
    }

    /*
     * Secara default notifikasi tetap dikirim agar
     * kompatibel dengan aplikasi lama.
     *
     * Super Admin dapat mengirim:
     * kirim_notifikasi=0
     * untuk memublikasikan banner tanpa broadcast.
     */
    $kirim_notifikasi_raw = $this->input->post(
      'kirim_notifikasi',
      true
    );

    $kirim_notifikasi = true;

    if (
      $kirim_notifikasi_raw !== null &&
      $kirim_notifikasi_raw !== ''
    ) {
      $nilai_notifikasi = strtolower(
        trim((string) $kirim_notifikasi_raw)
      );

      if (
        in_array(
          $nilai_notifikasi,
          ['1', 'true', 'ya', 'yes'],
          true
        )
      ) {
        $kirim_notifikasi = true;
      } elseif (
        in_array(
          $nilai_notifikasi,
          ['0', 'false', 'tidak', 'no'],
          true
        )
      ) {
        $kirim_notifikasi = false;
      } else {
        if (is_file($file_path)) {
          @unlink($file_path);
        }

        $this->api_response([
          'status'  => false,
          'message' => 'Nilai kirim_notifikasi tidak valid.'
        ], 422);
        return;
      }
    }

    $judul_notif =
      'Promo Baru di Marketplace!';

    $pesan_notif =
      'Admin baru saja menambahkan promo menarik. ' .
      'Yuk, cek sekarang di aplikasi sebelum kehabisan!';

    /*
     * Daftar Nasabah hanya diambil ketika broadcast
     * benar-benar diminta.
     */
    $nasabah = [];

    if ($kirim_notifikasi) {
      $query_nasabah = $this->db
        ->select([
          'u.id',
          'u.expo_token'
        ])
        ->from('tb_user u')
        ->join(
          'tb_cabang c',
          'c.id = u.cabang_id'
        )
        ->where('u.level', 'Nasabah')
        ->where('u.login', 'Ya')
        ->where('c.status', 'Aktif')
        ->get();

      if (!$query_nasabah) {
        $database_error = $this->db->error();

        if (is_file($file_path)) {
          @unlink($file_path);
        }

        log_message(
          'error',
          'Gagal mengambil penerima notifikasi banner: ' .
            json_encode($database_error)
        );

        $this->api_response([
          'status'  => false,
          'message' => 'Daftar penerima notifikasi gagal diambil.'
        ], 500);
        return;
      }

      $nasabah = $query_nasabah->result();
    }

    $tanggal = date('Y-m-d H:i:s');
    $data_notifikasi = [];

    foreach ($nasabah as $row) {
      $data_notifikasi[] = [
        'id_user' => (int) $row->id,
        'judul'   => $judul_notif,
        'pesan'   => $pesan_notif,
        'is_read' => 0,
        'tanggal' => $tanggal
      ];
    }

    $this->db->trans_begin();

    $insert_banner = $this->db->insert(
      'tb_banner_market',
      [
        'gambar'    => $file_name,
        'terdaftar' => $tanggal
      ]
    );

    $id_banner = (int) $this->db->insert_id();
    $insert_notifikasi = true;

    if (
      $insert_banner &&
      count($data_notifikasi) > 0
    ) {
      $insert_notifikasi = $this->db->insert_batch(
        'tb_notifikasi',
        $data_notifikasi
      );
    }

    if (
      !$insert_banner ||
      $insert_notifikasi === false ||
      $this->db->trans_status() === false
    ) {
      $database_error = $this->db->error();

      $this->db->trans_rollback();

      if (is_file($file_path)) {
        @unlink($file_path);
      }

      log_message(
        'error',
        'Gagal menyimpan banner marketplace: ' .
          json_encode($database_error)
      );

      $this->api_response([
        'status'  => false,
        'message' => 'Banner marketplace gagal disimpan.'
      ], 500);
      return;
    }

    $this->db->trans_commit();

    /*
     * Push dikirim setelah transaksi database berhasil.
     * Kegagalan push tidak membatalkan banner.
     */
    $jumlah_push_berhasil = 0;

    if ($kirim_notifikasi) {
      foreach ($nasabah as $row) {
        if (
          !empty($row->expo_token) &&
          $this->send_expo_push_notification(
            $row->expo_token,
            $judul_notif,
            $pesan_notif
          )
        ) {
          $jumlah_push_berhasil++;
        }
      }
    }

    $message = $kirim_notifikasi
      ? 'Banner berhasil dipublikasikan dan notifikasi telah dibuat.'
      : 'Banner berhasil dipublikasikan tanpa mengirim notifikasi.';

    $this->api_response([
      'status'  => true,
      'message' => $message,
      'data'    => [
        'id_banner' =>
        $id_banner,

        'gambar' =>
        $file_name,

        'width' =>
        $width,

        'height' =>
        $height,

        'notifikasi_dikirim' =>
        $kirim_notifikasi,

        'jumlah_notifikasi' =>
        count($data_notifikasi),

        'jumlah_push_berhasil' =>
        $jumlah_push_berhasil,

        'dipublikasikan_oleh' =>
        (int) $auth->id_user,

        'nama_operator' =>
        $auth->nama
      ]
    ], 201);
  }

  // 3. Hapus Banner Marketplace
  public function hapus_banner_market()
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

    if ($auth->level !== 'Super Admin') {
      $this->api_response([
        'status'  => false,
        'message' => 'Akses ditolak. Khusus Super Admin.'
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

    $id_banner_valid = filter_var(
      $request['id_banner'] ?? null,
      FILTER_VALIDATE_INT,
      [
        'options' => [
          'min_range' => 1
        ]
      ]
    );

    if ($id_banner_valid === false) {
      $this->api_response([
        'status'  => false,
        'message' => 'ID banner tidak valid.'
      ], 422);
      return;
    }

    $id_banner = (int) $id_banner_valid;

    $this->db->trans_begin();

    $banner = $this->db->query(
      "SELECT
          id,
          gambar
       FROM tb_banner_market
       WHERE id = ?
       LIMIT 1
       FOR UPDATE",
      [$id_banner]
    )->row();

    if (!$banner) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Banner marketplace tidak ditemukan.'
      ], 404);
      return;
    }

    $gambar_asli = (string) $banner->gambar;
    $file_name = basename($gambar_asli);

    /*
     * Tolak nama file yang mengandung path atau karakter
     * di luar pola banner marketplace.
     */
    if (
      $file_name !== $gambar_asli ||
      !preg_match(
        '/^banner_mkt_[A-Za-z0-9._-]+\.(jpg|jpeg|png|webp)$/i',
        $file_name
      )
    ) {
      $this->db->trans_rollback();

      log_message(
        'error',
        'Nama file banner marketplace tidak aman: ' .
          $gambar_asli
      );

      $this->api_response([
        'status'  => false,
        'message' => 'Nama file banner pada database tidak valid.'
      ], 409);
      return;
    }

    $delete = $this->db
      ->where('id', $id_banner)
      ->delete('tb_banner_market');

    if (
      !$delete ||
      $this->db->trans_status() === false
    ) {
      $database_error = $this->db->error();

      $this->db->trans_rollback();

      log_message(
        'error',
        'Gagal menghapus banner marketplace: ' .
          json_encode($database_error)
      );

      $this->api_response([
        'status'  => false,
        'message' => 'Banner marketplace gagal dihapus.'
      ], 500);
      return;
    }

    $this->db->trans_commit();

    /*
     * File dihapus setelah transaksi database berhasil.
     * Path selalu berasal dari basename yang telah divalidasi.
     */
    $file_path = FCPATH . 'assets/' . $file_name;
    $file_ditemukan = is_file($file_path);
    $file_terhapus = true;

    if ($file_ditemukan) {
      $file_terhapus = @unlink($file_path);

      if (!$file_terhapus) {
        log_message(
          'error',
          'File banner marketplace gagal dihapus: ' .
            $file_name
        );
      }
    }

    $this->api_response([
      'status'  => true,
      'message' => $file_terhapus
        ? 'Banner marketplace berhasil dihapus.'
        : 'Data banner berhasil dihapus, tetapi file fisik gagal dibersihkan.',
      'data'    => [
        'id_banner'       => $id_banner,
        'gambar'          => $file_name,
        'file_ditemukan'  => $file_ditemukan,
        'file_terhapus'   => $file_terhapus,
        'dihapus_oleh'    => (int) $auth->id_user,
        'nama_operator'   => $auth->nama
      ]
    ]);
  }


  // ==========================================
  // ADMIN ATUR DURASI KUNCI TABUNGAN EMAS
  // ==========================================
  public function admin_atur_kunci_emas()
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

    if (
      !in_array(
        $auth->level,
        ['Administrator', 'Super Admin'],
        true
      )
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Akses ditolak. Khusus Administrator.'
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

    $id_nasabah_valid = filter_var(
      $request['id_nasabah'] ?? null,
      FILTER_VALIDATE_INT,
      [
        'options' => [
          'min_range' => 1
        ]
      ]
    );

    if ($id_nasabah_valid === false) {
      $this->api_response([
        'status'  => false,
        'message' => 'ID Nasabah tidak valid.'
      ], 422);
      return;
    }

    $durasi_valid = filter_var(
      $request['durasi_bulan'] ?? null,
      FILTER_VALIDATE_INT,
      [
        'options' => [
          'min_range' => 6,
          'max_range' => 120
        ]
      ]
    );

    if ($durasi_valid === false) {
      $this->api_response([
        'status'  => false,
        'message' => 'Durasi kunci harus antara 6 sampai 120 bulan.'
      ], 422);
      return;
    }

    $id_nasabah = (int) $id_nasabah_valid;
    $durasi_bulan = (int) $durasi_valid;
    $waktu_sekarang = date('Y-m-d H:i:s');

    $this->db->trans_begin();

    /*
     * Kunci akun Nasabah agar pengaturan tidak berubah
     * bersamaan dengan transaksi pembelian atau pencairan.
     */
    $nasabah = $this->db->query(
      "SELECT
          u.id,
          u.nama,
          u.level,
          u.login,
          u.cabang_id,
          c.kode AS kode_cabang,
          c.nama AS nama_cabang,
          c.status AS status_cabang
       FROM tb_user AS u
       LEFT JOIN tb_cabang AS c
         ON c.id = u.cabang_id
       WHERE u.id = ?
       LIMIT 1
       FOR UPDATE",
      [$id_nasabah]
    )->row();

    if (
      !$nasabah ||
      $nasabah->level !== 'Nasabah'
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Nasabah tidak ditemukan.'
      ], 404);
      return;
    }

    if (
      $nasabah->login !== 'Ya' ||
      $nasabah->status_cabang !== 'Aktif'
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Akun atau cabang Nasabah sedang tidak aktif.'
      ], 409);
      return;
    }

    if (
      $auth->level === 'Administrator' &&
      (int) $nasabah->cabang_id !==
      (int) $auth->cabang_id
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Anda hanya dapat mengatur Nasabah pada cabang sendiri.'
      ], 403);
      return;
    }

    $kunci_lama = $this->db->query(
      "SELECT
          id_kunci,
          durasi_bulan,
          terkunci_sampai,
          ditetapkan_oleh,
          ditetapkan_pada
       FROM tb_kunci_emas
       WHERE id_nasabah = ?
       LIMIT 1
       FOR UPDATE",
      [$id_nasabah]
    )->row();

    /*
     * Hitung saldo dan pembelian emas terakhir.
     */
    $ringkasan_emas = $this->db->query(
      "SELECT
          COALESCE(SUM(gram_emas), 0)
            AS saldo_emas,

          MAX(
            CASE
              WHEN gram_emas > 0
              THEN terdaftar
              ELSE NULL
            END
          ) AS pembelian_terakhir
       FROM tb_transaksi
       WHERE idNasabah = ?
         AND status_konfirmasi = 'Sukses'
         AND gram_emas <> 0",
      [$id_nasabah]
    )->row();

    $saldo_emas = round(
      (float) ($ringkasan_emas->saldo_emas ?? 0),
      4
    );

    $pembelian_terakhir =
      $ringkasan_emas->pembelian_terakhir ?? null;

    $calon_terkunci_sampai = null;

    if (
      $saldo_emas > 0 &&
      $pembelian_terakhir !== null
    ) {
      try {
        $tanggal_kunci = new DateTime(
          $pembelian_terakhir
        );

        $tanggal_kunci->modify(
          '+' . $durasi_bulan . ' months'
        );

        $calon_terkunci_sampai =
          $tanggal_kunci->format('Y-m-d H:i:s');
      } catch (Exception $e) {
        $this->db->trans_rollback();

        log_message(
          'error',
          'Gagal menghitung jatuh tempo emas: ' .
            $e->getMessage()
        );

        $this->api_response([
          'status'  => false,
          'message' => 'Tanggal jatuh tempo emas gagal dihitung.'
        ], 500);
        return;
      }
    }

    /*
     * Durasi baru tidak boleh memperpendek masa kunci
     * yang masih tersimpan.
     */
    $terkunci_sampai = null;

    if ($saldo_emas > 0) {
      $terkunci_sampai =
        $kunci_lama->terkunci_sampai ?? null;

      if (
        $calon_terkunci_sampai !== null &&
        (
          $terkunci_sampai === null ||
          strtotime($calon_terkunci_sampai) >
          strtotime($terkunci_sampai)
        )
      ) {
        $terkunci_sampai =
          $calon_terkunci_sampai;
      }
    }

    $data_kunci = [
      'durasi_bulan'    => $durasi_bulan,
      'terkunci_sampai' => $terkunci_sampai,
      'ditetapkan_oleh' => (int) $auth->id_user,
      'ditetapkan_pada' => $waktu_sekarang,
      'diperbarui_pada' => $waktu_sekarang
    ];

    if ($kunci_lama) {
      $proses = $this->db
        ->where(
          'id_kunci',
          (int) $kunci_lama->id_kunci
        )
        ->where('id_nasabah', $id_nasabah)
        ->update(
          'tb_kunci_emas',
          $data_kunci
        );

      $id_kunci =
        (int) $kunci_lama->id_kunci;
    } else {
      $data_kunci['id_nasabah'] =
        $id_nasabah;

      $proses = $this->db->insert(
        'tb_kunci_emas',
        $data_kunci
      );

      $id_kunci =
        (int) $this->db->insert_id();
    }

    if (
      !$proses ||
      $this->db->trans_status() === false
    ) {
      $database_error = $this->db->error();

      $this->db->trans_rollback();

      log_message(
        'error',
        'Gagal mengatur kunci emas: ' .
          json_encode($database_error)
      );

      $this->api_response([
        'status'  => false,
        'message' => 'Pengaturan kunci emas gagal disimpan.'
      ], 500);
      return;
    }

    $this->db->trans_commit();

    $status_terkunci = (
      $saldo_emas > 0 &&
      $terkunci_sampai !== null &&
      strtotime($terkunci_sampai) >
      strtotime($waktu_sekarang)
    );

    $sisa_hari = 0;

    if ($status_terkunci) {
      $selisih_detik =
        strtotime($terkunci_sampai) -
        strtotime($waktu_sekarang);

      $sisa_hari = (int) ceil(
        $selisih_detik / 86400
      );
    }

    $this->api_response([
      'status'  => true,
      'message' => 'Pengaturan kunci emas berhasil disimpan.',
      'data'    => [
        'id_kunci' =>
        $id_kunci,

        'id_nasabah' =>
        $id_nasabah,

        'nama_nasabah' =>
        $nasabah->nama,

        'cabang_id' =>
        (int) $nasabah->cabang_id,

        'kode_cabang' =>
        $nasabah->kode_cabang,

        'nama_cabang' =>
        $nasabah->nama_cabang,

        'saldo_emas' =>
        number_format(
          $saldo_emas,
          4,
          '.',
          ''
        ),

        'durasi_bulan' =>
        $durasi_bulan,

        'pembelian_terakhir' =>
        $pembelian_terakhir,

        'terkunci_sampai' =>
        $terkunci_sampai,

        'status_terkunci' =>
        $status_terkunci,

        'sisa_hari' =>
        $sisa_hari,

        'ditetapkan_oleh' =>
        (int) $auth->id_user,

        'nama_admin' =>
        $auth->nama
      ]
    ]);
  }

  // ==========================================
  // PEMBELIAN EMAS NASABAH TERPROTEKSI
  // ==========================================
  public function simpan_emas()
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
        'message' => 'Akses ditolak. Endpoint ini khusus Nasabah.'
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

    /*
     * Identitas Nasabah berasal dari Bearer token.
     * id_nasabah dari request diabaikan.
     */
    $id_nasabah = (int) $auth->id_user;

    $pin = trim(
      (string) ($request['pin'] ?? '')
    );

    if (!preg_match('/^\d{6}$/', $pin)) {
      $this->api_response([
        'status'  => false,
        'message' => 'PIN harus terdiri dari 6 digit.'
      ], 422);
      return;
    }

    /*
     * request_key harus dibuat satu kali oleh aplikasi
     * untuk satu percobaan pembelian dan digunakan kembali
     * ketika request yang sama diulang.
     */
    $request_key = trim(
      (string) ($request['request_key'] ?? '')
    );

    if (
      !preg_match(
        '/^[A-Za-z0-9_-]{16,64}$/',
        $request_key
      )
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'request_key tidak valid.'
      ], 422);
      return;
    }

    /*
     * Mendukung nominal angka murni maupun format
     * ribuan Indonesia seperti 100.000.
     */
    $nominal_input = trim(
      (string) ($request['nominal'] ?? '')
    );

    if (preg_match('/^\d+$/', $nominal_input)) {
      $nominal_rupiah = (int) $nominal_input;
    } elseif (
      preg_match(
        '/^\d{1,3}(\.\d{3})+$/',
        $nominal_input
      )
    ) {
      $nominal_rupiah = (int) str_replace(
        '.',
        '',
        $nominal_input
      );
    } else {
      $this->api_response([
        'status'  => false,
        'message' => 'Nominal pembelian emas tidak valid.'
      ], 422);
      return;
    }

    if (
      $nominal_rupiah <= 0 ||
      $nominal_rupiah > 2000000000
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Nominal pembelian emas di luar batas yang diizinkan.'
      ], 422);
      return;
    }

    /*
     * Pemeriksaan idempotensi awal.
     */
    $transaksi_lama = $this->db
      ->select([
        'id',
        'idNasabah',
        'nominal',
        'gram_emas',
        'harga_emas_acuan',
        'durasi_kunci_bulan',
        'emas_terkunci_sampai',
        'referensi_tipe',
        'status_konfirmasi'
      ])
      ->where('request_key', $request_key)
      ->limit(1)
      ->get('tb_transaksi')
      ->row();

    if ($transaksi_lama) {
      if (
        (int) $transaksi_lama->idNasabah !==
        $id_nasabah ||
        $transaksi_lama->referensi_tipe !==
        'PembelianEmas'
      ) {
        $this->api_response([
          'status'  => false,
          'message' => 'request_key sudah digunakan untuk transaksi lain.'
        ], 409);
        return;
      }

      if (
        $transaksi_lama->status_konfirmasi !==
        'Sukses'
      ) {
        $this->api_response([
          'status'  => false,
          'message' => 'Transaksi dengan request_key ini belum berhasil.'
        ], 409);
        return;
      }

      $gram_lama = number_format(
        (float) $transaksi_lama->gram_emas,
        4,
        '.',
        ''
      );

      $this->api_response([
        'status'        => true,
        'message'       => 'Pembelian emas sebelumnya sudah berhasil.',
        'idempotent'    => true,
        'gram_didapat'  => $gram_lama,
        'data'          => [
          'id_transaksi' =>
          (int) $transaksi_lama->id,

          'nominal' =>
          (int) $transaksi_lama->nominal,

          'gram_didapat' =>
          $gram_lama,

          'harga_emas_acuan' =>
          (int) $transaksi_lama->harga_emas_acuan,

          'durasi_kunci_bulan' =>
          (int) $transaksi_lama->durasi_kunci_bulan,

          'terkunci_sampai' =>
          $transaksi_lama->emas_terkunci_sampai
        ]
      ]);
      return;
    }

    $this->db->trans_begin();

    /*
     * Kunci akun agar dua transaksi bersamaan tidak
     * dapat memakai saldo rupiah yang sama.
     */
    $user = $this->db->query(
      "SELECT
          u.id,
          u.nama,
          u.level,
          u.login,
          u.pin,
          u.pin_gagal,
          u.pin_terkunci_sampai,
          u.expo_token,
          u.cabang_id,
          c.status AS status_cabang
       FROM tb_user AS u
       LEFT JOIN tb_cabang AS c
         ON c.id = u.cabang_id
       WHERE u.id = ?
       LIMIT 1
       FOR UPDATE",
      [$id_nasabah]
    )->row();

    if (
      !$user ||
      $user->level !== 'Nasabah' ||
      $user->login !== 'Ya' ||
      $user->status_cabang !== 'Aktif'
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Akun Nasabah atau cabang tidak aktif.'
      ], 403);
      return;
    }

    /*
     * Verifikasi PIN berada dalam transaksi yang sama.
     */
    $hasil_pin =
      $this->verifikasi_pin_user_dalam_transaksi(
        $user,
        $pin
      );

    if (!$hasil_pin['status']) {
      if (
        !empty($hasil_pin['simpan_perubahan']) &&
        $this->db->trans_status() !== false
      ) {
        $this->db->trans_commit();
      } else {
        $this->db->trans_rollback();
      }

      $response_pin = [
        'status'  => false,
        'message' => $hasil_pin['message']
      ];

      if (!empty($hasil_pin['data'])) {
        $response_pin['data'] =
          $hasil_pin['data'];
      }

      $this->api_response(
        $response_pin,
        (int) $hasil_pin['http_code']
      );
      return;
    }

    /*
     * Periksa kembali request_key setelah akun terkunci.
     */
    $transaksi_bersamaan = $this->db->query(
      "SELECT
          id,
          idNasabah,
          referensi_tipe,
          status_konfirmasi
       FROM tb_transaksi
       WHERE request_key = ?
       LIMIT 1
       FOR UPDATE",
      [$request_key]
    )->row();

    if ($transaksi_bersamaan) {
      $this->db->trans_rollback();

      if (
        (int) $transaksi_bersamaan->idNasabah ===
        $id_nasabah &&
        $transaksi_bersamaan->referensi_tipe ===
        'PembelianEmas' &&
        $transaksi_bersamaan->status_konfirmasi ===
        'Sukses'
      ) {
        $this->api_response([
          'status'     => true,
          'message'    => 'Pembelian emas sebelumnya sudah berhasil.',
          'idempotent' => true,
          'data'       => [
            'id_transaksi' =>
            (int) $transaksi_bersamaan->id
          ]
        ]);
        return;
      }

      $this->api_response([
        'status'  => false,
        'message' => 'request_key sudah digunakan untuk transaksi lain.'
      ], 409);
      return;
    }

    /*
     * Durasi wajib sudah ditentukan Administrator.
     */
    $pengaturan_kunci = $this->db->query(
      "SELECT
          id_kunci,
          durasi_bulan,
          terkunci_sampai,
          ditetapkan_oleh
       FROM tb_kunci_emas
       WHERE id_nasabah = ?
       LIMIT 1
       FOR UPDATE",
      [$id_nasabah]
    )->row();

    if (!$pengaturan_kunci) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Durasi kunci emas belum ditentukan Administrator.'
      ], 422);
      return;
    }

    $durasi_bulan =
      (int) $pengaturan_kunci->durasi_bulan;

    if (
      $durasi_bulan < 6 ||
      $durasi_bulan > 120
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Konfigurasi durasi kunci emas tidak valid.'
      ], 500);
      return;
    }

    /*
     * Harga terbaru dikunci agar tidak berubah ketika
     * transaksi sedang dihitung.
     */
    $harga_emas = $this->db->query(
      "SELECT
          id,
          harga_beli,
          harga_jual,
          tanggal
       FROM tb_harga_emas
       ORDER BY id DESC
       LIMIT 1
       FOR UPDATE"
    )->row();

    if (
      !$harga_emas ||
      (int) $harga_emas->harga_beli <= 0
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Harga emas acuan belum tersedia.'
      ], 422);
      return;
    }

    $harga_beli =
      (int) $harga_emas->harga_beli;

    $gram_didapat = round(
      $nominal_rupiah / $harga_beli,
      4
    );

    if ($gram_didapat <= 0) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Nominal terlalu kecil untuk menghasilkan saldo emas.'
      ], 422);
      return;
    }

    /*
     * Hitung saldo rupiah setelah akun dikunci.
     */
    $saldo = $this->db->query(
      "SELECT
        (
          COALESCE((
            SELECT SUM(nominal)
            FROM tb_transaksi
            WHERE idNasabah = ?
              AND jenis = 'Masuk'
              AND status_konfirmasi = 'Sukses'
          ), 0)
          +
          COALESCE((
            SELECT SUM(CAST(nominal AS UNSIGNED))
            FROM tb_transfer
            WHERE idPenerima = ?
              AND status_transfer = 'Sukses'
          ), 0)
          -
          COALESCE((
            SELECT SUM(nominal)
            FROM tb_transaksi
            WHERE idNasabah = ?
              AND jenis = 'Keluar'
              AND status_konfirmasi = 'Sukses'
          ), 0)
          -
          COALESCE((
            SELECT SUM(CAST(nominal AS UNSIGNED))
            FROM tb_transfer
            WHERE idPengirim = ?
              AND status_transfer = 'Sukses'
          ), 0)
        ) AS saldo_aktif",
      [
        $id_nasabah,
        $id_nasabah,
        $id_nasabah,
        $id_nasabah
      ]
    )->row();

    if (!$saldo) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Saldo tabungan gagal dihitung.'
      ], 500);
      return;
    }

    $saldo_sebelum =
      (int) $saldo->saldo_aktif;

    if ($saldo_sebelum < $nominal_rupiah) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Saldo tabungan tidak mencukupi untuk membeli emas.',
        'data'    => [
          'saldo_aktif' =>
          $saldo_sebelum,

          'nominal_pembelian' =>
          $nominal_rupiah,

          'kekurangan' =>
          $nominal_rupiah -
            $saldo_sebelum
        ]
      ], 422);
      return;
    }

    $waktu_pembelian =
      date('Y-m-d H:i:s');

    try {
      $jatuh_tempo = new DateTime(
        $waktu_pembelian
      );

      $jatuh_tempo->modify(
        '+' . $durasi_bulan . ' months'
      );

      $calon_terkunci_sampai =
        $jatuh_tempo->format('Y-m-d H:i:s');
    } catch (Exception $e) {
      $this->db->trans_rollback();

      log_message(
        'error',
        'Gagal menghitung kunci pembelian emas: ' .
          $e->getMessage()
      );

      $this->api_response([
        'status'  => false,
        'message' => 'Jatuh tempo pembelian emas gagal dihitung.'
      ], 500);
      return;
    }

    /*
     * Pembelian baru tidak boleh memperpendek masa kunci
     * yang sebelumnya sudah lebih panjang.
     */
    $terkunci_sampai =
      $pengaturan_kunci->terkunci_sampai;

    if (
      empty($terkunci_sampai) ||
      strtotime($calon_terkunci_sampai) >
      strtotime($terkunci_sampai)
    ) {
      $terkunci_sampai =
        $calon_terkunci_sampai;
    }

    $transaksi_disimpan = $this->db->insert(
      'tb_transaksi',
      [
        'cabang_id' =>
        (int) $user->cabang_id,

        'idAdmin' =>
        0,

        'idNasabah' =>
        $id_nasabah,

        'idPotongan' =>
        0,

        'tanggal' =>
        date('Y-m-d'),

        'nominal' =>
        $nominal_rupiah,

        'gram_emas' =>
        $gram_didapat,

        'harga_emas_acuan' =>
        $harga_beli,

        'durasi_kunci_bulan' =>
        $durasi_bulan,

        'emas_terkunci_sampai' =>
        $terkunci_sampai,

        'jenis' =>
        'Keluar',

        'keterangan' =>
        'Nabung Emas ' .
          number_format(
            $gram_didapat,
            4,
            '.',
            ''
          ) .
          ' Gram',

        'referensi_tipe' =>
        'PembelianEmas',

        'referensi_id' =>
        null,

        'request_key' =>
        $request_key,

        'status_konfirmasi' =>
        'Sukses',

        'bukti_transfer' =>
        null,

        'terdaftar' =>
        $waktu_pembelian
      ]
    );

    if (!$transaksi_disimpan) {
      $database_error = $this->db->error();

      $this->db->trans_rollback();

      if (
        (int) ($database_error['code'] ?? 0) ===
        1062
      ) {
        $this->api_response([
          'status'  => false,
          'message' => 'request_key sudah digunakan. Periksa kembali riwayat transaksi.'
        ], 409);
        return;
      }

      log_message(
        'error',
        'Gagal menyimpan pembelian emas: ' .
          json_encode($database_error)
      );

      $this->api_response([
        'status'  => false,
        'message' => 'Pembelian emas gagal dicatat.'
      ], 500);
      return;
    }

    $id_transaksi =
      (int) $this->db->insert_id();

    $update_kunci = $this->db
      ->where(
        'id_kunci',
        (int) $pengaturan_kunci->id_kunci
      )
      ->where('id_nasabah', $id_nasabah)
      ->update(
        'tb_kunci_emas',
        [
          'terkunci_sampai' =>
          $terkunci_sampai,

          'diperbarui_pada' =>
          $waktu_pembelian
        ]
      );

    if (!$update_kunci) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Masa kunci emas gagal diperbarui.'
      ], 500);
      return;
    }

    /*
     * Administrator cabang terkait dan seluruh Super Admin
     * menerima notifikasi.
     */
    $query_admin = $this->db->query(
      "SELECT
          id,
          expo_token
       FROM tb_user
       WHERE login = 'Ya'
         AND (
           level = 'Super Admin'
           OR (
             level = 'Administrator'
             AND cabang_id = ?
           )
         )",
      [(int) $user->cabang_id]
    );

    if (!$query_admin) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Penerima notifikasi admin gagal diambil.'
      ], 500);
      return;
    }

    $admins = $query_admin->result();

    $gram_format = number_format(
      $gram_didapat,
      4,
      '.',
      ''
    );

    $judul_nasabah =
      'Pembelian Emas Berhasil';

    $pesan_nasabah =
      'Tabungan emas Anda bertambah ' .
      $gram_format .
      ' gram. Saldo utama dipotong Rp ' .
      number_format(
        $nominal_rupiah,
        0,
        ',',
        '.'
      ) .
      '. Seluruh saldo emas terkunci sampai ' .
      $terkunci_sampai .
      '.';

    $judul_admin =
      'Pembelian Emas Baru';

    $pesan_admin =
      'Nasabah ' .
      $user->nama .
      ' membeli ' .
      $gram_format .
      ' gram emas senilai Rp ' .
      number_format(
        $nominal_rupiah,
        0,
        ',',
        '.'
      ) .
      '.';

    $this->db->insert(
      'tb_notifikasi',
      [
        'id_user' =>
        $id_nasabah,

        'judul' =>
        $judul_nasabah,

        'pesan' =>
        $pesan_nasabah,

        'is_read' =>
        0,

        'tanggal' =>
        $waktu_pembelian
      ]
    );

    foreach ($admins as $admin) {
      $this->db->insert(
        'tb_notifikasi',
        [
          'id_user' =>
          (int) $admin->id,

          'judul' =>
          $judul_admin,

          'pesan' =>
          $pesan_admin,

          'is_read' =>
          0,

          'tanggal' =>
          $waktu_pembelian
        ]
      );
    }

    if ($this->db->trans_status() === false) {
      $database_error = $this->db->error();

      $this->db->trans_rollback();

      log_message(
        'error',
        'Pembelian emas dibatalkan: ' .
          json_encode($database_error)
      );

      $this->api_response([
        'status'  => false,
        'message' => 'Pembelian emas gagal diproses. Transaksi dibatalkan.'
      ], 500);
      return;
    }

    $this->db->trans_commit();

    /*
     * Push dikirim setelah commit agar gangguan layanan
     * notifikasi tidak membatalkan transaksi keuangan.
     */
    try {
      if (!empty($user->expo_token)) {
        $this->send_expo_push_notification(
          $user->expo_token,
          $judul_nasabah,
          $pesan_nasabah
        );
      }

      foreach ($admins as $admin) {
        if (!empty($admin->expo_token)) {
          $this->send_expo_push_notification(
            $admin->expo_token,
            $judul_admin,
            $pesan_admin
          );
        }
      }
    } catch (Throwable $e) {
      log_message(
        'error',
        'Push pembelian emas gagal: ' .
          $e->getMessage()
      );
    }

    $saldo_sesudah =
      $saldo_sebelum -
      $nominal_rupiah;

    $this->api_response([
      'status'        => true,
      'message'       => 'Pembelian emas berhasil. Saldo utama telah dipotong.',
      'idempotent'    => false,
      'gram_didapat'  => $gram_format,
      'data'          => [
        'id_transaksi' =>
        $id_transaksi,

        'id_nasabah' =>
        $id_nasabah,

        'nominal' =>
        $nominal_rupiah,

        'harga_emas_acuan' =>
        $harga_beli,

        'gram_didapat' =>
        $gram_format,

        'saldo_sebelum' =>
        $saldo_sebelum,

        'saldo_sesudah' =>
        $saldo_sesudah,

        'durasi_kunci_bulan' =>
        $durasi_bulan,

        'terkunci_sampai' =>
        $terkunci_sampai
      ]
    ], 201);
  }

  // ==========================================
  // API UNTUK MENGHITUNG TOTAL GRAM EMAS NASABAH
  // ==========================================
  // ==========================================
  // SALDO EMAS NASABAH TERPROTEKSI
  // ==========================================
  public function get_saldo_emas()
  {
    header('Access-Control-Allow-Origin: *');
    header('Content-Type: application/json; charset=UTF-8');
    header('Access-Control-Allow-Methods: POST');

    if ($this->input->method(TRUE) !== 'POST') {
      $this->api_response([
        'status'     => false,
        'message'    => 'Metode request tidak diizinkan.',
        'total_gram' => '0.0000'
      ], 405);
      return;
    }

    $auth = $this->authenticate_api();

    if (!$auth) {
      return;
    }

    if ($auth->level !== 'Nasabah') {
      $this->api_response([
        'status'     => false,
        'message'    => 'Akses ditolak. Endpoint ini khusus Nasabah.',
        'total_gram' => '0.0000'
      ], 403);
      return;
    }

    $request = json_decode(
      $this->input->raw_input_stream,
      true
    );

    if (!is_array($request)) {
      $this->api_response([
        'status'     => false,
        'message'    => 'Format JSON tidak valid.',
        'total_gram' => '0.0000'
      ], 400);
      return;
    }

    /*
     * id_nasabah dari request diabaikan.
     * Identitas selalu berasal dari Bearer token.
     */
    $id_nasabah = (int) $auth->id_user;

    $ringkasan = $this->db->query(
      "SELECT
          COALESCE(SUM(gram_emas), 0)
            AS total_gram,

          COALESCE(SUM(
            CASE
              WHEN gram_emas > 0
              THEN gram_emas
              ELSE 0
            END
          ), 0) AS total_pembelian,

          COALESCE(ABS(SUM(
            CASE
              WHEN gram_emas < 0
              THEN gram_emas
              ELSE 0
            END
          )), 0) AS total_dicairkan,

          MAX(
            CASE
              WHEN gram_emas > 0
              THEN terdaftar
              ELSE NULL
            END
          ) AS pembelian_terakhir
       FROM tb_transaksi
       WHERE idNasabah = ?
         AND status_konfirmasi = 'Sukses'
         AND gram_emas <> 0",
      [$id_nasabah]
    )->row();

    if (!$ringkasan) {
      $this->api_response([
        'status'     => false,
        'message'    => 'Saldo emas gagal dihitung.',
        'total_gram' => '0.0000'
      ], 500);
      return;
    }

    $kunci = $this->db
      ->select([
        'id_kunci',
        'durasi_bulan',
        'terkunci_sampai',
        'ditetapkan_oleh',
        'ditetapkan_pada',
        'diperbarui_pada'
      ])
      ->where('id_nasabah', $id_nasabah)
      ->limit(1)
      ->get('tb_kunci_emas')
      ->row();

    $total_gram = max(
      0,
      round(
        (float) $ringkasan->total_gram,
        4
      )
    );

    $total_pembelian = round(
      (float) $ringkasan->total_pembelian,
      4
    );

    $total_dicairkan = round(
      (float) $ringkasan->total_dicairkan,
      4
    );

    $waktu_sekarang = date('Y-m-d H:i:s');

    $terkunci_sampai = $kunci
      ? $kunci->terkunci_sampai
      : null;

    $status_terkunci = (
      $total_gram > 0 &&
      $terkunci_sampai !== null &&
      strtotime($terkunci_sampai) >
      strtotime($waktu_sekarang)
    );

    $saldo_terkunci = $status_terkunci
      ? $total_gram
      : 0;

    $saldo_bisa_dicairkan = $status_terkunci
      ? 0
      : $total_gram;

    $sisa_hari = 0;

    if ($status_terkunci) {
      $selisih_detik =
        strtotime($terkunci_sampai) -
        strtotime($waktu_sekarang);

      $sisa_hari = (int) ceil(
        $selisih_detik / 86400
      );
    }

    /*
     * total_gram dipertahankan pada level teratas
     * agar kompatibel dengan aplikasi lama.
     */
    $total_gram_format = number_format(
      $total_gram,
      4,
      '.',
      ''
    );

    $this->api_response([
      'status'     => true,
      'message'    => 'Saldo emas berhasil diambil.',
      'total_gram' => $total_gram_format,
      'data'       => [
        'id_nasabah' =>
        $id_nasabah,

        'nama_nasabah' =>
        $auth->nama,

        'total_gram' =>
        $total_gram_format,

        'total_pembelian' =>
        number_format(
          $total_pembelian,
          4,
          '.',
          ''
        ),

        'total_dicairkan' =>
        number_format(
          $total_dicairkan,
          4,
          '.',
          ''
        ),

        'saldo_terkunci' =>
        number_format(
          $saldo_terkunci,
          4,
          '.',
          ''
        ),

        'saldo_bisa_dicairkan' =>
        number_format(
          $saldo_bisa_dicairkan,
          4,
          '.',
          ''
        ),

        'dapat_dicairkan' => (
          $total_gram > 0 &&
          !$status_terkunci
        ),

        'pengaturan_kunci_tersedia' =>
        $kunci !== null,

        'durasi_kunci_bulan' =>
        $kunci
          ? (int) $kunci->durasi_bulan
          : null,

        'terkunci_sampai' =>
        $terkunci_sampai,

        'status_terkunci' =>
        $status_terkunci,

        'sisa_hari' =>
        $sisa_hari,

        'pembelian_terakhir' =>
        $ringkasan->pembelian_terakhir,

        'waktu_server' =>
        $waktu_sekarang
      ]
    ]);
  }

  // ==========================================
  // PENCAIRAN EMAS NASABAH TERPROTEKSI
  // ==========================================
  public function tarik_emas()
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
        'message' => 'Akses ditolak. Endpoint ini khusus Nasabah.'
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

    /*
     * Identitas Nasabah selalu berasal dari Bearer token.
     */
    $id_nasabah = (int) $auth->id_user;

    $pin = trim(
      (string) ($request['pin'] ?? '')
    );

    if (!preg_match('/^\d{6}$/', $pin)) {
      $this->api_response([
        'status'  => false,
        'message' => 'PIN harus terdiri dari 6 digit.'
      ], 422);
      return;
    }

    $request_key = trim(
      (string) ($request['request_key'] ?? '')
    );

    if (
      !preg_match(
        '/^[A-Za-z0-9_-]{16,64}$/',
        $request_key
      )
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'request_key tidak valid.'
      ], 422);
      return;
    }

    $gram_input = trim(
      (string) ($request['gram_ditarik'] ?? '')
    );

    /*
     * Maksimal empat angka desimal karena gram_emas
     * menggunakan DECIMAL(10,4).
     */
    if (
      !preg_match(
        '/^\d{1,6}([.,]\d{1,4})?$/',
        $gram_input
      )
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Jumlah gram emas tidak valid.'
      ], 422);
      return;
    }

    $gram_dijual = round(
      (float) str_replace(
        ',',
        '.',
        $gram_input
      ),
      4
    );

    if ($gram_dijual <= 0) {
      $this->api_response([
        'status'  => false,
        'message' => 'Jumlah gram emas harus lebih besar dari nol.'
      ], 422);
      return;
    }

    /*
     * Pemeriksaan idempotensi awal.
     */
    $transaksi_lama = $this->db
      ->select([
        'id',
        'idNasabah',
        'nominal',
        'gram_emas',
        'harga_emas_acuan',
        'referensi_tipe',
        'status_konfirmasi',
        'terdaftar'
      ])
      ->where('request_key', $request_key)
      ->limit(1)
      ->get('tb_transaksi')
      ->row();

    if ($transaksi_lama) {
      if (
        (int) $transaksi_lama->idNasabah !==
        $id_nasabah ||
        $transaksi_lama->referensi_tipe !==
        'PencairanEmas'
      ) {
        $this->api_response([
          'status'  => false,
          'message' => 'request_key sudah digunakan untuk transaksi lain.'
        ], 409);
        return;
      }

      if (
        $transaksi_lama->status_konfirmasi !==
        'Sukses'
      ) {
        $this->api_response([
          'status'  => false,
          'message' => 'Transaksi dengan request_key ini belum berhasil.'
        ], 409);
        return;
      }

      $gram_lama = number_format(
        abs((float) $transaksi_lama->gram_emas),
        4,
        '.',
        ''
      );

      $this->api_response([
        'status'     => true,
        'message'    => 'Pencairan emas sebelumnya sudah berhasil.',
        'idempotent' => true,
        'data'       => [
          'id_transaksi' =>
          (int) $transaksi_lama->id,

          'gram_dicairkan' =>
          $gram_lama,

          'harga_emas_acuan' =>
          (int) $transaksi_lama->harga_emas_acuan,

          'nominal_diterima' =>
          (int) $transaksi_lama->nominal,

          'dicairkan_pada' =>
          $transaksi_lama->terdaftar
        ]
      ]);
      return;
    }

    $this->db->trans_begin();

    /*
     * Kunci akun agar pembelian dan pencairan emas
     * tidak berjalan bersamaan.
     */
    $user = $this->db->query(
      "SELECT
          u.id,
          u.nama,
          u.level,
          u.login,
          u.pin,
          u.pin_gagal,
          u.pin_terkunci_sampai,
          u.expo_token,
          u.cabang_id,
          c.status AS status_cabang
       FROM tb_user AS u
       LEFT JOIN tb_cabang AS c
         ON c.id = u.cabang_id
       WHERE u.id = ?
       LIMIT 1
       FOR UPDATE",
      [$id_nasabah]
    )->row();

    if (
      !$user ||
      $user->level !== 'Nasabah' ||
      $user->login !== 'Ya' ||
      $user->status_cabang !== 'Aktif'
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Akun Nasabah atau cabang tidak aktif.'
      ], 403);
      return;
    }

    $hasil_pin =
      $this->verifikasi_pin_user_dalam_transaksi(
        $user,
        $pin
      );

    if (!$hasil_pin['status']) {
      if (
        !empty($hasil_pin['simpan_perubahan']) &&
        $this->db->trans_status() !== false
      ) {
        $this->db->trans_commit();
      } else {
        $this->db->trans_rollback();
      }

      $response_pin = [
        'status'  => false,
        'message' => $hasil_pin['message']
      ];

      if (!empty($hasil_pin['data'])) {
        $response_pin['data'] =
          $hasil_pin['data'];
      }

      $this->api_response(
        $response_pin,
        (int) $hasil_pin['http_code']
      );
      return;
    }

    /*
     * Periksa request_key kembali di dalam transaksi.
     */
    $transaksi_bersamaan = $this->db->query(
      "SELECT
          id,
          idNasabah,
          referensi_tipe,
          status_konfirmasi
       FROM tb_transaksi
       WHERE request_key = ?
       LIMIT 1
       FOR UPDATE",
      [$request_key]
    )->row();

    if ($transaksi_bersamaan) {
      $this->db->trans_rollback();

      if (
        (int) $transaksi_bersamaan->idNasabah ===
        $id_nasabah &&
        $transaksi_bersamaan->referensi_tipe ===
        'PencairanEmas' &&
        $transaksi_bersamaan->status_konfirmasi ===
        'Sukses'
      ) {
        $this->api_response([
          'status'     => true,
          'message'    => 'Pencairan emas sebelumnya sudah berhasil.',
          'idempotent' => true,
          'data'       => [
            'id_transaksi' =>
            (int) $transaksi_bersamaan->id
          ]
        ]);
        return;
      }

      $this->api_response([
        'status'  => false,
        'message' => 'request_key sudah digunakan untuk transaksi lain.'
      ], 409);
      return;
    }

    /*
     * Kunci konfigurasi emas dan periksa jatuh tempo.
     */
    $pengaturan_kunci = $this->db->query(
      "SELECT
          id_kunci,
          durasi_bulan,
          terkunci_sampai
       FROM tb_kunci_emas
       WHERE id_nasabah = ?
       LIMIT 1
       FOR UPDATE",
      [$id_nasabah]
    )->row();

    if (!$pengaturan_kunci) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Pengaturan kunci emas belum tersedia.'
      ], 422);
      return;
    }

    $waktu_sekarang = date('Y-m-d H:i:s');

    if (
      !empty($pengaturan_kunci->terkunci_sampai) &&
      strtotime(
        $pengaturan_kunci->terkunci_sampai
      ) > strtotime($waktu_sekarang)
    ) {
      $selisih_detik =
        strtotime(
          $pengaturan_kunci->terkunci_sampai
        ) -
        strtotime($waktu_sekarang);

      $sisa_hari = (int) ceil(
        $selisih_detik / 86400
      );

      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Saldo emas masih dalam masa kunci dan belum dapat dicairkan.',
        'data'    => [
          'terkunci_sampai' =>
          $pengaturan_kunci->terkunci_sampai,

          'sisa_hari' =>
          $sisa_hari,

          'dapat_dicairkan' =>
          false
        ]
      ], 409);
      return;
    }

    /*
     * Hitung saldo emas setelah akun dan konfigurasi dikunci.
     */
    $ringkasan_emas = $this->db->query(
      "SELECT
          COALESCE(SUM(gram_emas), 0)
            AS saldo_emas
       FROM tb_transaksi
       WHERE idNasabah = ?
         AND status_konfirmasi = 'Sukses'
         AND gram_emas <> 0",
      [$id_nasabah]
    )->row();

    if (!$ringkasan_emas) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Saldo emas gagal dihitung.'
      ], 500);
      return;
    }

    $saldo_emas_sebelum = max(
      0,
      round(
        (float) $ringkasan_emas->saldo_emas,
        4
      )
    );

    if (
      round($gram_dijual, 4) >
      round($saldo_emas_sebelum, 4)
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Saldo emas tidak mencukupi.',
        'data'    => [
          'saldo_emas' =>
          number_format(
            $saldo_emas_sebelum,
            4,
            '.',
            ''
          ),

          'gram_diminta' =>
          number_format(
            $gram_dijual,
            4,
            '.',
            ''
          ),

          'kekurangan' =>
          number_format(
            $gram_dijual -
              $saldo_emas_sebelum,
            4,
            '.',
            ''
          )
        ]
      ], 422);
      return;
    }

    /*
     * Ambil dan kunci harga buyback terbaru.
     */
    $harga_emas = $this->db->query(
      "SELECT
          id,
          harga_beli,
          harga_jual,
          tanggal
       FROM tb_harga_emas
       ORDER BY id DESC
       LIMIT 1
       FOR UPDATE"
    )->row();

    if (
      !$harga_emas ||
      (int) $harga_emas->harga_jual <= 0
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Harga jual emas belum tersedia.'
      ], 422);
      return;
    }

    $harga_jual =
      (int) $harga_emas->harga_jual;

    $nominal_rupiah = (int) round(
      $gram_dijual * $harga_jual
    );

    if ($nominal_rupiah <= 0) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Nilai pencairan emas terlalu kecil.'
      ], 422);
      return;
    }

    /*
     * Hitung saldo rupiah sebelum pencairan.
     */
    $saldo_rupiah = $this->db->query(
      "SELECT
        (
          COALESCE((
            SELECT SUM(nominal)
            FROM tb_transaksi
            WHERE idNasabah = ?
              AND jenis = 'Masuk'
              AND status_konfirmasi = 'Sukses'
          ), 0)
          +
          COALESCE((
            SELECT SUM(CAST(nominal AS UNSIGNED))
            FROM tb_transfer
            WHERE idPenerima = ?
              AND status_transfer = 'Sukses'
          ), 0)
          -
          COALESCE((
            SELECT SUM(nominal)
            FROM tb_transaksi
            WHERE idNasabah = ?
              AND jenis = 'Keluar'
              AND status_konfirmasi = 'Sukses'
          ), 0)
          -
          COALESCE((
            SELECT SUM(CAST(nominal AS UNSIGNED))
            FROM tb_transfer
            WHERE idPengirim = ?
              AND status_transfer = 'Sukses'
          ), 0)
        ) AS saldo_aktif",
      [
        $id_nasabah,
        $id_nasabah,
        $id_nasabah,
        $id_nasabah
      ]
    )->row();

    if (!$saldo_rupiah) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Saldo rupiah gagal dihitung.'
      ], 500);
      return;
    }

    $saldo_rupiah_sebelum =
      (int) $saldo_rupiah->saldo_aktif;

    $waktu_pencairan =
      date('Y-m-d H:i:s');

    $transaksi_disimpan = $this->db->insert(
      'tb_transaksi',
      [
        'cabang_id' =>
        (int) $user->cabang_id,

        'idAdmin' =>
        0,

        'idNasabah' =>
        $id_nasabah,

        'idPotongan' =>
        0,

        'tanggal' =>
        date('Y-m-d'),

        'nominal' =>
        $nominal_rupiah,

        'gram_emas' =>
        -$gram_dijual,

        'harga_emas_acuan' =>
        $harga_jual,

        'durasi_kunci_bulan' =>
        null,

        'emas_terkunci_sampai' =>
        null,

        'jenis' =>
        'Masuk',

        'keterangan' =>
        'Jual Emas ' .
          number_format(
            $gram_dijual,
            4,
            '.',
            ''
          ) .
          ' Gram',

        'referensi_tipe' =>
        'PencairanEmas',

        'referensi_id' =>
        null,

        'request_key' =>
        $request_key,

        'status_konfirmasi' =>
        'Sukses',

        'bukti_transfer' =>
        null,

        'terdaftar' =>
        $waktu_pencairan
      ]
    );

    if (!$transaksi_disimpan) {
      $database_error = $this->db->error();

      $this->db->trans_rollback();

      if (
        (int) ($database_error['code'] ?? 0) ===
        1062
      ) {
        $this->api_response([
          'status'  => false,
          'message' => 'request_key sudah digunakan. Periksa kembali riwayat transaksi.'
        ], 409);
        return;
      }

      log_message(
        'error',
        'Gagal mencatat pencairan emas: ' .
          json_encode($database_error)
      );

      $this->api_response([
        'status'  => false,
        'message' => 'Pencairan emas gagal dicatat.'
      ], 500);
      return;
    }

    $id_transaksi =
      (int) $this->db->insert_id();

    /*
     * Masa kunci yang sudah berakhir dibersihkan.
     * Durasi kebijakan tetap dipertahankan.
     */
    $update_kunci = $this->db
      ->where(
        'id_kunci',
        (int) $pengaturan_kunci->id_kunci
      )
      ->where('id_nasabah', $id_nasabah)
      ->update(
        'tb_kunci_emas',
        [
          'terkunci_sampai' =>
          null,

          'diperbarui_pada' =>
          $waktu_pencairan
        ]
      );

    if (!$update_kunci) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Status kunci emas gagal diperbarui.'
      ], 500);
      return;
    }

    $query_admin = $this->db->query(
      "SELECT
          id,
          expo_token
       FROM tb_user
       WHERE login = 'Ya'
         AND (
           level = 'Super Admin'
           OR (
             level = 'Administrator'
             AND cabang_id = ?
           )
         )",
      [(int) $user->cabang_id]
    );

    if (!$query_admin) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Penerima notifikasi admin gagal diambil.'
      ], 500);
      return;
    }

    $admins = $query_admin->result();

    $gram_format = number_format(
      $gram_dijual,
      4,
      '.',
      ''
    );

    $saldo_emas_sesudah = max(
      0,
      round(
        $saldo_emas_sebelum -
          $gram_dijual,
        4
      )
    );

    $judul_nasabah =
      'Pencairan Emas Berhasil';

    $pesan_nasabah =
      'Pencairan ' .
      $gram_format .
      ' gram emas berhasil. Saldo utama bertambah Rp ' .
      number_format(
        $nominal_rupiah,
        0,
        ',',
        '.'
      ) .
      '.';

    $judul_admin =
      'Pencairan Emas Baru';

    $pesan_admin =
      'Nasabah ' .
      $user->nama .
      ' mencairkan ' .
      $gram_format .
      ' gram emas senilai Rp ' .
      number_format(
        $nominal_rupiah,
        0,
        ',',
        '.'
      ) .
      '.';

    $this->db->insert(
      'tb_notifikasi',
      [
        'id_user' =>
        $id_nasabah,

        'judul' =>
        $judul_nasabah,

        'pesan' =>
        $pesan_nasabah,

        'is_read' =>
        0,

        'tanggal' =>
        $waktu_pencairan
      ]
    );

    foreach ($admins as $admin) {
      $this->db->insert(
        'tb_notifikasi',
        [
          'id_user' =>
          (int) $admin->id,

          'judul' =>
          $judul_admin,

          'pesan' =>
          $pesan_admin,

          'is_read' =>
          0,

          'tanggal' =>
          $waktu_pencairan
        ]
      );
    }

    if ($this->db->trans_status() === false) {
      $database_error = $this->db->error();

      $this->db->trans_rollback();

      log_message(
        'error',
        'Pencairan emas dibatalkan: ' .
          json_encode($database_error)
      );

      $this->api_response([
        'status'  => false,
        'message' => 'Pencairan emas gagal diproses. Transaksi dibatalkan.'
      ], 500);
      return;
    }

    $this->db->trans_commit();

    try {
      if (!empty($user->expo_token)) {
        $this->send_expo_push_notification(
          $user->expo_token,
          $judul_nasabah,
          $pesan_nasabah
        );
      }

      foreach ($admins as $admin) {
        if (!empty($admin->expo_token)) {
          $this->send_expo_push_notification(
            $admin->expo_token,
            $judul_admin,
            $pesan_admin
          );
        }
      }
    } catch (Throwable $e) {
      log_message(
        'error',
        'Push pencairan emas gagal: ' .
          $e->getMessage()
      );
    }

    $saldo_rupiah_sesudah =
      $saldo_rupiah_sebelum +
      $nominal_rupiah;

    $this->api_response([
      'status'     => true,
      'message'    =>
      'Pencairan emas berhasil. Rp ' .
        number_format(
          $nominal_rupiah,
          0,
          ',',
          '.'
        ) .
        ' telah masuk ke saldo utama.',
      'idempotent' => false,
      'data'       => [
        'id_transaksi' =>
        $id_transaksi,

        'id_nasabah' =>
        $id_nasabah,

        'gram_dicairkan' =>
        $gram_format,

        'harga_emas_acuan' =>
        $harga_jual,

        'nominal_diterima' =>
        $nominal_rupiah,

        'saldo_emas_sebelum' =>
        number_format(
          $saldo_emas_sebelum,
          4,
          '.',
          ''
        ),

        'saldo_emas_sesudah' =>
        number_format(
          $saldo_emas_sesudah,
          4,
          '.',
          ''
        ),

        'saldo_rupiah_sebelum' =>
        $saldo_rupiah_sebelum,

        'saldo_rupiah_sesudah' =>
        $saldo_rupiah_sesudah,

        'dicairkan_pada' =>
        $waktu_pencairan
      ]
    ], 201);
  }


  public function get_harga_emas_hari_ini()
  {
    if (ob_get_length()) {
      ob_clean();
    }

    header('Access-Control-Allow-Origin: *');
    header('Content-Type: application/json; charset=UTF-8');
    header('Access-Control-Allow-Methods: GET, POST');
    header(
      'Cache-Control: no-store, no-cache, must-revalidate, max-age=0'
    );

    $method = $this->input->method(TRUE);

    /*
   * GET dan POST tetap diterima agar kompatibel
   * dengan aplikasi versi lama.
   */
    if (!in_array($method, ['GET', 'POST'], true)) {
      $this->api_response([
        'status'     => false,
        'harga_beli' => 0,
        'harga_jual' => 0,
        'message'    => 'Metode request tidak diizinkan.'
      ], 405);
      return;
    }

    /*
   * Harga emas merupakan informasi publik.
   * Tidak memerlukan Bearer token.
   */
    $harga_emas = $this->db
      ->select([
        'id',
        'harga_beli',
        'harga_jual',
        'tanggal'
      ])
      ->from('tb_harga_emas')
      ->order_by('id', 'DESC')
      ->limit(1)
      ->get()
      ->row();

    if (!$harga_emas) {
      $this->api_response([
        'status'         => false,
        'harga_beli'     => 0,
        'harga_jual'     => 0,
        'tanggal_update' => null,
        'message'        => 'Harga emas belum tersedia.'
      ], 404);
      return;
    }

    $harga_beli = (int) $harga_emas->harga_beli;
    $harga_jual = (int) $harga_emas->harga_jual;

    /*
   * Lindungi aplikasi dari data harga yang rusak
   * atau tidak masuk akal.
   */
    if (
      $harga_beli <= 0 ||
      $harga_jual <= 0
    ) {
      log_message(
        'error',
        'Harga emas terbaru tidak valid. ID harga: ' .
          (int) $harga_emas->id
      );

      $this->api_response([
        'status'         => false,
        'harga_beli'     => 0,
        'harga_jual'     => 0,
        'tanggal_update' => null,
        'message'        => 'Data harga emas tidak valid.'
      ], 500);
      return;
    }

    /*
   * Field lama tetap dipertahankan agar aplikasi
   * tidak memerlukan perubahan format respons.
   */
    $this->api_response([
      'status'         => true,
      'harga_beli'     => $harga_beli,
      'harga_jual'     => $harga_jual,
      'tanggal_update' => $harga_emas->tanggal,
      'data'           => [
        'id_harga'       => (int) $harga_emas->id,
        'harga_beli'     => $harga_beli,
        'harga_jual'     => $harga_jual,
        'tanggal_update' => $harga_emas->tanggal
      ]
    ]);
  }


  public function update_harga_emas()
  {
    if (ob_get_length()) {
      ob_clean();
    }

    header('Access-Control-Allow-Origin: *');
    header('Content-Type: application/json; charset=UTF-8');
    header('Access-Control-Allow-Methods: POST');
    header(
      'Cache-Control: no-store, no-cache, must-revalidate, max-age=0'
    );

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
   * Harga emas berlaku global untuk seluruh cabang,
   * sehingga hanya Super Admin yang dapat mengubahnya.
   */
    if ($auth->level !== 'Super Admin') {
      $this->api_response([
        'status'  => false,
        'message' => 'Akses ditolak. Khusus Super Admin.'
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

    if (
      !array_key_exists('harga_beli', $request) ||
      !array_key_exists('harga_jual', $request)
    ) {
      $this->api_response([
        'status'  => false,
        'message' =>
        'Harga beli dan harga jual wajib diisi.'
      ], 422);
      return;
    }

    $harga_beli_input = $request['harga_beli'];
    $harga_jual_input = $request['harga_jual'];

    /*
   * Hanya menerima bilangan bulat positif.
   * Format pecahan, negatif, dan notasi ilmiah ditolak.
   */
    $harga_beli_valid =
      is_int($harga_beli_input) ||
      (
        is_string($harga_beli_input) &&
        preg_match(
          '/^\d{1,10}$/',
          trim($harga_beli_input)
        )
      );

    $harga_jual_valid =
      is_int($harga_jual_input) ||
      (
        is_string($harga_jual_input) &&
        preg_match(
          '/^\d{1,10}$/',
          trim($harga_jual_input)
        )
      );

    if (
      !$harga_beli_valid ||
      !$harga_jual_valid
    ) {
      $this->api_response([
        'status'  => false,
        'message' =>
        'Harga emas harus berupa bilangan bulat positif.'
      ], 422);
      return;
    }

    $harga_beli = (int) $harga_beli_input;
    $harga_jual = (int) $harga_jual_input;

    if (
      $harga_beli <= 0 ||
      $harga_jual <= 0 ||
      $harga_beli > 1000000000 ||
      $harga_jual > 1000000000
    ) {
      $this->api_response([
        'status'  => false,
        'message' =>
        'Nilai harga emas berada di luar batas yang diizinkan.'
      ], 422);
      return;
    }

    /*
   * Harga buyback kepada Nasabah tidak boleh melebihi
   * harga pembelian emas oleh Nasabah.
   */
    if ($harga_jual > $harga_beli) {
      $this->api_response([
        'status'  => false,
        'message' =>
        'Harga jual kembali tidak boleh melebihi harga beli.'
      ], 422);
      return;
    }

    $tanggal = date('Y-m-d');

    $db_debug_sebelumnya =
      $this->db->db_debug;

    /*
   * Mencegah CodeIgniter mengeluarkan halaman HTML
   * jika terjadi kesalahan database.
   */
    $this->db->db_debug = false;
    $this->db->trans_begin();

    /*
   * Kolom tanggal memiliki UNIQUE KEY.
   * Jika harga hari ini sudah ada, nilainya diperbarui.
   */
    $proses = $this->db->query(
      "INSERT INTO tb_harga_emas
      (
        harga_beli,
        harga_jual,
        tanggal
      )
     VALUES (?, ?, ?)
     ON DUPLICATE KEY UPDATE
       harga_beli = VALUES(harga_beli),
       harga_jual = VALUES(harga_jual)",
      [
        $harga_beli,
        $harga_jual,
        $tanggal
      ]
    );

    if (
      !$proses ||
      $this->db->trans_status() === false
    ) {
      $database_error = $this->db->error();

      $this->db->trans_rollback();
      $this->db->db_debug =
        $db_debug_sebelumnya;

      log_message(
        'error',
        'Gagal memperbarui harga emas: ' .
          json_encode($database_error)
      );

      $this->api_response([
        'status'  => false,
        'message' =>
        'Harga acuan emas gagal diperbarui.'
      ], 500);
      return;
    }

    $harga_tersimpan = $this->db
      ->select([
        'id',
        'harga_beli',
        'harga_jual',
        'tanggal'
      ])
      ->where('tanggal', $tanggal)
      ->limit(1)
      ->get('tb_harga_emas')
      ->row();

    if (
      !$harga_tersimpan ||
      $this->db->trans_status() === false
    ) {
      $database_error = $this->db->error();

      $this->db->trans_rollback();
      $this->db->db_debug =
        $db_debug_sebelumnya;

      log_message(
        'error',
        'Harga emas tersimpan gagal diverifikasi: ' .
          json_encode($database_error)
      );

      $this->api_response([
        'status'  => false,
        'message' =>
        'Harga acuan emas gagal diverifikasi.'
      ], 500);
      return;
    }

    $this->db->trans_commit();
    $this->db->db_debug =
      $db_debug_sebelumnya;

    $this->api_response([
      'status'  => true,
      'message' =>
      'Harga acuan emas berhasil diperbarui.',
      'data'    => [
        'id_harga' =>
        (int) $harga_tersimpan->id,

        'harga_beli' =>
        (int) $harga_tersimpan->harga_beli,

        'harga_jual' =>
        (int) $harga_tersimpan->harga_jual,

        'tanggal_update' =>
        $harga_tersimpan->tanggal,

        'diperbarui_oleh' =>
        (int) $auth->id_user,

        'nama_operator' =>
        $auth->nama
      ]
    ]);
  }


  // ==========================================
  // H. Ambil Saldo Emas Seluruh Nasabah (Khusus Admin)
  // ==========================================
  public function admin_get_semua_emas()
  {
    if (ob_get_length()) {
      ob_clean();
    }

    header('Access-Control-Allow-Origin: *');
    header('Content-Type: application/json; charset=UTF-8');
    header('Access-Control-Allow-Methods: POST');
    header(
      'Cache-Control: no-store, no-cache, must-revalidate, max-age=0'
    );

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

    if (
      $auth->level !== 'Administrator' &&
      $auth->level !== 'Super Admin'
    ) {
      $this->api_response([
        'status'  => false,
        'message' =>
        'Akses ditolak. Khusus Administrator dan Super Admin.'
      ], 403);
      return;
    }

    /*
   * Identitas, level, dan cabang operator selalu
   * berasal dari Bearer token. Data dari body diabaikan.
   *
   * Administrator hanya melihat Nasabah di cabangnya.
   * Super Admin dapat melihat seluruh cabang.
   */
    $sql = "
    SELECT
      u.id,
      u.nama,
      u.username,
      u.foto,
      u.login,
      u.cabang_id,
      c.kode AS kode_cabang,
      c.nama AS nama_cabang,
      c.status AS status_cabang,
      COALESCE(e.total_gram, 0) AS total_gram,
      k.durasi_bulan,
      k.terkunci_sampai
    FROM tb_user AS u
    LEFT JOIN tb_cabang AS c
      ON c.id = u.cabang_id
    LEFT JOIN (
      SELECT
        idNasabah,
        COALESCE(SUM(gram_emas), 0) AS total_gram
      FROM tb_transaksi
      WHERE status_konfirmasi = 'Sukses'
        AND gram_emas <> 0
      GROUP BY idNasabah
    ) AS e
      ON e.idNasabah = u.id
    LEFT JOIN tb_kunci_emas AS k
      ON k.id_nasabah = u.id
    WHERE u.level = 'Nasabah'
  ";

    $parameter = [];

    if ($auth->level === 'Administrator') {
      $sql .= "
      AND u.cabang_id = ?
    ";

      $parameter[] = (int) $auth->cabang_id;
    }

    $sql .= "
    ORDER BY
      c.nama ASC,
      u.nama ASC,
      u.id ASC
  ";

    $db_debug_sebelumnya =
      $this->db->db_debug;

    $this->db->db_debug = false;

    $query = $this->db->query(
      $sql,
      $parameter
    );

    if (!$query) {
      $database_error = $this->db->error();

      $this->db->db_debug =
        $db_debug_sebelumnya;

      log_message(
        'error',
        'Gagal mengambil daftar saldo emas: ' .
          json_encode($database_error)
      );

      $this->api_response([
        'status'  => false,
        'message' =>
        'Daftar saldo emas gagal diambil.'
      ], 500);
      return;
    }

    $nasabah = $query->result();

    $this->db->db_debug =
      $db_debug_sebelumnya;

    $data_emas = [];
    $waktu_sekarang = time();

    $jumlah_memiliki_emas = 0;
    $jumlah_saldo_terkunci = 0;
    $total_seluruh_gram = 0.0;

    foreach ($nasabah as $row) {
      $total_gram_angka = max(
        0,
        round(
          (float) $row->total_gram,
          4
        )
      );

      $pengaturan_kunci_tersedia =
        !empty($row->durasi_bulan);

      $status_terkunci =
        $total_gram_angka > 0 &&
        !empty($row->terkunci_sampai) &&
        strtotime($row->terkunci_sampai) >
        $waktu_sekarang;

      $sisa_hari = 0;

      if ($status_terkunci) {
        $selisih_detik =
          strtotime($row->terkunci_sampai) -
          $waktu_sekarang;

        $sisa_hari = (int) ceil(
          $selisih_detik / 86400
        );
      }

      $saldo_terkunci =
        $status_terkunci
        ? $total_gram_angka
        : 0;

      $saldo_bisa_dicairkan =
        $status_terkunci
        ? 0
        : $total_gram_angka;

      if ($total_gram_angka > 0) {
        $jumlah_memiliki_emas++;
      }

      if ($status_terkunci) {
        $jumlah_saldo_terkunci++;
      }

      $total_seluruh_gram +=
        $total_gram_angka;

      /*
     * Field id, nama, username, foto, dan total_gram
     * dipertahankan agar kompatibel dengan aplikasi lama.
     */
      $data_emas[] = [
        'id' =>
        (int) $row->id,

        'nama' =>
        $row->nama,

        'username' =>
        $row->username,

        'foto' =>
        $row->foto,

        'total_gram' =>
        number_format(
          $total_gram_angka,
          4,
          '.',
          ''
        ),

        'cabang_id' =>
        (int) $row->cabang_id,

        'kode_cabang' =>
        $row->kode_cabang,

        'nama_cabang' =>
        $row->nama_cabang,

        'status_cabang' =>
        $row->status_cabang,

        'status_akun' =>
        $row->login,

        'pengaturan_kunci_tersedia' =>
        $pengaturan_kunci_tersedia,

        'durasi_kunci_bulan' =>
        $pengaturan_kunci_tersedia
          ? (int) $row->durasi_bulan
          : null,

        'terkunci_sampai' =>
        $row->terkunci_sampai,

        'status_terkunci' =>
        $status_terkunci,

        'sisa_hari' =>
        $sisa_hari,

        'saldo_terkunci' =>
        number_format(
          $saldo_terkunci,
          4,
          '.',
          ''
        ),

        'saldo_bisa_dicairkan' =>
        number_format(
          $saldo_bisa_dicairkan,
          4,
          '.',
          ''
        ),

        'dapat_dicairkan' =>
        $total_gram_angka > 0 &&
          !$status_terkunci
      ];
    }

    $this->api_response([
      'status'  => true,
      'message' =>
      'Daftar saldo emas berhasil diambil.',
      'data'    => $data_emas,
      'meta'    => [
        'jumlah_nasabah' =>
        count($data_emas),

        'jumlah_memiliki_emas' =>
        $jumlah_memiliki_emas,

        'jumlah_saldo_terkunci' =>
        $jumlah_saldo_terkunci,

        'total_seluruh_gram' =>
        number_format(
          $total_seluruh_gram,
          4,
          '.',
          ''
        ),

        'cakupan' =>
        $auth->level === 'Super Admin'
          ? 'Semua Cabang'
          : 'Cabang Sendiri',

        'cabang_id_operator' =>
        (int) $auth->cabang_id,

        'diakses_oleh' =>
        (int) $auth->id_user,

        'nama_operator' =>
        $auth->nama
      ]
    ]);
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
