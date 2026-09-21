Warning: truncated output (original token count: 143600)
Total output lines: 23931

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
         u.login AS status_akun,
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

    /*
     * Token lama tidak boleh tetap digunakan setelah akun
     * dinonaktifkan atau pendaftar ditolak. Cabut seluruh sesi
     * aktif pengguna agar token tidak hidup kembali jika akun
     * kemudian diaktifkan ulang.
     */
    if ($auth->status_akun !== 'Ya') {
      $waktu_pencabutan = date('Y-m-d H:i:s');

      $this->db
        ->where('id_user', (int) $auth->id_user)
        ->where('revoked_at IS NULL', null, false)
        ->update('tb_api_token', [
          'revoked_at' => $waktu_pencabutan
        ]);

      $this->api_response([
        'status'  => false,
        'message' => 'Akun sudah tidak aktif. Seluruh sesi login telah dicabut.'
      ], 403);

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

  /**
   * Menentukan cakupan cabang untuk menu pemantauan Administrator.
   *
   * Administrator selalu dikunci ke cabang pada Bearer token.
   * Super Admin boleh memilih satu cabang aktif atau memakai seluruh cabang
   * dengan mengirim cabang_id kosong/0.
   */
  private function resolve_admin_branch_scope($auth, $requested_cabang_id = 0)
  {
    if ($auth->level === 'Administrator') {
      return [
        'cabang_id'   => (int) $auth->cabang_id,
        'kode_cabang' => $auth->kode_cabang,
        'nama_cabang' => $auth->nama_cabang,
        'cakupan'     => 'Cabang sendiri'
      ];
    }

    if ($auth->level !== 'Super Admin') {
      $this->api_response([
        'status'  => false,
        'message' => 'Anda tidak memiliki izin untuk memilih cakupan cabang.'
      ], 403);
      return null;
    }

    $requested_cabang_id = (int) $requested_cabang_id;

    if ($requested_cabang_id <= 0) {
      return [
        'cabang_id'   => null,
        'kode_cabang' => null,
        'nama_cabang' => null,
        'cakupan'     => 'Semua cabang'
      ];
    }

    $cabang = $this->db
      ->select('id, kode, nama')
      ->where('id', $requested_cabang_id)
      ->where('status', 'Aktif')
      ->limit(1)
      ->get('tb_cabang')
      ->row();

    if (!$cabang) {
      $this->api_response([
        'status'  => false,
        'message' => 'Cabang yang dipilih tidak ditemukan atau sedang tidak aktif.'
      ], 422);
      return null;
    }

    return [
      'cabang_id'   => (int) $cabang->id,
      'kode_cabang' => $cabang->kode,
      'nama_cabang' => $cabang->nama,
      'cakupan'     => 'Cabang pilihan'
    ];
  }

  // ==========================================
  // 1. ENDPOINT LOGIN (SUDAH DENGAN FOTO)
  // ==========================================
  public function login()
  {
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');

    if ($this->input->method(TRUE) !== 'POST') {
      $this->api_response([
        'status'  => false,
        'message' => 'Gunakan metode POST.'
      ], 405);
      return;
    }

    $content_length = (int) $this->input->server(
      'CONTENT_LENGTH'
    );

    if ($content_length > 8192) {
      $this->api_response([
        'status'  => false,
        'message' => 'Ukuran permintaan login terlalu besar.'
      ], 413);
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

    $username = trim((string) ($request['username'] ?? ''));
    $password = (string) ($request['password'] ?? '');
    $device = trim((string) (
      $request['device'] ?? 'Perangkat tidak diketahui'
    ));

    if ($username === '' || $password === '') {
      $this->api_response([
        'status'  => false,
        'message' => 'Username dan password harus diisi.'
      ], 422);
      return;
    }

    if (
      mb_strlen($username) > 256 ||
      strlen($password) > 1024
    ) {
      /*
       * Pesan dibuat sama agar keberadaan username
       * tidak dapat ditebak dari validasi panjang.
       */
      $this->api_response([
        'status'  => false,
        'message' => 'Username atau password salah.'
      ], 401);
      return;
    }

    $username_normal = mb_strtolower(
      $username,
      'UTF-8'
    );

    /*
     * Username mentah tidak pernah dicatat pada log percobaan.
     */
    $username_hash = hash(
      'sha256',
      $username_normal
    );

    $ip_address = mb_substr(
      (string) $this->input->ip_address(),
      0,
      45
    );

    $user_agent_header =
      $this->input->get_request_header(
        'User-Agent',
        true
      );

    $user_agent = $user_agent_header
      ? mb_substr(
        (string) $user_agent_header,
        0,
        255
      )
      : null;

    $batas_waktu = date(
      'Y-m-d H:i:s',
      strtotime('-15 minutes')
    );

    /*
     * Hapus catatan kedaluwarsa agar tabel tidak tumbuh
     * tanpa batas. Data tujuh hari terakhir dipertahankan.
     */
    $this->db
      ->where(
        'dicoba_pada <',
        date(
          'Y-m-d H:i:s',
          strtotime('-7 days')
        )
      )
      ->delete('tb_login_attempt');

    $jumlah_kombinasi = $this->db
      ->where('username_hash', $username_hash)
      ->where('ip_address', $ip_address)
      ->where('dicoba_pada >=', $batas_waktu)
      ->count_all_results('tb_login_attempt');

    $jumlah_username = $this->db
      ->where('username_hash', $username_hash)
      ->where('dicoba_pada >=', $batas_waktu)
      ->count_all_results('tb_login_attempt');

    $jumlah_ip = $this->db
      ->where('ip_address', $ip_address)
      ->where('dicoba_pada >=', $batas_waktu)
      ->count_all_results('tb_login_attempt');

    if (
      $jumlah_kombinasi >= 5 ||
      $jumlah_username >= 10 ||
      $jumlah_ip >= 30
    ) {
      header('Retry-After: 900');

      $this->api_response([
        'status'  => false,
        'message' => 'Terlalu banyak percobaan login. Silakan coba kembali setelah 15 menit.',
        'data'    => [
          'coba_lagi_dalam_detik' => 900
        ]
      ], 429);
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
      $insert_attempt = $this->db->insert(
        'tb_login_attempt',
        [
          'username_hash' => $username_hash,
          'id_user'       => $user
            ? (int) $user->id
            : null,
          'ip_address'    => $ip_address,
          'user_agent'    => $user_agent,
          'dicoba_pada'   => date('Y-m-d H:i:s')
        ]
      );

      if (!$insert_attempt) {
        log_message(
          'error',
          'Gagal mencatat percobaan login dari IP ' .
            $ip_address
        );

        $this->api_response([
          'status'  => false,
          'message' => 'Layanan login sementara tidak tersedia.'
        ], 503);
        return;
      }

      $jumlah_kombinasi++;
      $jumlah_username++;
      $jumlah_ip++;

      if (
        $jumlah_kombinasi >= 5 ||
        $jumlah_username >= 10 ||
        $jumlah_ip >= 30
      ) {
        header('Retry-After: 900');

        $this->api_response([
          'status'  => false,
          'message' => 'Terlalu banyak percobaan login. Silakan coba kembali setelah 15 menit.',
          'data'    => [
            'coba_lagi_dalam_detik' => 900
          ]
        ], 429);
        return;
      }

      $this->api_response([
        'status'  => false,
        'message' => 'Username atau password salah.'
      ], 401);
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

      $this->api_response([
        'status'  => false,
        'message' => $message
      ], 403);

      return;
    }

    if (empty($user->cabang_id)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Akun belum terhubung dengan cabang.'
      ], 403);
      return;
    }

    if ($user->status_cabang !== 'Aktif') {
      $this->api_response([
        'status'  => false,
        'message' => 'Cabang akun Anda sedang tidak aktif.'
      ], 403);
      return;
    }

    $transaksi_login_dimulai = false;

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

      $this->db->trans_begin();
      $transaksi_login_dimulai = true;

      $token_disimpan = $this->db->insert(
        'tb_api_token',
        $dataToken
      );

      /*
       * Login berhasil menghapus kegagalan untuk username
       * tersebut. Catatan IP bagi username lain tetap ada.
       */
      $attempt_dibersihkan = $this->db
        ->where('username_hash', $username_hash)
        ->delete('tb_login_attempt');

      if (
        !$token_disimpan ||
        !$attempt_dibersihkan ||
        $this->db->trans_status() === false
      ) {
        $database_error = $this->db->error();
        $this->db->trans_rollback();

        log_message(
          'error',
          'Gagal membuat sesi login: ' .
            json_encode($database_error)
        );

        $this->api_response([
          'status'  => false,
          'message' => 'Gagal membuat sesi login.'
        ], 500);
        return;
      }

      $this->db->trans_commit();
      $transaksi_login_dimulai = false;

      $this->api_response([
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
          'is_pusat'       => (int) $user->is_pusat,
          'pin_wajib_diubah' =>
          $user->level === 'Nasabah' &&
            (int) $user->pin_wajib_diubah === 1,
          'pin_reset_kedaluwarsa' =>
          $user->level === 'Nasabah' &&
            (int) $user->pin_wajib_diubah === 1
            ? $user->pin_reset_kedaluwarsa
            : null
        ]
      ]);
    } catch (Throwable $e) {
      if ($transaksi_login_dimulai) {
        $this->db->trans_rollback();
      }

      log_message(
        'error',
        'Gagal membuat token API: ' .
          $e->getMessage()
      );

      $this->api_response([
        'status'  => false,
        'message' => 'Terjadi kesalahan saat membuat sesi login.'
      ], 500);
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

    $this->db->trans_begin();

    $this->db->where('id', $auth->token_id);
    $session_revoked = $this->db->update('tb_api_token', [
      'revoked_at' => date('Y-m-d H:i:s')
    ]);

    /*
     * Lepaskan Expo token saat logout agar perangkat yang sudah
     * keluar tidak lagi menerima notifikasi milik akun sebelumnya.
     */
    $this->db->where('id', (int) $auth->id_user);
    $notification_token_removed = $this->db->update('tb_user', [
      'expo_token' => null
    ]);

    if (
      !$session_revoked ||
      !$notification_token_removed ||
      $this->db->trans_status() === false
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Logout gagal diproses.'
      ], 500);

      return;
    }

    $this->db->trans_commit();

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
    $this->db->where('u.login', 'Ya');
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

    /*
     * Semua transaksi Setor (jenis Masuk) wajib mempunyai sedikitnya satu
     * rekening penampungan aktif pada cabang nasabah. Validasi server ini
     * tidak dapat dilewati dengan memanggil API secara manual.
     */
    if ($jenis === 'Masuk') {
      if (!$this->db->table_exists('tb_rekening_penampungan')) {
        $this->api_response([
          'status'  => false,
          'message' => 'Rekening penampungan belum dikonfigurasi.'
        ], 503);

        return;
      }

      $rekening_aktif = $this->db
        ->where('cabang_id', (int) $nasabah->cabang_id)
        ->where('status', 'Aktif')
        ->count_all_results('tb_rekening_penampungan');

      if ($rekening_aktif < 1) {
        $this->api_response([
          'status'  => false,
          'message' => 'Cabang nasabah belum memiliki rekening penampungan aktif.'
        ], 422);

        return;
      }
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

    if (
      !$insert ||
      $id_transaksi <= 0 ||
      $this->db->trans_status() === false
    ) {
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

    // Notifikasi dikirim setelah transaksi database selesai.
    if ($status_konfirmasi === 'Pending') {
      $jenis_teks = $jenis === 'Masuk'
        ? 'menabung'
        : 'penarikan';

      /*
       * Administrator cabang terkait dan seluruh Super Admin.
       */
      $this->db->select('id, expo_token');
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
  // QR TRANSFER INTERNAL ANTAR NASABAH
  // ==========================================
  private function _ambil_token_qr_transfer($nilai)
  {
    $nilai = trim((string) $nilai);
    if ($nilai === '') return null;
    if (preg_match('/^[A-Za-z0-9_-]{43}$/', $nilai)) return $nilai;

    $bagian = parse_url($nilai);
    if (!is_array($bagian)) return null;

    $query = [];
    parse_str((string) ($bagian['query'] ?? ''), $query);
    $token = trim((string) ($query['token'] ?? ''));
    return preg_match('/^[A-Za-z0-9_-]{43}$/', $token) ? $token : null;
  }

  public function buat_qr_transfer()
  {
    if ($this->input->method(TRUE) !== 'POST') {
      $this->api_response(['status' => false, 'message' => 'Gunakan metode POST.'], 405);
      return;
    }

    $auth = $this->authenticate_api();
    if (!$auth) return;

    if ($auth->level !== 'Nasabah') {
      $this->api_response(['status' => false, 'message' => 'QR Transfer hanya dapat dibuat oleh Nasabah.'], 403);
      return;
    }

    if (!$this->db->table_exists('tb_qr_transfer')) {
      $this->api_response(['status' => false, 'message' => 'Tabel QR Transfer belum dipasang.'], 503);
      return;
    }

    $request = json_decode($this->input->raw_input_stream, true);
    if (!is_array($request)) {
      $this->api_response(['status' => false, 'message' => 'Format permintaan tidak valid.'], 400);
      return;
    }

    $nominal_input = trim((string) ($request['nominal'] ?? ''));
    $nominal = null;
    if ($nominal_input !== '') {
      if (strpos($nominal_input, '-') !== false) {
        $this->api_response(['status' => false, 'message' => 'Nominal QR tidak valid.'], 422);
        return;
      }
      $nominal = (int) preg_replace('/[^0-9]/', '', $nominal_input);
      if ($nominal <= 0 || $nominal > 2147483647) {
        $this->api_response(['status' => false, 'message' => 'Nominal QR berada di luar batas.'], 422);
        return;
      }
    }

    $penerima = $this->db->query(
      "SELECT u.id, u.nama, u.login, u.level, u.cabang_id,
              c.kode AS kode_cabang, c.nama AS nama_cabang,
              c.status AS status_cabang
       FROM tb_user u
       INNER JOIN tb_cabang c ON c.id = u.cabang_id
       WHERE u.id = ? LIMIT 1",
      [(int) $auth->id_user]
    )->row();

    if (!$penerima || $penerima->level !== 'Nasabah' ||
        $penerima->login !== 'Ya' || $penerima->status_cabang !== 'Aktif') {
      $this->api_response(['status' => false, 'message' => 'Akun atau cabang Nasabah sedang tidak aktif.'], 403);
      return;
    }

    try {
      $token = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    } catch (Exception $e) {
      log_message('error', 'Token QR Transfer gagal dibuat: ' . $e->getMessage());
      $this->api_response(['status' => false, 'message' => 'QR Transfer gagal dibuat.'], 500);
      return;
    }

    $sekarang = date('Y-m-d H:i:s');
    $kedaluwarsa = date('Y-m-d H:i:s', strtotime('+10 minutes'));
    $this->db->trans_begin();

    $this->db
      ->where('id_penerima', (int) $auth->id_user)
      ->where('status', 'Aktif')
      ->update('tb_qr_transfer', ['status' => 'Dibatalkan']);

    $insert = $this->db->insert('tb_qr_transfer', [
      'token_hash' => hash('sha256', $token),
      'id_penerima' => (int) $auth->id_user,
      'nominal' => $nominal,
      'status' => 'Aktif',
      'kedaluwarsa_pada' => $kedaluwarsa,
      'dibuat_pada' => $sekarang
    ]);

    if (!$insert || $this->db->trans_status() === false) {
      $this->db->trans_rollback();
      $this->api_response(['status' => false, 'message' => 'QR Transfer gagal disimpan.'], 500);
      return;
    }

    $id_qr = (int) $this->db->insert_id();
    $this->db->trans_commit();
    $payload = 'tabunganmakmur://qr-transfer?token=' . rawurlencode($token);

    $this->api_response([
      'status' => true,
      'message' => 'QR Transfer berhasil dibuat dan berlaku selama 10 menit.',
      'data' => [
        'id_qr' => $id_qr,
        'qr_payload' => $payload,
        'nominal' => $nominal,
        'kedaluwarsa_pada' => $kedaluwarsa,
        'penerima' => [
          'nama' => $penerima->nama,
          'cabang_id' => (int) $penerima->cabang_id,
          'kode_cabang' => $penerima->kode_cabang,
          'nama_cabang' => $penerima->nama_cabang
        ]
      ]
    ], 201);
  }

  public function baca_qr_transfer()
  {
    if ($this->input->method(TRUE) !== 'POST') {
      $this->api_response(['status' => false, 'message' => 'Gunakan metode POST.'], 405);
      return;
    }

    $auth = $this->authenticate_api();
    if (!$auth) return;

    if ($auth->level !== 'Nasabah') {
      $this->api_response(['status' => false, 'message' => 'QR Transfer hanya dapat dipindai oleh Nasabah.'], 403);
      return;
    }

    if (!$this->db->table_exists('tb_qr_transfer')) {
      $this->api_response(['status' => false, 'message' => 'Tabel QR Transfer belum dipasang.'], 503);
      return;
    }

    $request = json_decode($this->input->raw_input_stream, true);
    if (!is_array($request)) {
      $this->api_response(['status' => false, 'message' => 'Format permintaan tidak valid.'], 400);
      return;
    }

    $token = $this->_ambil_token_qr_transfer(
      $request['qr_payload'] ?? ($request['token'] ?? '')
    );
    if ($token === null) {
      $this->api_response(['status' => false, 'message' => 'Kode QR Transfer tidak valid.'], 422);
      return;
    }

    $qr = $this->db->query(
      "SELECT q.id, q.id_penerima, q.nominal, q.status, q.kedaluwarsa_pada,
              u.nama AS nama_penerima, u.login AS status_akun, u.level,
              u.cabang_id, c.kode AS kode_cabang, c.nama AS nama_cabang,
              c.status AS status_cabang
       FROM tb_qr_transfer q
       INNER JOIN tb_user u ON u.id = q.id_penerima
       INNER JOIN tb_cabang c ON c.id = u.cabang_id
       WHERE q.token_hash = ? LIMIT 1",
      [hash('sha256', $token)]
    )->row();

    if (!$qr) {
      $this->api_response(['status' => false, 'message' => 'QR Transfer tidak ditemukan.'], 404);
      return;
    }
    if ($qr->status !== 'Aktif') {
      $this->api_response(['status' => false, 'message' => 'QR Transfer sudah tidak aktif.'], 409);
      return;
    }
    if (strtotime($qr->kedaluwarsa_pada) <= time()) {
      $this->db->where('id', (int) $qr->id)->update('tb_qr_transfer', ['status' => 'Kedaluwarsa']);
      $this->api_response(['status' => false, 'message' => 'QR Transfer sudah kedaluwarsa.'], 410);
      return;
    }
    if ((int) $qr->id_penerima === (int) $auth->id_user) {
      $this->api_response(['status' => false, 'message' => 'Anda tidak dapat memindai QR milik sendiri.'], 422);
      return;
    }
    if ($qr->level !== 'Nasabah' || $qr->status_akun !== 'Ya' ||
        $qr->status_cabang !== 'Aktif') {
      $this->api_response(['status' => false, 'message' => 'Penerima atau cabang sedang tidak aktif.'], 403);
      return;
    }

    $this->api_response([
      'status' => true,
      'message' => 'QR Transfer valid.',
      'data' => [
        'qr_payload' => 'tabunganmakmur://qr-transfer?token=' . rawurlencode($token),
        'nominal' => $qr->nominal === null ? null : (int) $qr->nominal,
        'kedaluwarsa_pada' => $qr->kedaluwarsa_pada,
        'penerima' => [
          'nama' => $qr->nama_penerima,
          'cabang_id' => (int) $qr->cabang_id,
          'kode_cabang' => $qr->kode_cabang,
          'nama_cabang' => $qr->nama_cabang
        ]
      ]
    ]);
  }

  public function status_qr_transfer()
  {
    if ($this->input->method(TRUE) !== 'POST') {
      $this->api_response(['status' => false, 'message' => 'Gunakan metode POST.'], 405);
      return;
    }

    $auth = $this->authenticate_api();
    if (!$auth) return;

    if ($auth->level !== 'Nasabah') {
      $this->api_response(['status' => false, 'message' => 'Status QR Transfer hanya dapat diperiksa oleh Nasabah.'], 403);
      return;
    }

    if (!$this->db->table_exists('tb_qr_transfer')) {
      $this->api_response(['status' => false, 'message' => 'Tabel QR Transfer belum dipasang.'], 503);
      return;
    }

    $request = json_decode($this->input->raw_input_stream, true);
    if (!is_array($request)) {
      $this->api_response(['status' => false, 'message' => 'Format permintaan tidak valid.'], 400);
      return;
    }

    $token = $this->_ambil_token_qr_transfer(
      $request['qr_payload'] ?? ($request['token'] ?? '')
    );
    if ($token === null) {
      $this->api_response(['status' => false, 'message' => 'Kode QR Transfer tidak valid.'], 422);
      return;
    }

    $qr = $this->db->query(
      "SELECT q.id, q.nominal AS nominal_qr, q.status, q.kedaluwarsa_pada,
              q.digunakan_pada, t.nominal AS nominal_transfer,
              pengirim.nama AS nama_pengirim
       FROM tb_qr_transfer q
       LEFT JOIN tb_transfer t ON t.id = q.id_transfer
       LEFT JOIN tb_user pengirim ON pengirim.id = t.idPengirim
       WHERE q.token_hash = ? AND q.id_penerima = ? LIMIT 1",
      [hash('sha256', $token), (int) $auth->id_user]
    )->row();

    if (!$qr) {
      $this->api_response(['status' => false, 'message' => 'QR Transfer tidak ditemukan atau bukan milik Anda.'], 404);
      return;
    }

    if ($qr->status === 'Aktif' && strtotime($qr->kedaluwarsa_pada) <= time()) {
      $this->db
        ->where('id', (int) $qr->id)
        ->where('status', 'Aktif')
        ->update('tb_qr_transfer', ['status' => 'Kedaluwarsa']);
      $qr->status = 'Kedaluwarsa';
    }

    $nominal_diterima = $qr->nominal_transfer !== null
      ? (int) $qr->nominal_transfer
      : ($qr->nominal_qr === null ? null : (int) $qr->nominal_qr);

    $this->api_response([
      'status' => true,
      'message' => 'Status QR Transfer berhasil diperiksa.',
      'data' => [
        'status' => $qr->status,
        'nominal' => $nominal_diterima,
        'nama_pengirim' => $qr->nama_pengirim,
        'kedaluwarsa_pada' => $qr->kedaluwarsa_pada,
        'digunakan_pada' => $qr->digunakan_pada
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

    $qr_token = $this->_ambil_token_qr_transfer(
      $request['qr_payload'] ?? ($request['qr_token'] ?? '')
    );
    $is_qr_transfer = $qr_token !== null;
    $qr_preview = null;

    if ($is_qr_transfer) {
      if ($level !== 'Nasabah') {
        $this->api_response(['status' => false, 'message' => 'QR Transfer hanya dapat dilakukan oleh Nasabah.'], 403);
        return;
      }
      if (!$this->db->table_exists('tb_qr_transfer')) {
        $this->api_response(['status' => false, 'message' => 'Tabel QR Transfer belum dipasang.'], 503);
        return;
      }
      $qr_preview = $this->db
        ->where('token_hash', hash('sha256', $qr_token))
        ->limit(1)->get('tb_qr_transfer')->row();
      if (!$qr_preview) {
        $this->api_response(['status' => false, 'message' => 'QR Transfer tidak ditemukan.'], 404);
        return;
      }
      if ($qr_preview->status !== 'Aktif' ||
          strtotime($qr_preview->kedaluwarsa_pada) <= time()) {
        $this->api_response(['status' => false, 'message' => 'QR Transfer sudah tidak aktif atau kedaluwarsa.'], 410);
        return;
      }
      $id_penerima = (int) $qr_preview->id_penerima;
    } else {
      $id_penerima = (int) ($request['id_penerima'] ?? 0);
    }

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

    if ($is_qr_transfer && $qr_preview->nominal !== null) {
      $nominal_input = (string) $qr_preview->nominal;
    }

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

    if ($is_qr_transfer) {
      $keterangan = $keterangan === ''
        ? 'QR Transfer'
        : 'QR Transfer - ' . $keterangan;
    }

    $pin = trim((string) ($request['pin'] ?? ''));
    if ($level === 'Nasabah' && !preg_match('/^[0-9]{6}$/', $pin)) {
      $this->api_response(['status' => false, 'message' => 'PIN harus terdiri dari tepat 6 digit angka.'], 422);
      return;
    }

    $this->db->trans_begin();
    $qr_transfer = null;

    if ($is_qr_transfer) {
      $qr_transfer = $this->db->query(
        "SELECT * FROM tb_qr_transfer
         WHERE token_hash = ? LIMIT 1 FOR UPDATE",
        [hash('sha256', $qr_token)]
      )->row();

      if (!$qr_transfer || $qr_transfer->status !== 'Aktif' ||
          strtotime($qr_transfer->kedaluwarsa_pada) <= time()) {
        $this->db->trans_rollback();
        $this->api_response(['status' => false, 'message' => 'QR Transfer sudah digunakan, dibatalkan, atau kedaluwarsa.'], 409);
        return;
      }
      if ((int) $qr_transfer->id_penerima !== $id_penerima) {
        $this->db->trans_rollback();
        $this->api_response(['status' => false, 'message' => 'Penerima QR Transfer tidak valid.'], 409);
        return;
      }
      if ($qr_transfer->nominal !== null && (int) $qr_transfer->nominal !== $nominal) {
        $this->db->trans_rollback();
        $this->api_response(['status' => false, 'message' => 'Nominal tidak sesuai dengan QR Transfer.'], 409);
        return;
      }
    }

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
            u.login AS status_akun,
            u.pin,
            u.pin_gagal,
            u.pin_terkunci_sampai,
            u.pin_wajib_diubah,
            u.pin_reset_kedaluwarsa,
            u.expo_token,
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

    /*
     * Akun yang belum diverifikasi, ditolak, atau dinonaktifkan
     * tidak boleh menjadi pengirim maupun penerima transfer.
     * Pemeriksaan dilakukan kembali di server meskipun daftar
     * penerima pada get_nasabah sudah disaring.
     */
    if (
      $pengirim->status_akun !== 'Ya' ||
      $penerima->status_akun !== 'Ya'
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Akun pengirim atau penerima tidak aktif.'
      ], 403);

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
     * PIN diverifikasi di transaksi database yang sama dengan transfer.
     */
    if ($level === 'Nasabah') {
      $hasil_pin = $this->verifikasi_pin_user_dalam_transaksi($pengirim, $pin);

      if (!$hasil_pin['status']) {
        if (!empty($hasil_pin['simpan_perubahan']) &&
            $this->db->trans_status() !== false) {
          $this->db->trans_commit();
        } else {
          $this->db->trans_rollback();
        }

        $jawaban_pin = [
          'status' => false,
          'message' => $hasil_pin['message']
        ];
        if (!empty($hasil_pin['data'])) {
          $jawaban_pin['data'] = $hasil_pin['data'];
        }
        $this->api_response($jawaban_pin, (int) $hasil_pin['http_code']);
        return;
      }
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

    if (
      !$insert ||
      $id_transfer <= 0 ||
      $this->db->trans_status() === false
    ) {
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

    /*
     * Saldo digital langsung berpindah ketika transfer berhasil. Untuk
     * transfer lintas cabang, dana fisik masih berada pada rekening
     * penampungan cabang pengirim. Karena itu dibuat satu kewajiban
     * antar-cabang dalam transaksi database yang sama dengan transfer.
     * Transfer satu cabang tidak memerlukan settlement fisik.
     */
    $is_lintas_cabang = (
      (int) $pengirim->cabang_id !==
      (int) $penerima->cabang_id
    );
    $id_kewajiban = null;
    $kode_kewajiban = null;

    if ($is_lintas_cabang) {
      $kode_kewajiban = 'KWA-TRF-' . str_pad(
        (string) $id_transfer,
        10,
        '0',
        STR_PAD_LEFT
      );

      $data_kewajiban = [
        'kode_kewajiban'   => $kode_kewajiban,
        'jenis_sumber'     => 'TransferNasabah',
        'referensi_id'     => $id_transfer,
        'cabang_asal_id'   => (int) $pengirim->cabang_id,
        'cabang_tujuan_id' => (int) $penerima->cabang_id,
        'nominal'          => $nominal,
        'status'           => 'Terbuka',
        'dibuat_oleh'      => (int) $auth->id_user,
        'catatan_status'   =>
          'Dibuat otomatis dari transfer ' . $kode_transfer
      ];

      $insert_kewajiban = $this->db->insert(
        'tb_kewajiban_antar_cabang',
        $data_kewajiban
      );

      $id_kewajiban = (int) $this->db->insert_id();

      if (
        !$insert_kewajiban ||
        $id_kewajiban <= 0 ||
        $this->db->trans_status() === false
      ) {
        $database_error = $this->db->error();
        $this->db->trans_rollback();

        log_message(
          'error',
          'Gagal membuat kewajiban transfer antar-cabang: ' .
            json_encode($database_error)
        );

        $this->api_response([
          'status'  => false,
          'message' =>
            'Transfer lintas cabang gagal mencatat kewajiban settlement.'
        ], 500);

        return;
      }
    }

    if ($is_qr_transfer) {
      $qr_updated = $this->db
        ->where('id', (int) $qr_transfer->id)
        ->where('status', 'Aktif')
        ->update('tb_qr_transfer', [
          'status' => 'Digunakan',
          'digunakan_pada' => date('Y-m-d H:i:s'),
          'id_transfer' => $id_transfer
        ]);

      if (!$qr_updated || $this->db->affected_rows() !== 1 ||
          $this->db->trans_status() === false) {
        $this->db->trans_rollback();
        $this->api_response(['status' => false, 'message' => 'QR Transfer gagal ditandai sebagai telah digunakan.'], 409);
        return;
      }
    }

    $this->db->trans_commit();

    if ($is_qr_transfer) {
      $nominal_format = 'Rp ' . number_format($nominal, 0, ',', '.');
      $judul_notifikasi = 'QR Transfer Diterima';
      $isi_notifikasi = 'Anda menerima ' . $nominal_format .
        ' dari ' . $pengirim->nama . '.';

      $this->db->insert('tb_notifikasi', [
        'id_user' => $id_penerima,
        'judul' => $judul_notifikasi,
        'pesan' => $isi_notifikasi,
        'tanggal' => date('Y-m-d H:i:s')
      ]);
      if (!empty($penerima->expo_token)) {
        $this->send_expo_push_notification(
          $penerima->expo_token,
          $judul_notifikasi,
          $isi_notifikasi
        );
      }
    }

    $this->api_response([
      'status'  => true,
      'message' => 'Transfer berhasil dikirim.',
      'data'    => [
        'id_transfer'        => $id_transfer,
        'kode_transfer'      => $kode_transfer,
        'nominal'            => $nominal,
        'status_transfer'    => 'Sukses',
        'metode_transfer'    => $is_qr_transfer
          ? 'QR Transfer'
          : 'Transfer Antar Rekening',
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
        'saldo_sebelum'         => $saldo_pengirim,
        'saldo_sesudah'         => $saldo_pengirim - $nominal,
        'lintas_cabang'         => $is_lintas_cabang,
        'settlement_diperlukan' => $is_lintas_cabang,
        'kewajiban_settlement'  => $is_lintas_cabang
          ? [
              'id_kewajiban'   => $id_kewajiban,
              'kode_kewajiban' => $kode_kewajiban,
              'status'          => 'Terbuka'
            ]
          : null
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

    if (!$this->db->table_exists('tb_rekening_penampungan')) {
      $this->api_response([
        'status'  => false,
        'message' => 'Tabel rekening penampungan belum tersedia.'
      ], 503);

      return;
    }

    /*
     * Nasabah dan Administrator selalu menggunakan cabang dari token.
     * Super Admin dapat meminta rekening cabang nasabah yang sedang dipilih.
     * cabang_id dari request sengaja tidak diterima agar cakupan cabang tidak
     * dapat dimanipulasi oleh klien.
     */
    $cabang = (object) [
      'id'   => (int) $auth->cabang_id,
      'kode' => $auth->kode_cabang,
      'nama' => $auth->nama_cabang
    ];

    $id_nasabah = (int) $this->input->get('id_nasabah', true);

    if ($auth->level === 'Super Admin' && $id_nasabah > 0) {
      $this->db->select([
        'c.id',
        'c.kode',
        'c.nama'
      ]);

      $this->db->from('tb_user AS u');

      $this->db->join(
        'tb_cabang AS c',
        'c.id = u.cabang_id',
        'inner'
      );

      $this->db->where('u.id', $id_nasabah);
      $this->db->where('u.level', 'Nasabah');
      $this->db->where('c.status', 'Aktif');

      $cabang_nasabah = $this->db->get()->row();

      if (!$cabang_nasabah) {
        $this->api_response([
          'status'  => false,
          'message' => 'Nasabah atau cabang nasabah tidak ditemukan.'
        ], 404);

        return;
      }

      $cabang = $cabang_nasabah;
    }

    if ((int) $cabang->id <= 0) {
      $this->api_response([
        'status'  => false,
        'message' => 'Cabang rekening belum dapat ditentukan.'
      ], 422);

      return;
    }

    $this->db->select([
      'id',
      'jenis',
      'nama_bank AS bank',
      'nomor_rekening AS nomor',
      'atas_nama',
      'icon',
      'urutan'
    ]);

    $this->db->from('tb_rekening_penampungan');
    $this->db->where('cabang_id', (int) $cabang->id);
    $this->db->where('status', 'Aktif');
    $this->db->order_by('urutan', 'ASC');
    $this->db->order_by('id', 'ASC');

    $rekening = $this->db->get()->result_array();

    $this->api_response([
      'status' => true,
      'scope'  => 'rekening_cabang',
      'cabang' => [
        'id'   => (int) $cabang->id,
        'kode' => $cabang->kode,
        'nama' => $cabang->nama
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
    $password_saat_ini = (string) (
      $request['password_saat_ini'] ?? ''
    );
    $password_changed = $password !== '';
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
     * Jika diisi, gunakan 8 sampai 72 karakter agar sesuai
     * dengan batas input bcrypt.
     */
    if (
      $password_changed &&
      (
        strlen($password) < 8 ||
        strlen($password) > 72
      )
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'Password baru harus berisi 8 sampai 72 karakter.'
      ], 422);

      return;
    }

    if ($password_changed) {
      if ($password_saat_ini === '') {
        $this->api_response([
          'status'  => false,
          'message' => 'Password saat ini wajib diisi untuk mengganti password.'
        ], 422);
        return;
      }

      if (strlen($password_saat_ini) > 1024) {
        $this->api_response([
          'status'  => false,
          'message' => 'Password saat ini tidak valid.'
        ], 401);
        return;
      }

      $username_hash = hash(
        'sha256',
        mb_strtolower(
          (string) $current_user->username,
          'UTF-8'
        )
      );

      $ip_address = mb_substr(
        (string) $this->input->ip_address(),
        0,
        45
      );

      $batas_waktu = date(
        'Y-m-d H:i:s',
        strtotime('-15 minutes')
      );

      $jumlah_kombinasi = $this->db
        ->where('username_hash', $username_hash)
        ->where('ip_address', $ip_address)
        ->where('dicoba_pada >=', $batas_waktu)
        ->count_all_results('tb_login_attempt');

      $jumlah_username = $this->db
        ->where('username_hash', $username_hash)
        ->where('dicoba_pada >=', $batas_waktu)
        ->count_all_results('tb_login_attempt');

      $jumlah_ip = $this->db
        ->where('ip_address', $ip_address)
        ->where('dicoba_pada >=', $batas_waktu)
        ->count_all_results('tb_login_attempt');

      if (
        $jumlah_kombinasi >= 5 ||
        $jumlah_username >= 10 ||
        $jumlah_ip >= 30
      ) {
        header('Retry-After: 900');

        $this->api_response([
          'status'  => false,
          'message' => 'Terlalu banyak percobaan verifikasi password. Silakan coba kembali setelah 15 menit.',
          'data'    => [
            'coba_lagi_dalam_detik' => 900
          ]
        ], 429);
        return;
      }

      if (!password_verify(
        $password_saat_ini,
        (string) $current_user->password
      )) {
        $user_agent_header =
          $this->input->get_request_header(
            'User-Agent',
            true
          );

        $insert_attempt = $this->db->insert(
          'tb_login_attempt',
          [
            'username_hash' => $username_hash,
            'id_user'       => $id_user,
            'ip_address'    => $ip_address,
            'user_agent'    => $user_agent_header
              ? mb_substr(
                (string) $user_agent_header,
                0,
                255
              )
              : null,
            'dicoba_pada'   => date('Y-m-d H:i:s')
          ]
        );

        if (!$insert_attempt) {
          log_message(
            'error',
            'Gagal mencatat verifikasi password profil dari IP ' .
              $ip_address
          );

          $this->api_response([
            'status'  => false,
            'message' => 'Layanan perubahan password sementara tidak tersedia.'
          ], 503);
          return;
        }

        $jumlah_kombinasi++;
        $jumlah_username++;
        $jumlah_ip++;

        if (
          $jumlah_kombinasi >= 5 ||
          $jumlah_username >= 10 ||
          $jumlah_ip >= 30
        ) {
          header('Retry-After: 900');

          $this->api_response([
            'status'  => false,
            'message' => 'Terlalu banyak percobaan verifikasi password. Silakan coba kembali setelah 15 menit.',
            'data'    => [
              'coba_lagi_dalam_detik' => 900
            ]
          ], 429);
          return;
        }

        $this->api_response([
          'status'  => false,
          'message' => 'Password saat ini salah.'
        ], 401);
        return;
      }

      if (password_verify(
        $password,
        (string) $current_user->password
      )) {
        $this->api_response([
          'status'  => false,
          'message' => 'Password baru tidak boleh sama dengan password saat ini.'
        ], 422);
        return;
      }
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

    if ($password_changed) {
      $hash_password_baru = password_hash(
        $password,
        PASSWORD_BCRYPT
      );

      if ($hash_password_baru === false) {
        $this->api_response([
          'status'  => false,
       …93600 tokens truncated…       'message' => 'Administrator belum terhubung dengan cabang yang valid.'
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

    if (!in_array(
      $auth->level,
      ['Nasabah', 'Administrator', 'Super Admin'],
      true
    )) {
      $this->api_response([
        'status'  => false,
        'message' => 'Level pengguna tidak memiliki akses untuk mencatat tabungan emas.'
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
     * Nasabah hanya boleh membeli untuk dirinya sendiri.
     * Administrator dan Super Admin wajib menentukan nasabah
     * tujuan. Validasi cakupan cabang dilakukan kembali setelah
     * data nasabah dikunci dari database.
     */
    if ($auth->level === 'Nasabah') {
      $id_nasabah = (int) $auth->id_user;
    } else {
      $id_nasabah = (int) ($request['id_nasabah'] ?? 0);

      if ($id_nasabah <= 0) {
        $this->api_response([
          'status'  => false,
          'message' => 'Nasabah tujuan tabungan emas wajib dipilih.'
        ], 422);
        return;
      }
    }

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
          u.pin_wajib_diubah,
          u.pin_reset_kedaluwarsa,
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
     * Administrator hanya boleh mencatat transaksi untuk nasabah
     * pada cabangnya. Super Admin boleh memilih nasabah dari semua
     * cabang aktif. Cabang transaksi selalu mengikuti data nasabah.
     */
    if (
      $auth->level === 'Administrator' &&
      (int) $user->cabang_id !== (int) $auth->cabang_id
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Nasabah tujuan tidak terdaftar pada cabang Anda.'
      ], 403);
      return;
    }

    /*
     * PIN yang diverifikasi adalah PIN pelaku transaksi:
     * PIN Nasabah untuk pembelian mandiri atau PIN operator untuk
     * pencatatan manual oleh Administrator/Super Admin.
     */
    $pengguna_pin = $user;

    if ($auth->level !== 'Nasabah') {
      $pengguna_pin = $this->db->query(
        "SELECT
            id,
            level,
            login,
            pin,
            pin_gagal,
            pin_terkunci_sampai,
            pin_wajib_diubah,
            pin_reset_kedaluwarsa
         FROM tb_user
         WHERE id = ?
         LIMIT 1
         FOR UPDATE",
        [(int) $auth->id_user]
      )->row();

      if (
        !$pengguna_pin ||
        !in_array(
          $pengguna_pin->level,
          ['Administrator', 'Super Admin'],
          true
        ) ||
        $pengguna_pin->login !== 'Ya'
      ) {
        $this->db->trans_rollback();

        $this->api_response([
          'status'  => false,
          'message' => 'Akun operator tidak aktif.'
        ], 403);
        return;
      }
    }

    /*
     * Verifikasi PIN berada dalam transaksi yang sama.
     */
    $hasil_pin =
      $this->verifikasi_pin_user_dalam_transaksi(
        $pengguna_pin,
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
        $auth->level === 'Nasabah'
          ? 0
          : (int) $auth->id_user,

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
          u.pin_wajib_diubah,
          u.pin_reset_kedaluwarsa,
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

    $request = json_decode($this->input->raw_input_stream, true);
    $request = is_array($request) ? $request : [];
    $scope = $this->resolve_admin_branch_scope(
      $auth,
      $request['cabang_id'] ?? 0
    );

    if ($scope === null) {
      return;
    }

    /*
     * Identitas, level, dan cabang operator berasal dari Bearer token.
     * cabang_id pada body hanya menjadi filter opsional untuk Super Admin.
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

    if ($scope['cabang_id'] !== null) {
      $sql .= "
      AND u.cabang_id = ?
    ";

      $parameter[] = (int) $scope['cabang_id'];
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

        'cakupan' => $scope['cakupan'],

        'cabang_id_filter' => $scope['cabang_id'],

        'kode_cabang_filter' => $scope['kode_cabang'],

        'nama_cabang_filter' => $scope['nama_cabang'],

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

    if (!in_array($method, ['GET', 'POST'], true)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Metode request tidak diizinkan.'
      ], 405);
      return;
    }

    /*
   * Informasi versi bersifat publik.
   * Data pribadi pengunggah tidak ditampilkan.
   */
    $aplikasi = $this->db
      ->select([
        'id',
        'versi_aplikasi',
        'link_apk',
        'apk_nama_file',
        'apk_ukuran',
        'apk_sha256',
        'tgl_update_apk'
      ])
      ->where('id', 1)
      ->limit(1)
      ->get('tb_aplikasi')
      ->row();

    if (!$aplikasi) {
      $this->api_response([
        'status'  => false,
        'message' =>
        'Informasi versi aplikasi belum tersedia.',
        'data'    => [
          'versi'        => null,
          'link_apk'     => '',
          'nama_file'    => null,
          'ukuran_byte'  => null,
          'sha256'       => null,
          'tgl_update'   => null,
          'apk_tersedia' => false
        ]
      ], 404);
      return;
    }

    $versi = trim(
      (string) $aplikasi->versi_aplikasi
    );

    $link_apk = trim(
      (string) $aplikasi->link_apk
    );

    $nama_file_database = trim(
      (string) $aplikasi->apk_nama_file
    );

    $ukuran_database = $aplikasi->apk_ukuran !== null
      ? (int) $aplikasi->apk_ukuran
      : null;

    $sha256 = strtolower(
      trim(
        (string) $aplikasi->apk_sha256
      )
    );

    if (
      $versi === '' ||
      strlen($versi) > 20 ||
      !preg_match(
        '/^\d{1,4}(?:\.\d{1,4}){1,3}(?:-[A-Za-z0-9.-]+)?$/',
        $versi
      )
    ) {
      log_message(
        'error',
        'Format versi aplikasi tidak valid pada ID ' .
          (int) $aplikasi->id
      );

      $this->api_response([
        'status'  => false,
        'message' =>
        'Konfigurasi versi aplikasi tidak valid.'
      ], 500);
      return;
    }

    if (
      $nama_file_database === '' ||
      basename($nama_file_database) !==
      $nama_file_database ||
      strtolower(
        pathinfo(
          $nama_file_database,
          PATHINFO_EXTENSION
        )
      ) !== 'apk'
    ) {
      log_message(
        'error',
        'Nama file APK pada database tidak valid.'
      );

      $this->api_response([
        'status'  => false,
        'message' =>
        'Konfigurasi nama file APK tidak valid.'
      ], 500);
      return;
    }

    if (
      $ukuran_database === null ||
      $ukuran_database < 1024 ||
      $ukuran_database > 209715200
    ) {
      log_message(
        'error',
        'Ukuran APK pada database tidak valid.'
      );

      $this->api_response([
        'status'  => false,
        'message' =>
        'Konfigurasi ukuran APK tidak valid.'
      ], 500);
      return;
    }

    if (
      !preg_match(
        '/^[0-9a-f]{64}$/',
        $sha256
      )
    ) {
      log_message(
        'error',
        'SHA-256 APK pada database tidak valid.'
      );

      $this->api_response([
        'status'  => false,
        'message' =>
        'Konfigurasi integritas APK tidak valid.'
      ], 500);
      return;
    }

    $scheme = strtolower(
      (string) parse_url(
        $link_apk,
        PHP_URL_SCHEME
      )
    );

    $host = strtolower(
      (string) parse_url(
        $link_apk,
        PHP_URL_HOST
      )
    );

    if (
      !filter_var(
        $link_apk,
        FILTER_VALIDATE_URL
      ) ||
      $scheme !== 'https' ||
      $host !== 'kelolawarga.my.id' ||
      rawurldecode(
        basename(
          (string) parse_url(
            $link_apk,
            PHP_URL_PATH
          )
        )
      ) !== $nama_file_database
    ) {
      log_message(
        'error',
        'Link APK tidak cocok dengan konfigurasi file.'
      );

      $this->api_response([
        'status'  => false,
        'message' =>
        'Konfigurasi tautan APK tidak valid.'
      ], 500);
      return;
    }

    $file_path =
      FCPATH .
      'assets/apk/' .
      $nama_file_database;

    $file_tersedia =
      is_file($file_path) &&
      is_readable($file_path);

    $ukuran_fisik = $file_tersedia
      ? filesize($file_path)
      : false;

    $ukuran_cocok =
      $ukuran_fisik !== false &&
      (int) $ukuran_fisik ===
      $ukuran_database;

    if (
      !$file_tersedia ||
      !$ukuran_cocok
    ) {
      log_message(
        'error',
        'File APK tidak tersedia atau ukurannya berubah: ' .
          $nama_file_database
      );

      $this->api_response([
        'status'  => false,
        'message' =>
        'File APK belum tersedia atau tidak konsisten.',
        'data'    => [
          'versi'        => $versi,
          'link_apk'     => '',
          'nama_file'    => $nama_file_database,
          'ukuran_byte'  => $ukuran_database,
          'sha256'       => $sha256,
          'tgl_update'   => $aplikasi->tgl_update_apk,
          'apk_tersedia' => false
        ]
      ], 503);
      return;
    }

    $this->api_response([
      'status' => true,
      'data'   => [
        'versi' =>
        $versi,

        'link_apk' =>
        $link_apk,

        'nama_file' =>
        $nama_file_database,

        'ukuran_byte' =>
        $ukuran_database,

        'sha256' =>
        $sha256,

        'tgl_update' =>
        $aplikasi->tgl_update_apk,

        'apk_tersedia' =>
        true
      ]
    ]);
  }

  // 2. Endpoint Upload Update APK Baru (Khusus Admin)
  public function upload_update_apk()
  {
    if (ob_get_length()) {
      ob_clean();
    }

    header('Access-Control-Allow-Origin: *');
    header('Content-Type: application/json; charset=UTF-8');
    header('Access-Control-Allow-Methods: POST');
    header(
      'Access-Control-Allow-Headers: Authorization, Content-Type'
    );
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
   * Rilis APK berlaku global, sehingga hanya
   * Super Admin yang dapat mengunggahnya.
   */
    if ($auth->level !== 'Super Admin') {
      $this->api_response([
        'status'  => false,
        'message' => 'Akses ditolak. Khusus Super Admin.'
      ], 403);
      return;
    }

    /*
   * Batas file 200 MiB.
   * Batas request diberi ruang tambahan untuk multipart.
   */
    $batas_file =
      200 * 1024 * 1024;

    $batas_request =
      210 * 1024 * 1024;

    $content_length = isset(
      $_SERVER['CONTENT_LENGTH']
    )
      ? (int) $_SERVER['CONTENT_LENGTH']
      : 0;

    if (
      $content_length > 0 &&
      $content_length > $batas_request
    ) {
      $this->api_response([
        'status'  => false,
        'message' =>
        'Ukuran request melebihi batas 210 MB.'
      ], 413);
      return;
    }

    /*
   * id_admin dari multipart tidak dipercaya.
   * Identitas operator berasal dari Bearer token.
   */
    $versi_baru = trim(
      (string) $this->input->post(
        'versi_baru',
        true
      )
    );

    if (
      $versi_baru === '' ||
      strlen($versi_baru) > 20 ||
      !preg_match(
        '/^\d{1,4}(?:\.\d{1,4}){1,3}(?:-[A-Za-z0-9.-]+)?$/',
        $versi_baru
      )
    ) {
      $this->api_response([
        'status'  => false,
        'message' =>
        'Format versi aplikasi tidak valid.'
      ], 422);
      return;
    }

    /*
   * Pastikan konfigurasi aplikasi tersedia dan
   * versi baru lebih tinggi daripada versi aktif.
   */
    $aplikasi_sekarang = $this->db
      ->select([
        'id',
        'versi_aplikasi',
        'link_apk',
        'apk_nama_file',
        'apk_sha256'
      ])
      ->where('id', 1)
      ->limit(1)
      ->get('tb_aplikasi')
      ->row();

    if (!$aplikasi_sekarang) {
      $this->api_response([
        'status'  => false,
        'message' =>
        'Konfigurasi aplikasi tidak ditemukan.'
      ], 404);
      return;
    }

    $versi_sekarang = trim(
      (string) $aplikasi_sekarang->versi_aplikasi
    );

    if (
      $versi_sekarang !== '' &&
      version_compare(
        $versi_baru,
        $versi_sekarang,
        '<='
      )
    ) {
      $this->api_response([
        'status'  => false,
        'message' =>
        'Versi baru harus lebih tinggi dari versi yang sedang aktif.',
        'data'    => [
          'versi_sekarang' =>
          $versi_sekarang,

          'versi_diajukan' =>
          $versi_baru
        ]
      ], 409);
      return;
    }

    if (
      !isset($_FILES['file_apk']) ||
      !is_array($_FILES['file_apk'])
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'File APK wajib dipilih.'
      ], 422);
      return;
    }

    $file_apk = $_FILES['file_apk'];

    $upload_error = (int) (
      $file_apk['error'] ??
      UPLOAD_ERR_NO_FILE
    );

    if ($upload_error !== UPLOAD_ERR_OK) {
      if (
        $upload_error === UPLOAD_ERR_INI_SIZE ||
        $upload_error === UPLOAD_ERR_FORM_SIZE
      ) {
        $this->api_response([
          'status'  => false,
          'message' =>
          'Ukuran file APK melebihi batas yang diizinkan.'
        ], 413);
        return;
      }

      if ($upload_error === UPLOAD_ERR_PARTIAL) {
        $this->api_response([
          'status'  => false,
          'message' =>
          'File APK hanya terunggah sebagian. Silakan ulangi.'
        ], 422);
        return;
      }

      if ($upload_error === UPLOAD_ERR_NO_FILE) {
        $this->api_response([
          'status'  => false,
          'message' => 'File APK wajib dipilih.'
        ], 422);
        return;
      }

      log_message(
        'error',
        'Upload APK ditolak oleh PHP. Kode: ' .
          $upload_error
      );

      $this->api_response([
        'status'  => false,
        'message' =>
        'File APK gagal diterima oleh server.'
      ], 422);
      return;
    }

    $nama_asli = basename(
      (string) ($file_apk['name'] ?? '')
    );

    $tmp_path = (string) (
      $file_apk['tmp_name'] ?? ''
    );

    $ukuran_laporan = (int) (
      $file_apk['size'] ?? 0
    );

    $ekstensi = strtolower(
      pathinfo(
        $nama_asli,
        PATHINFO_EXTENSION
      )
    );

    if (
      $nama_asli === '' ||
      $ekstensi !== 'apk'
    ) {
      $this->api_response([
        'status'  => false,
        'message' =>
        'Format file tidak diizinkan. File harus berekstensi .apk.'
      ], 422);
      return;
    }

    if (
      $tmp_path === '' ||
      !is_uploaded_file($tmp_path) ||
      !is_file($tmp_path)
    ) {
      $this->api_response([
        'status'  => false,
        'message' =>
        'Sumber file upload tidak valid.'
      ], 422);
      return;
    }

    $ukuran_sebenarnya = filesize(
      $tmp_path
    );

    if ($ukuran_sebenarnya === false) {
      $this->api_response([
        'status'  => false,
        'message' =>
        'Ukuran file APK gagal diperiksa.'
      ], 422);
      return;
    }

    $ukuran_sebenarnya =
      (int) $ukuran_sebenarnya;

    if (
      $ukuran_sebenarnya <= 0 ||
      $ukuran_sebenarnya > $batas_file
    ) {
      $this->api_response([
        'status'  => false,
        'message' =>
        'Ukuran file APK harus lebih dari 0 dan maksimal 200 MB.'
      ], 413);
      return;
    }

    if (
      $ukuran_laporan > 0 &&
      $ukuran_laporan !== $ukuran_sebenarnya
    ) {
      log_message(
        'error',
        'Ukuran APK multipart berbeda dengan file sementara.'
      );

      $this->api_response([
        'status'  => false,
        'message' =>
        'Ukuran file APK tidak konsisten.'
      ], 422);
      return;
    }

    /*
   * Periksa MIME berdasarkan isi file.
   * Beberapa server membaca APK sebagai ZIP atau octet-stream.
   * Struktur internal tetap diperiksa setelahnya.
   */
    if (!function_exists('finfo_open')) {
      $this->api_response([
        'status'  => false,
        'message' =>
        'Validasi MIME belum tersedia pada server.'
      ], 500);
      return;
    }

    $finfo = finfo_open(
      FILEINFO_MIME_TYPE
    );

    if (!$finfo) {
      $this->api_response([
        'status'  => false,
        'message' =>
        'Pemeriksa MIME gagal dijalankan.'
      ], 500);
      return;
    }

    $mime = strtolower(
      (string) finfo_file(
        $finfo,
        $tmp_path
      )
    );

    finfo_close($finfo);

    $mime_diizinkan = [
      'application/vnd.android.package-archive',
      'application/zip',
      'application/x-zip',
      'application/x-zip-compressed',
      'application/octet-stream',
      'application/java-archive'
    ];

    if (
      !in_array(
        $mime,
        $mime_diizinkan,
        true
      )
    ) {
      log_message(
        'error',
        'MIME APK ditolak: ' . $mime
      );

      $this->api_response([
        'status'  => false,
        'message' =>
        'Isi file tidak dikenali sebagai paket aplikasi Android.'
      ], 422);
      return;
    }

    /*
   * APK adalah arsip ZIP. File wajib memiliki
   * AndroidManifest.xml dan classes.dex.
   */
    if (!class_exists('ZipArchive')) {
      $this->api_response([
        'status'  => false,
        'message' =>
        'Validasi struktur APK belum tersedia pada server.'
      ], 500);
      return;
    }

    $zip = new ZipArchive();

    $hasil_buka_zip = $zip->open(
      $tmp_path,
      ZipArchive::CHECKCONS
    );

    if ($hasil_buka_zip !== true) {
      $this->api_response([
        'status'  => false,
        'message' =>
        'File tidak memiliki struktur APK yang valid.'
      ], 422);
      return;
    }

    $jumlah_entri =
      (int) $zip->numFiles;

    $manifest_ditemukan =
      $zip->locateName(
        'AndroidManifest.xml',
        ZipArchive::FL_NOCASE
      ) !== false;

    $classes_ditemukan =
      $zip->locateName(
        'classes.dex',
        ZipArchive::FL_NOCASE
      ) !== false;

    $zip->close();

    if (
      $jumlah_entri <= 0 ||
      $jumlah_entri > 100000 ||
      !$manifest_ditemukan ||
      !$classes_ditemukan
    ) {
      $this->api_response([
        'status'  => false,
        'message' =>
        'Struktur APK tidak valid atau tidak lengkap.'
      ], 422);
      return;
    }

    $sha256 = hash_file(
      'sha256',
      $tmp_path
    );

    if (
      !is_string($sha256) ||
      !preg_match(
        '/^[0-9a-f]{64}$/',
        $sha256
      )
    ) {
      $this->api_response([
        'status'  => false,
        'message' =>
        'Hash integritas APK gagal dibuat.'
      ], 500);
      return;
    }

    $sha256_sekarang = strtolower(
      trim(
        (string)
        $aplikasi_sekarang->apk_sha256
      )
    );

    /*
   * Cegah APK lama dirilis ulang menggunakan
   * nomor versi baru yang berbeda.
   */
    if (
      $sha256_sekarang !== '' &&
      hash_equals(
        $sha256_sekarang,
        $sha256
      )
    ) {
      $this->api_response([
        'status'  => false,
        'message' =>
        'File APK sama dengan versi yang sedang aktif.',
        'data'    => [
          'versi_aktif' =>
          $versi_sekarang,

          'sha256' =>
          $sha256
        ]
      ], 409);
      return;
    }

    $upload_dir =
      FCPATH . 'assets/apk/';

    if (!is_dir($upload_dir)) {
      if (
        !mkdir(
          $upload_dir,
          0755,
          true
        ) &&
        !is_dir($upload_dir)
      ) {
        $this->api_response([
          'status'  => false,
          'message' =>
          'Folder penyimpanan APK gagal dibuat.'
        ], 500);
        return;
      }
    }

    if (!is_writable($upload_dir)) {
      $this->api_response([
        'status'  => false,
        'message' =>
        'Folder penyimpanan APK tidak dapat ditulis.'
      ], 500);
      return;
    }

    try {
      $nama_acak =
        bin2hex(random_bytes(8));
    } catch (Exception $e) {
      $nama_acak = str_replace(
        '.',
        '',
        uniqid('', true)
      );
    }

    $versi_file = preg_replace(
      '/[^A-Za-z0-9]+/',
      '_',
      $versi_baru
    );

    $nama_file =
      'TabunganMakmur_v' .
      $versi_file .
      '_' .
      date('YmdHis') .
      '_' .
      $nama_acak .
      '.apk';

    $nama_file = basename(
      $nama_file
    );

    $file_path =
      $upload_dir . $nama_file;

    if (is_file($file_path)) {
      $this->api_response([
        'status'  => false,
        'message' =>
        'Nama file APK sudah digunakan. Silakan ulangi.'
      ], 409);
      return;
    }

    if (
      !move_uploaded_file(
        $tmp_path,
        $file_path
      )
    ) {
      $this->api_response([
        'status'  => false,
        'message' =>
        'File APK gagal disimpan.'
      ], 500);
      return;
    }

    @chmod(
      $file_path,
      0644
    );

    /*
   * Pastikan ukuran dan hash tidak berubah
   * setelah file dipindahkan.
   */
    $ukuran_tersimpan =
      filesize($file_path);

    $sha256_tersimpan =
      hash_file(
        'sha256',
        $file_path
      );

    if (
      $ukuran_tersimpan === false ||
      (int) $ukuran_tersimpan !==
      $ukuran_sebenarnya ||
      !is_string($sha256_tersimpan) ||
      !hash_equals(
        $sha256,
        $sha256_tersimpan
      )
    ) {
      if (is_file($file_path)) {
        @unlink($file_path);
      }

      $this->api_response([
        'status'  => false,
        'message' =>
        'Integritas file APK berubah setelah disimpan.'
      ], 500);
      return;
    }

    /*
   * Gunakan alamat publik resmi dan jangan membentuk
   * URL dari HTTP_HOST karena dapat dimanipulasi.
   */
    $base_url_apk =
      'https://kelolawarga.my.id/tabungan/assets/apk/';

    $link_apk =
      $base_url_apk .
      rawurlencode($nama_file);

    $waktu_upload =
      date('Y-m-d H:i:s');

    $db_debug_sebelumnya =
      $this->db->db_debug;

    $this->db->db_debug = false;
    $this->db->trans_begin();

    /*
   * Kunci konfigurasi untuk mencegah dua rilis
   * berjalan bersamaan.
   */
    $aplikasi_terkunci = $this->db->query(
      "SELECT
        id,
        versi_aplikasi,
        link_apk,
        apk_nama_file
     FROM tb_aplikasi
     WHERE id = 1
     LIMIT 1
     FOR UPDATE"
    )->row();

    if (!$aplikasi_terkunci) {
      $this->db->trans_rollback();
      $this->db->db_debug =
        $db_debug_sebelumnya;

      if (is_file($file_path)) {
        @unlink($file_path);
      }

      $this->api_response([
        'status'  => false,
        'message' =>
        'Konfigurasi aplikasi tidak ditemukan.'
      ], 404);
      return;
    }

    /*
   * Periksa versi kembali setelah row database dikunci.
   */
    if (
      version_compare(
        $versi_baru,
        trim(
          (string)
          $aplikasi_terkunci->versi_aplikasi
        ),
        '<='
      )
    ) {
      $this->db->trans_rollback();
      $this->db->db_debug =
        $db_debug_sebelumnya;

      if (is_file($file_path)) {
        @unlink($file_path);
      }

      $this->api_response([
        'status'  => false,
        'message' =>
        'Versi aplikasi telah diperbarui oleh proses lain.'
      ], 409);
      return;
    }

    $updated = $this->db
      ->where('id', 1)
      ->update(
        'tb_aplikasi',
        [
          'versi_aplikasi' =>
          $versi_baru,

          'link_apk' =>
          $link_apk,

          'apk_nama_file' =>
          $nama_file,

          'apk_ukuran' =>
          $ukuran_sebenarnya,

          'apk_sha256' =>
          $sha256,

          'apk_diupload_oleh' =>
          (int) $auth->id_user,

          'tgl_update_apk' =>
          $waktu_upload
        ]
      );

    if (
      !$updated ||
      $this->db->trans_status() === false
    ) {
      $database_error =
        $this->db->error();

      $this->db->trans_rollback();
      $this->db->db_debug =
        $db_debug_sebelumnya;

      if (is_file($file_path)) {
        @unlink($file_path);
      }

      log_message(
        'error',
        'Rilis APK gagal disimpan: ' .
          json_encode($database_error)
      );

      $this->api_response([
        'status'  => false,
        'message' =>
        'Informasi rilis APK gagal disimpan.'
      ], 500);
      return;
    }

    $this->db->trans_commit();
    $this->db->db_debug =
      $db_debug_sebelumnya;

    /*
   * APK lama tidak langsung dihapus agar tersedia
   * untuk rollback jika rilis baru bermasalah.
   */
    $this->api_response([
      'status'  => true,
      'message' =>
      'Aplikasi v' .
        $versi_baru .
        ' berhasil dirilis.',
      'data'    => [
        'versi' =>
        $versi_baru,

        'link_apk' =>
        $link_apk,

        'nama_file' =>
        $nama_file,

        'ukuran_byte' =>
        $ukuran_sebenarnya,

        'sha256' =>
        $sha256,

        'tanggal_rilis' =>
        $waktu_upload,

        'diperbarui_oleh' =>
        (int) $auth->id_user,

        'nama_operator' =>
        $auth->nama,

        'apk_sebelumnya' =>
        $aplikasi_terkunci->apk_nama_file
      ]
    ], 201);
  }

  // ==========================================
  // ENDPOINT API: TARIK KAS ADMIN & SEMUA SALDO NASABAH
  // ==========================================
  public function get_semua_saldo_eksternal()
  {
    if (ob_get_length()) {
      ob_clean();
    }

    header('Access-Control-Allow-Origin: *');
    header('Content-Type: application/json; charset=UTF-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');

    /*
   * Endpoint monitoring eksternal dinonaktifkan
   * sampai mekanisme autentikasi server-to-server
   * dan pembatasan akses selesai dibuat.
   *
   * Jangan mengaktifkan kembali API key lama karena
   * sebelumnya pernah tersimpan di source code.
   */
    $this->api_response([
      'status'  => false,
      'message' =>
      'Endpoint monitoring eksternal sedang dinonaktifkan.'
    ], 410);
  }


  public function reset_pin_nasabah()
  {
    header('Access-Control-Allow-Origin: *');
    header('Content-Type: application/json; charset=UTF-8');
    header('Access-Control-Allow-Methods: POST');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');

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
        'message' => 'Reset PIN hanya dapat dilakukan oleh Administrator atau Super Admin.'
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

    $id_nasabah_raw = $request['id_nasabah'] ?? null;

    if (
      !is_int($id_nasabah_raw) &&
      !(
        is_string($id_nasabah_raw) &&
        ctype_digit($id_nasabah_raw)
      )
    ) {
      $this->api_response([
        'status'  => false,
        'message' => 'ID Nasabah wajib berupa angka.'
      ], 422);
      return;
    }

    $id_nasabah = (int) $id_nasabah_raw;

    if ($id_nasabah <= 0) {
      $this->api_response([
        'status'  => false,
        'message' => 'ID Nasabah tidak valid.'
      ], 422);
      return;
    }

    $id_pereset = (int) $auth->id_user;
    $this->db->trans_begin();

    /*
     * Identitas pelaksana selalu berasal dari Bearer token.
     * id_admin yang dikirim dari body tidak pernah dipercaya.
     */
    $pereset = $this->db->query(
      "SELECT
          u.id,
          u.nama,
          u.level,
          u.login,
          u.cabang_id,
          c.status AS status_cabang
       FROM tb_user AS u
       LEFT JOIN tb_cabang AS c
         ON c.id = u.cabang_id
       WHERE u.id = ?
       LIMIT 1
       FOR UPDATE",
      [$id_pereset]
    )->row();

    if (
      !$pereset ||
      !in_array(
        $pereset->level,
        ['Administrator', 'Super Admin'],
        true
      ) ||
      $pereset->login !== 'Ya' ||
      $pereset->status_cabang !== 'Aktif'
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Akun Administrator tidak ditemukan atau tidak aktif.'
      ], 403);
      return;
    }

    $nasabah = $this->db->query(
      "SELECT
          u.id,
          u.nama,
          u.level,
          u.login,
          u.cabang_id,
          u.expo_token,
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
      $nasabah->level !== 'Nasabah' ||
      $nasabah->login !== 'Ya'
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Akun Nasabah tidak ditemukan atau tidak aktif.'
      ], 404);
      return;
    }

    if ($nasabah->status_cabang !== 'Aktif') {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Cabang Nasabah sedang tidak aktif.'
      ], 403);
      return;
    }

    if (
      $pereset->level === 'Administrator' &&
      (int) $pereset->cabang_id !==
      (int) $nasabah->cabang_id
    ) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Administrator hanya dapat mereset PIN Nasabah pada cabangnya sendiri.'
      ], 403);
      return;
    }

    /*
     * Cegah reset berulang untuk Nasabah yang sama dalam 5 menit.
     */
    $reset_terakhir = $this->db->query(
      "SELECT dibuat_pada
       FROM tb_reset_pin_log
       WHERE id_nasabah = ?
         AND dibuat_pada > DATE_SUB(NOW(), INTERVAL 5 MINUTE)
       ORDER BY dibuat_pada DESC
       LIMIT 1",
      [$id_nasabah]
    )->row();

    if ($reset_terakhir) {
      $coba_lagi_pada = date(
        'Y-m-d H:i:s',
        strtotime(
          '+5 minutes',
          strtotime($reset_terakhir->dibuat_pada)
        )
      );

      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'PIN baru saja direset. Silakan tunggu sebelum melakukan reset kembali.',
        'data'    => [
          'coba_lagi_pada' => $coba_lagi_pada
        ]
      ], 429);
      return;
    }

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
      '012345',
      '123456',
      '234567',
      '345678',
      '456789',
      '987654',
      '876543',
      '765432',
      '654321',
      '543210'
    ];

    try {
      do {
        $pin_sementara = str_pad(
          (string) random_int(0, 999999),
          6,
          '0',
          STR_PAD_LEFT
        );
      } while (in_array($pin_sementara, $pin_lemah, true));
    } catch (Throwable $e) {
      $this->db->trans_rollback();

      log_message(
        'error',
        'Generator PIN sementara gagal: ' .
          $e->getMessage()
      );

      $this->api_response([
        'status'  => false,
        'message' => 'Gagal membuat PIN sementara yang aman.'
      ], 500);
      return;
    }

    $hash_pin = password_hash(
      $pin_sementara,
      PASSWORD_BCRYPT
    );

    if ($hash_pin === false) {
      $this->db->trans_rollback();

      $this->api_response([
        'status'  => false,
        'message' => 'Gagal melindungi PIN sementara.'
      ], 500);
      return;
    }

    $waktu_reset = date('Y-m-d H:i:s');
    $kedaluwarsa_pada = date(
      'Y-m-d H:i:s',
      strtotime('+24 hours')
    );

    $update = $this->db
      ->where('id', $id_nasabah)
      ->update('tb_user', [
        'pin'                   => $hash_pin,
        'pin_gagal'             => 0,
        'pin_terkunci_sampai'   => null,
        'pin_wajib_diubah'      => 1,
        'pin_reset_oleh'        => $id_pereset,
        'pin_reset_pada'        => $waktu_reset,
        'pin_reset_kedaluwarsa' => $kedaluwarsa_pada
      ]);

    $user_agent = $this->input->get_request_header(
      'User-Agent',
      true
    );

    $insert_log = $this->db->insert(
      'tb_reset_pin_log',
      [
        'id_nasabah'        => $id_nasabah,
        'nama_nasabah'      => mb_substr(
          (string) $nasabah->nama,
          0,
          255
        ),
        'direset_oleh'       => $id_pereset,
        'nama_pereset'      => mb_substr(
          (string) $pereset->nama,
          0,
          255
        ),
        'level_pereset'     => mb_substr(
          (string) $pereset->level,
          0,
          50
        ),
        'cabang_id'         => (int) $nasabah->cabang_id,
        'kedaluwarsa_pada'  => $kedaluwarsa_pada,
        'ip_address'        => mb_substr(
          (string) $this->input->ip_address(),
          0,
          45
        ),
        'user_agent'        => $user_agent
          ? mb_substr((string) $user_agent, 0, 255)
          : null,
        'dibuat_pada'       => $waktu_reset
      ]
    );

    $judul_notifikasi = 'PIN Transaksi Direset';
    $pesan_notifikasi =
      'PIN transaksi Anda telah direset oleh ' .
      $pereset->nama .
      '. Gunakan PIN sementara yang diberikan Administrator lalu segera ubah PIN sebelum ' .
      $kedaluwarsa_pada .
      '.';

    $insert_notifikasi = $this->db->insert(
      'tb_notifikasi',
      [
        'id_user' => $id_nasabah,
        'judul'   => $judul_notifikasi,
        'pesan'   => $pesan_notifikasi,
        'is_read' => 0,
        'tanggal' => $waktu_reset
      ]
    );

    if (
      !$update ||
      !$insert_log ||
      !$insert_notifikasi ||
      $this->db->trans_status() === false
    ) {
      $database_error = $this->db->error();
      $this->db->trans_rollback();

      log_message(
        'error',
        'Reset PIN Nasabah gagal: ' .
          json_encode($database_error)
      );

      $this->api_response([
        'status'  => false,
        'message' => 'Terjadi kesalahan sistem. PIN gagal direset.'
      ], 500);
      return;
    }

    $this->db->trans_commit();

    /*
     * Push tidak berisi PIN dan dikirim setelah transaksi tersimpan.
     */
    try {
      if (!empty($nasabah->expo_token)) {
        $this->send_expo_push_notification(
          $nasabah->expo_token,
          $judul_notifikasi,
          'PIN transaksi Anda telah direset. Segera ubah PIN sementara melalui aplikasi.'
        );
      }
    } catch (Throwable $e) {
      log_message(
        'error',
        'Push reset PIN gagal: ' .
          $e->getMessage()
      );
    }

    /*
     * PIN plaintext hanya dikirim pada respons ini satu kali.
     * Database, audit, notifikasi, dan log tidak menyimpannya.
     */
    $this->api_response([
      'status'  => true,
      'message' => 'PIN Nasabah berhasil direset. PIN sementara hanya ditampilkan satu kali.',
      'data'    => [
        'id_nasabah'        => $id_nasabah,
        'nama_nasabah'      => $nasabah->nama,
        'cabang_id'         => (int) $nasabah->cabang_id,
        'kode_cabang'       => $nasabah->kode_cabang,
        'nama_cabang'       => $nasabah->nama_cabang,
        'pin_sementara'     => $pin_sementara,
        'pin_wajib_diubah'  => true,
        'kedaluwarsa_pada'  => $kedaluwarsa_pada,
        'masa_berlaku_jam'  => 24
      ]
    ]);
  }
}
