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

  /**
   * Mengambil Bearer token dari header Authorization.
   */
  private function get_bearer_token()
  {
    $authorization = $this->input->get_request_header(
      'Authorization',
      true
    );

    // Fallback untuk beberapa konfigurasi Apache/XAMPP
    if (empty($authorization) && isset($_SERVER['HTTP_AUTHORIZATION'])) {
      $authorization = $_SERVER['HTTP_AUTHORIZATION'];
    }

    if (
      empty($authorization) &&
      isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])
    ) {
      $authorization = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
    }

    if (
      empty($authorization) ||
      !preg_match(
        '/^Bearer\s+(\S+)$/i',
        trim($authorization),
        $matches
      )
    ) {
      return null;
    }

    $token = trim($matches[1]);

    // Token yang dibuat saat login berupa 64 karakter hexadecimal
    if (strlen($token) !== 64 || !ctype_xdigit($token)) {
      return null;
    }

    return $token;
  }

  /**
   * Memvalidasi Bearer token dan mengembalikan data pengguna.
   */
  private function authenticate_api()
  {
    $token = $this->get_bearer_token();

    if (empty($token)) {
      $this->api_response([
        'status'  => false,
        'message' => 'Bearer token tidak ditemukan.'
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
  // 4. ENDPOINT AMBIL DATA NASABAH
  // ==========================================
  public function get_nasabah()
  {
    if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
      echo json_encode(['status' => false, 'message' => 'Gunakan metode GET.']);
      return;
    }

    $this->db->select('id, nama');
    $this->db->where('level', 'Nasabah');
    $this->db->order_by('nama', 'ASC');
    $nasabah = $this->db->get('tb_user')->result_array();

    echo json_encode(['status' => true, 'data' => $nasabah]);
  }

  // ==========================================
  // 5. ENDPOINT SIMPAN TRANSAKSI (SETOR & TARIK)
  // ==========================================
  public function simpan_transaksi()
  {
    $request = json_decode($this->input->raw_input_stream, true);

    if ($_SERVER['REQUEST_METHOD'] !== 'POST' || empty($request)) {
      echo json_encode(['status' => false, 'message' => 'Permintaan tidak valid.']);
      return;
    }

    $idAdmin = $request['id_admin'] ?? 0;
    $status_konfirmasi = ($idAdmin != 0) ? 'Sukses' : 'Pending';

    // 1. Proses Upload Gambar (Jika Ada)
    $file_name = null;
    if (!empty($request['bukti_base64'])) {
      $image_parts = explode(";base64,", $request['bukti_base64']);
      if (count($image_parts) == 2) {
        $image_base64 = base64_decode($image_parts[1]);
        $file_name = 'bukti_' . time() . '_' . uniqid() . '.jpg';

        $upload_dir = FCPATH . 'assets/bukti_transfer/';
        if (!is_dir($upload_dir)) {
          mkdir($upload_dir, 0777, true);
        }
        file_put_contents($upload_dir . $file_name, $image_base64);
      }
    }

    // 2. Siapkan Data Transaksi
    $data = [
      'idAdmin'           => $idAdmin,
      'idNasabah'         => $request['id_nasabah'] ?? 0,
      'idPotongan'        => 0,
      'tanggal'           => date('Y-m-d'),
      'nominal'           => str_replace('.', '', $request['nominal'] ?? '0'),
      'jenis'             => $request['jenis'] ?? '',
      'keterangan'        => $request['keterangan'] ?? '',
      'status_konfirmasi' => $status_konfirmasi,
      'bukti_transfer'    => $file_name,
      'terdaftar'         => date('Y-m-d H:i:s')
    ];

    if (empty($data['idNasabah']) || empty($data['nominal']) || empty($data['jenis'])) {
      echo json_encode(['status' => false, 'message' => 'Data tidak lengkap!']);
      return;
    }

    // =======================================================
    // 🔥 3. LOGIKA PENGECEKAN SALDO (CEGAH SALDO MINUS) 🔥
    // =======================================================
    if ($data['jenis'] === 'Keluar') {
      $id_cek = $data['idNasabah'];
      $nominal_tarik = (int)$data['nominal'];

      // Hitung total uang masuk
      $tbMsk = $this->db->query("SELECT SUM(nominal) AS total FROM tb_transaksi WHERE idNasabah=? AND jenis='Masuk' AND status_konfirmasi='Sukses'", [$id_cek])->row()->total ?? 0;
      $tfMsk = $this->db->query("SELECT SUM(nominal) AS total FROM tb_transfer WHERE idPenerima=?", [$id_cek])->row()->total ?? 0;
      $totalMasuk = $tbMsk + $tfMsk;

      // Hitung total uang keluar
      $tbKlr = $this->db->query("SELECT SUM(nominal) AS total FROM tb_transaksi WHERE idNasabah=? AND jenis='Keluar' AND status_konfirmasi='Sukses'", [$id_cek])->row()->total ?? 0;
      $tfKlr = $this->db->query("SELECT SUM(nominal) AS total FROM tb_transfer WHERE idPengirim=?", [$id_cek])->row()->total ?? 0;
      $totalKeluar = $tbKlr + $tfKlr;

      // Hitung saldo aktif
      $saldo_aktif = $totalMasuk - $totalKeluar;

      // Validasi: Jika yang ditarik lebih besar dari saldo aktif
      if ($nominal_tarik > $saldo_aktif) {
        echo json_encode([
          'status' => false,
          'message' => 'Penarikan gagal! Saldo nasabah tidak mencukupi. (Sisa Saldo: Rp ' . number_format($saldo_aktif, 0, ',', '.') . ')'
        ]);
        return; // Hentikan proses agar transaksi tidak masuk ke database
      }
    }
    // =======================================================

    // 4. Eksekusi Simpan ke Database (CUKUP 1 KALI SAJA)
    $insert = $this->db->insert('tb_transaksi', $data);

    if ($insert) {
      // Jika statusnya Pending (Nasabah yang input)
      if ($status_konfirmasi === 'Pending') {
        $this->db->where('id', $data['idNasabah']);
        $nasabah = $this->db->get('tb_user')->row();
        $nama_nasabah = $nasabah ? $nasabah->nama : 'Nasabah';

        $jenis_teks = ($data['jenis'] === 'Masuk') ? 'menabung' : 'penarikan';
        $jenis_wa = ($data['jenis'] === 'Masuk') ? 'Menabung' : 'Penarikan';

        // Kirim Notifikasi WhatsApp ke Admin
        $pesan_wa = "🔔 *PENGAJUAN TRANSAKSI BARU*\n\n";
        $pesan_wa .= "Halo Admin, ada pengajuan baru:\n";
        $pesan_wa .= "👤 *Nama:* " . $nama_nasabah . "\n";
        $pesan_wa .= "📝 *Jenis:* " . $jenis_wa . " Dana\n";
        $pesan_wa .= "💰 *Nominal:* Rp " . number_format($data['nominal'], 0, ',', '.') . "\n";
        $pesan_wa .= "📌 *Ket:* " . ($data['keterangan'] ? $data['keterangan'] : '-') . "\n\n";
        $pesan_wa .= "Mohon segera cek aplikasi untuk konfirmasi.";

        $nomor_admin = '081234567890'; // GANTI DENGAN NOMOR WA ADMIN
        $this->send_whatsapp($nomor_admin, $pesan_wa);

        // Ambil data admin untuk Push Notification & Lonceng
        $this->db->where_in('level', ['Administrator', 'Super Admin']);
        $this->db->where('expo_token !=', NULL);
        $admins = $this->db->get('tb_user')->result();

        foreach ($admins as $admin) {
          // Simpan ke DB NOTIFIKASI (Agar muncul di lonceng Admin)
          $this->db->insert('tb_notifikasi', [
            'id_user' => $admin->id,
            'judul'   => "🔔 Pengajuan Transaksi Baru",
            'pesan'   => "Nasabah {$nama_nasabah} mengajukan {$jenis_teks} sebesar Rp " . number_format($data['nominal'], 0, ',', '.'),
            'tanggal' => date('Y-m-d H:i:s')
          ]);

          // KIRIM PUSH NOTIFICATION (Muncul pop-up di HP)
          $this->send_expo_push_notification(
            $admin->expo_token,
            "🔔 Pengajuan Transaksi Baru",
            "Nasabah {$nama_nasabah} mengajukan {$jenis_teks} sebesar Rp " . number_format($data['nominal'], 0, ',', '.')
          );
        }

        $pesanBalasan = 'Pengajuan berhasil dikirim! Menunggu konfirmasi Admin.';
      } else {
        // Jika Admin yang input, langsung sukses
        $pesanBalasan = 'Transaksi berhasil disimpan!';
      }

      echo json_encode(['status' => true, 'message' => $pesanBalasan]);
    } else {
      echo json_encode(['status' => false, 'message' => 'Gagal menyimpan transaksi.']);
    }
  }

  // ==========================================
  // 6. ENDPOINT SIMPAN TRANSFER
  // ==========================================
  public function simpan_transfer()
  {
    $request = json_decode($this->input->raw_input_stream, true);

    if ($_SERVER['REQUEST_METHOD'] !== 'POST' || empty($request)) {
      echo json_encode(['status' => false, 'message' => 'Permintaan tidak valid.']);
      return;
    }

    $data = [
      'idPengirim' => $request['id_pengirim'] ?? 0,
      'idPenerima' => $request['id_penerima'] ?? 0,
      'nominal'    => str_replace('.', '', $request['nominal'] ?? '0'),
      'keterangan' => $request['keterangan'] ?? '',
      'terdaftar'  => date('Y-m-d H:i:s')
    ];

    if (empty($data['idPengirim']) || empty($data['idPenerima']) || empty($data['nominal'])) {
      echo json_encode(['status' => false, 'message' => 'Data transfer tidak lengkap!']);
      return;
    }

    $insert = $this->db->insert('tb_transfer', $data);

    if ($insert) {
      echo json_encode(['status' => true, 'message' => 'Transfer berhasil dikirim!']);
    } else {
      echo json_encode(['status' => false, 'message' => 'Gagal memproses transfer.']);
    }
  }

  // ==========================================
  // 7. ENDPOINT KONFIRMASI TRANSAKSI
  // ==========================================
  public function konfirmasi_transaksi()
  {
    $request = json_decode($this->input->raw_input_stream, true);

    if ($_SERVER['REQUEST_METHOD'] !== 'POST' || empty($request)) {
      echo json_encode(['status' => false, 'message' => 'Permintaan tidak valid.']);
      return;
    }

    $raw_id_transaksi = $request['id_transaksi'] ?? '';
    $status_baru      = $request['status'] ?? '';
    $id_admin         = $request['id_admin'] ?? '';

    if (empty($raw_id_transaksi) || empty($status_baru) || empty($id_admin)) {
      echo json_encode(['status' => false, 'message' => 'Data tidak lengkap.']);
      return;
    }

    $id_transaksi = str_replace('trx_', '', $raw_id_transaksi);

    $this->db->where('id', $id_transaksi);
    $update = $this->db->update('tb_transaksi', [
      'status_konfirmasi' => $status_baru,
      'idAdmin'           => $id_admin
    ]);

    if ($update) {
      // 🔥 TAMBAHKAN tb_transaksi.idNasabah pada select
      $this->db->select('tb_transaksi.nominal, tb_transaksi.jenis, tb_transaksi.idNasabah, tb_user.expo_token');
      $this->db->from('tb_transaksi');
      $this->db->join('tb_user', 'tb_transaksi.idNasabah = tb_user.id');
      $this->db->where('tb_transaksi.id', $id_transaksi);
      $trx_data = $this->db->get()->row();

      // 🔥 UBAH PENGECEKAN: Pengecekan expo_token dipindah ke dalam
      if ($trx_data) {
        $jenis_teks = ($trx_data->jenis === 'Masuk') ? 'menabung' : 'penarikan';
        $nominal_format = 'Rp ' . number_format($trx_data->nominal, 0, ',', '.');
        $judul_notif = ($status_baru === 'Sukses') ? "✅ Transaksi Disetujui!" : "❌ Transaksi Ditolak";
        $body_notif = "Pengajuan {$jenis_teks} sebesar {$nominal_format} telah berstatus: {$status_baru}.";

        // 1. SIMPAN KE DB NOTIFIKASI (Akan selalu masuk lonceng)
        $this->db->insert('tb_notifikasi', [
          'id_user' => $trx_data->idNasabah,
          'judul'   => $judul_notif,
          'pesan'   => $body_notif,
          'tanggal' => date('Y-m-d H:i:s')
        ]);

        // 2. KIRIM PUSH NOTIFICATION (Hanya jika token tersedia)
        if (!empty($trx_data->expo_token)) {
          $this->send_expo_push_notification($trx_data->expo_token, $judul_notif, $body_notif);
        }
      }

      echo json_encode(['status' => true, 'message' => 'Transaksi berhasil di-' . $status_baru]);
    } else {
      echo json_encode(['status' => false, 'message' => 'Gagal mengubah status.']);
    }
  }

  // ==========================================
  // 8. ENDPOINT AMBIL DAFTAR REKENING ADMIN
  // ==========================================
  public function get_rekening()
  {
    if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
      echo json_encode(['status' => false, 'message' => 'Gunakan metode GET.']);
      return;
    }

    $rekening = [
      [
        'id' => 1,
        'bank' => 'BCA (Bank Central Asia)',
        'nomor' => '0380463563',
        'atas_nama' => 'a.n. Mohammad Lukman Nurdin',
        'icon' => 'card'
      ],
      [
        'id' => 2,
        'bank' => 'DANA',
        'nomor' => '085793771111',
        'atas_nama' => 'a.n. Mohammad Lukman Nurdin',
        'icon' => 'wallet'
      ]
    ];

    echo json_encode(['status' => true, 'data' => $rekening]);
  }

  // ==========================================
  // 9. ENDPOINT EDIT PROFIL (SUDAH DIPERBARUI DENGAN DATA LENGKAP)
  // ==========================================
  public function update_profil()
  {
    $request = json_decode($this->input->raw_input_stream, true);

    if ($_SERVER['REQUEST_METHOD'] !== 'POST' || empty($request)) {
      echo json_encode(['status' => false, 'message' => 'Permintaan tidak valid.']);
      return;
    }

    $id_user = $request['id_user'] ?? '';
    $nama = $request['nama'] ?? '';
    $username = $request['username'] ?? '';
    $password = $request['password'] ?? '';
    $foto_base64 = $request['foto_base64'] ?? '';

    // MENANGKAP DATA DARI REACT NATIVE
    $jenis_kelamin = $request['jenis_kelamin'] ?? '';
    $telp = $request['telp'] ?? '';
    $email = $request['email'] ?? '';
    $alamat = $request['alamat'] ?? '';

    if (empty($id_user) || empty($nama) || empty($username)) {
      echo json_encode(['status' => false, 'message' => 'Nama dan Username wajib diisi!']);
      return;
    }

    $this->db->where('username', $username);
    $this->db->where('id !=', $id_user);
    if ($this->db->get('tb_user')->num_rows() > 0) {
      echo json_encode(['status' => false, 'message' => 'Username sudah digunakan orang lain.']);
      return;
    }

    $data_update = [
      'nama'         => $nama,
      'username'     => $username,
      'jenisKelamin' => $jenis_kelamin,
      'telp'         => $telp,
      'email'        => $email,
      'alamat'       => $alamat
    ];

    if (!empty($password)) {
      $data_update['password'] = password_hash($password, PASSWORD_DEFAULT);
    }

    if (!empty($foto_base64)) {
      $image_parts = explode(";base64,", $foto_base64);
      if (count($image_parts) == 2) {
        $image_base64 = base64_decode($image_parts[1]);
        $file_name = 'profil_' . time() . '_' . uniqid() . '.jpg';
        $upload_dir = FCPATH . 'assets/profil/';
        if (!is_dir($upload_dir)) {
          mkdir($upload_dir, 0777, true);
        }
        file_put_contents($upload_dir . $file_name, $image_base64);

        $data_update['foto'] = $file_name;
      }
    }

    $this->db->where('id', $id_user);
    $update = $this->db->update('tb_user', $data_update);

    if ($update) {
      echo json_encode(['status' => true, 'message' => 'Profil berhasil diperbarui!', 'foto_baru' => $data_update['foto'] ?? null]);
    } else {
      echo json_encode(['status' => false, 'message' => 'Gagal memperbarui profil.']);
    }
  }

  // ==========================================
  // FUNGSI HELPER
  // ==========================================
  public function update_token()
  {
    $request = json_decode($this->input->raw_input_stream, true);
    $id_user = $request['id_user'] ?? '';
    $token = $request['token'] ?? '';

    if (!empty($id_user) && !empty($token)) {
      $this->db->where('id', $id_user);
      $this->db->update('tb_user', ['expo_token' => $token]);
      echo json_encode(['status' => true, 'message' => 'Token berhasil disimpan.']);
    } else {
      echo json_encode(['status' => false, 'message' => 'Data tidak lengkap.']);
    }
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

  public function update_pengaturan()
  {
    $input = json_decode(file_get_contents('php://input'), true);

    // Pastikan yang mengakses adalah Super Admin
    $this->db->where('id', $input['id_admin']);
    $this->db->where('level', 'Super Admin');
    $admin = $this->db->get('tb_user')->row();

    if (!$admin) {
      echo json_encode(['status' => false, 'message' => 'Akses ditolak! Khusus Super Admin.']);
      return;
    }

    $data_update = [
      'nama' => $input['nama'] ?? '',
      'telp' => $input['telp'] ?? '',
      'email' => $input['email'] ?? '',
      'alamat' => $input['alamat'] ?? ''
    ];

    // Jika Admin mengubah logo
    if (!empty($input['logo_base64'])) {
      $image_parts = explode(";base64,", $input['logo_base64']);
      if (count($image_parts) == 2) {
        $image_base64 = base64_decode($image_parts[1]);
        $file_name = 'Logo-' . time() . '.png';

        $file_path = FCPATH . 'assets/logo/' . $file_name;

        if (file_put_contents($file_path, $image_base64)) {
          $data_update['logo'] = $file_name;
        }
      }
    }

    // 🔥 PERBAIKAN: Logika Cerdas (Jika tabel kosong maka INSERT, jika ada maka UPDATE)
    $cek_data = $this->db->get('tb_aplikasi')->num_rows();

    if ($cek_data > 0) {
      $this->db->where('id', 1);
      $update = $this->db->update('tb_aplikasi', $data_update);
    } else {
      $data_update['id'] = 1;
      $update = $this->db->insert('tb_aplikasi', $data_update);
    }

    if ($update) {
      echo json_encode(['status' => true, 'message' => 'Pengaturan aplikasi berhasil disimpan!']);
    } else {
      echo json_encode(['status' => false, 'message' => 'Gagal menyimpan pengaturan.']);
    }
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

  public function upload_banner()
  {
    $input = json_decode(file_get_contents('php://input'), true);

    // Pastikan hanya Administrator yang bisa upload
    $this->db->where('id', $input['id_admin']);
    $this->db->where_in('level', ['Administrator', 'Super Admin']); // ✅ Sisa teks dihapus
    $admin = $this->db->get('tb_user')->row();
    if (!$admin) {
      echo json_encode(['status' => false, 'message' => 'Akses ditolak! Khusus Admin.']);
      return;
    }

    if (!empty($input['gambar_base64'])) {
      $image_parts = explode(";base64,", $input['gambar_base64']);
      if (count($image_parts) == 2) {
        $image_base64 = base64_decode($image_parts[1]);
        $file_name = 'banner_' . time() . '_' . uniqid() . '.jpg';

        $upload_dir = FCPATH . 'assets/banner/';
        if (!is_dir($upload_dir)) {
          mkdir($upload_dir, 0777, true);
        }

        if (file_put_contents($upload_dir . $file_name, $image_base64)) {
          $this->db->insert('tb_banner', [
            'gambar' => $file_name,
            'terdaftar' => date('Y-m-d H:i:s')
          ]);
          echo json_encode(['status' => true, 'message' => 'Banner berhasil dipublikasikan!']);
          return;
        }
      }
    }
    echo json_encode(['status' => false, 'message' => 'Gagal mengupload gambar.']);
  }

  public function hapus_banner()
  {
    $input = json_decode(file_get_contents('php://input'), true);

    $this->db->where('id', $input['id_admin']);
    $this->db->where_in('level', ['Administrator', 'Super Admin']);
    $admin = $this->db->get('tb_user')->row();
    if (!$admin) {
      echo json_encode(['status' => false, 'message' => 'Akses ditolak!']);
      return;
    }

    $id_banner = $input['id_banner'] ?? '';
    $banner = $this->db->get_where('tb_banner', ['id' => $id_banner])->row();

    if ($banner) {
      $file_path = FCPATH . 'assets/banner/' . $banner->gambar;
      if (file_exists($file_path)) {
        unlink($file_path);
      }

      $this->db->where('id', $id_banner);
      $this->db->delete('tb_banner');
      echo json_encode(['status' => true, 'message' => 'Banner berhasil dihapus!']);
    } else {
      echo json_encode(['status' => false, 'message' => 'Data banner tidak ditemukan.']);
    }
  }
  public function register()
  {
    header("Access-Control-Allow-Origin: *");
    header("Content-Type: application/json; charset=UTF-8");
    header("Access-Control-Allow-Methods: POST");

    $json = file_get_contents('php://input');
    $data = json_decode($json, true);

    if (!empty($data['nama']) && !empty($data['username']) && !empty($data['password'])) {

      $username = $data['username'];

      $cek_user = $this->db->get_where('tb_user', ['username' => $username])->num_rows();

      if ($cek_user > 0) {
        echo json_encode([
          'status' => false,
          'message' => 'Username sudah terdaftar! Silakan pilih username lain.'
        ]);
        return;
      }

      $insert_data = [
        'nama'         => $data['nama'],
        'jenisKelamin' => 'Laki-Laki',
        'telp'         => $data['telp'],
        'email'        => $data['email'],
        'alamat'       => $data['alamat'],
        'username'     => $username,
        'password'     => password_hash($data['password'], PASSWORD_BCRYPT),
        'foto'         => 'no-image.png',
        'skin'         => 'green',
        'level'        => 'Nasabah',
        'login'        => 'Tidak',
        'terdaftar'    => date('Y-m-d H:i:s')
      ];

      $insert = $this->db->insert('tb_user', $insert_data);

      if ($insert) {
        // ==========================================
        // 🔥 FITUR NOTIFIKASI (PUSH EXPO & IN-APP DATABASE)
        // ==========================================

        // 1. Ambil data ID dan expo_token milik semua Admin
        $this->db->select('id, expo_token');
        $this->db->where_in('level', ['Administrator', 'Super Admin']);
        $admins = $this->db->get('tb_user')->result();

        $notif_database = []; // Array untuk menyimpan ke tb_notifikasi

        foreach ($admins as $admin) {

          // A. Siapkan data untuk In-App Notification (Database)
          $notif_database[] = [
            'id_user' => $admin->id,
            'judul'   => 'Pendaftar Nasabah Baru! 👤',
            'pesan'   => 'Nasabah baru atas nama ' . $data['nama'] . ' baru saja mendaftar. Segera cek dan verifikasi akunnya.',
            'is_read' => 0,
            'tanggal' => date('Y-m-d H:i:s')
          ];

          // B. Kirim Push Notification Expo menggunakan fungsi bawaan API Bapak
          if (!empty($admin->expo_token)) {
            $this->send_expo_push_notification(
              $admin->expo_token,
              "Pendaftar Nasabah Baru! 👤",
              "Nasabah baru atas nama " . $data['nama'] . " baru saja mendaftar. Segera cek dan verifikasi akunnya."
            );
          }
        }

        // 2. Simpan ke Database (tb_notifikasi) secara massal
        if (count($notif_database) > 0) {
          $this->db->insert_batch('tb_notifikasi', $notif_database);
        }
        // ==========================================

        echo json_encode([
          'status' => true,
          'message' => 'Pendaftaran berhasil. Silakan tunggu Admin memverifikasi akun Anda sebelum login.'
        ]);
      } else {
        echo json_encode([
          'status' => false,
          'message' => 'Gagal mendaftar, terjadi kesalahan pada database server.'
        ]);
      }
    } else {
      echo json_encode([
        'status' => false,
        'message' => 'Data pendaftaran tidak lengkap.'
      ]);
    }
  }

  public function get_nasabah_baru()
  {
    header("Access-Control-Allow-Origin: *");
    header("Content-Type: application/json; charset=UTF-8");

    $this->db->select('id, nama, username, telp, alamat, terdaftar');
    $this->db->from('tb_user');
    $this->db->where('level', 'Nasabah');
    $this->db->where('login', 'Tidak');
    $this->db->order_by('id', 'DESC');
    $query = $this->db->get();

    if ($query->num_rows() > 0) {
      echo json_encode(['status' => true, 'data' => $query->result()]);
    } else {
      echo json_encode(['status' => false, 'message' => 'Tidak ada pendaftar baru.']);
    }
  }

  public function verifikasi_nasabah()
  {
    header("Access-Control-Allow-Origin: *");
    header("Content-Type: application/json; charset=UTF-8");
    header("Access-Control-Allow-Methods: POST");

    $json = file_get_contents('php://input');
    $data = json_decode($json, true);

    if (!empty($data['id_user'])) {
      $this->db->where('id', $data['id_user']);
      $update = $this->db->update('tb_user', ['login' => 'Ya']);

      if ($update) {
        echo json_encode(['status' => true, 'message' => 'Akun nasabah berhasil diaktifkan!']);
      } else {
        echo json_encode(['status' => false, 'message' => 'Gagal memverifikasi akun.']);
      }
    } else {
      echo json_encode(['status' => false, 'message' => 'ID User tidak valid.']);
    }
  }

  public function tolak_nasabah()
  {
    header("Access-Control-Allow-Origin: *");
    header("Content-Type: application/json; charset=UTF-8");
    header("Access-Control-Allow-Methods: POST");

    $json = file_get_contents('php://input');
    $data = json_decode($json, true);

    if (!empty($data['id_user'])) {
      $this->db->where('id', $data['id_user']);
      $delete = $this->db->delete('tb_user');

      if ($delete) {
        echo json_encode(['status' => true, 'message' => 'Pendaftaran nasabah berhasil ditolak (dihapus).']);
      } else {
        echo json_encode(['status' => false, 'message' => 'Gagal menolak pendaftaran.']);
      }
    } else {
      echo json_encode(['status' => false, 'message' => 'ID User tidak valid.']);
    }
  }

  public function tambah_nasabah()
  {
    header("Access-Control-Allow-Origin: *");
    header("Content-Type: application/json; charset=UTF-8");
    header("Access-Control-Allow-Methods: POST");

    $json = file_get_contents('php://input');
    $data = json_decode($json, true);

    if (!empty($data['nama']) && !empty($data['username']) && !empty($data['password'])) {

      $username = $data['username'];

      $cek_user = $this->db->get_where('tb_user', ['username' => $username])->num_rows();

      if ($cek_user > 0) {
        echo json_encode([
          'status' => false,
          'message' => 'Username sudah terdaftar! Silakan gunakan username lain.'
        ]);
        return;
      }

      $insert_data = [
        'nama'         => $data['nama'],
        'jenisKelamin' => 'Laki-Laki',
        'telp'         => $data['telp'],
        'email'        => $data['email'],
        'alamat'       => $data['alamat'],
        'username'     => $username,
        'password'     => password_hash($data['password'], PASSWORD_BCRYPT),
        'foto'         => 'no-image.png',
        'skin'         => 'green',
        'level'        => 'Nasabah',
        'login'        => 'Ya',
        'terdaftar'    => date('Y-m-d H:i:s')
      ];

      $insert = $this->db->insert('tb_user', $insert_data);

      if ($insert) {
        echo json_encode([
          'status' => true,
          'message' => 'Nasabah baru berhasil ditambahkan dan akun langsung aktif!'
        ]);
      } else {
        echo json_encode([
          'status' => false,
          'message' => 'Gagal menambahkan nasabah ke database.'
        ]);
      }
    } else {
      echo json_encode([
        'status' => false,
        'message' => 'Data pendaftaran tidak lengkap.'
      ]);
    }
  }

  // 🔥 FUNGSI INFAQ YANG SUDAH DILENGKAPI NOTIFIKASI WA & PUSH 🔥
  public function simpan_infaq()
  {
    header("Access-Control-Allow-Origin: *");
    header("Content-Type: application/json; charset=UTF-8");
    header("Access-Control-Allow-Methods: POST");

    $json = file_get_contents('php://input');
    $data = json_decode($json, true);

    if (!empty($data['id_nasabah']) && !empty($data['nominal'])) {

      // Bersihkan format nominal dari titik
      $nominal = str_replace('.', '', $data['nominal']);
      $keterangan_infaq = !empty($data['keterangan']) ? $data['keterangan'] : 'Infaq Umum';

      $insert_data = [
        'idAdmin'           => 0,
        'idNasabah'         => $data['id_nasabah'],
        'idPotongan'        => 0,
        'tanggal'           => date('Y-m-d'),
        'nominal'           => $nominal,
        'jenis'             => 'Keluar',
        'keterangan'        => 'INFAQ: ' . $keterangan_infaq,
        'status_konfirmasi' => 'Sukses',
        'terdaftar'         => date('Y-m-d H:i:s')
      ];

      $insert = $this->db->insert('tb_transaksi', $insert_data);

      if ($insert) {
        // =======================================================
        // 🔥 BAGIAN BARU: KIRIM NOTIFIKASI SETELAH INFAQ SUKSES
        // =======================================================

        // 1. Ambil data Nasabah yang berinfaq
        $this->db->where('id', $data['id_nasabah']);
        $nasabah = $this->db->get('tb_user')->row();
        $nama_nasabah = $nasabah ? $nasabah->nama : 'Hamba Allah';
        $token_nasabah = $nasabah ? $nasabah->expo_token : '';
        $nominal_format = 'Rp ' . number_format($nominal, 0, ',', '.');

        // 2. Notifikasi WhatsApp ke Admin
        $pesan_wa = "💖 *INFO INFAQ / SEDEKAH BARU*\n\n";
        $pesan_wa .= "Alhamdulillah, telah masuk infaq:\n";
        $pesan_wa .= "👤 *Dari:* " . $nama_nasabah . "\n";
        $pesan_wa .= "💰 *Nominal:* " . $nominal_format . "\n";
        $pesan_wa .= "📌 *Doa/Niat:* " . ($keterangan_infaq ? $keterangan_infaq : '-') . "\n\n";
        $pesan_wa .= "Semoga Allah memberikan keberkahan pada harta yang tersisa.";

        $nomor_admin = '081234567890'; // 🔥 GANTI DENGAN NOMOR WA ADMIN
        $this->send_whatsapp($nomor_admin, $pesan_wa);

        // 3. Push Notification Expo ke Semua Admin
        $this->db->where_in('level', ['Administrator', 'Super Admin']);
        $this->db->where('expo_token !=', NULL);
        $admins = $this->db->get('tb_user')->result();

        foreach ($admins as $admin) {
          $this->send_expo_push_notification(
            $admin->expo_token,
            "💖 Alhamdulillah, Infaq Baru Masuk",
            "Infaq dari {$nama_nasabah} sebesar {$nominal_format} telah diterima sistem."
          );
        }

        // 4. Push Notification Expo ke Nasabah (Apresiasi)
        if (!empty($token_nasabah)) {
          $this->send_expo_push_notification(
            $token_nasabah,
            "✅ Alhamdulillah, Infaq Berhasil",
            "Terima kasih atas infaq sebesar {$nominal_format}. Semoga menjadi pembersih harta dan jiwa serta dicatat sebagai amal soleh."
          );
        }

        // =======================================================

        echo json_encode([
          'status' => true,
          'message' => 'Alhamdulillah, Infaq berhasil disalurkan. Semoga menjadi amal jariyah!'
        ]);
      } else {
        echo json_encode([
          'status' => false,
          'message' => 'Gagal memproses Infaq. Silakan coba lagi.'
        ]);
      }
    } else {
      echo json_encode([
        'status' => false,
        'message' => 'Data nominal infaq tidak lengkap.'
      ]);
    }
  }

  // ==========================================
  // 11. ENDPOINT TARGET TABUNGAN (CELENGAN IMPIAN)
  // ==========================================

  // A. Mengambil daftar target milik nasabah
  public function get_target()
  {
    header("Access-Control-Allow-Origin: *");
    header("Content-Type: application/json; charset=UTF-8");
    header("Access-Control-Allow-Methods: POST");

    $request = json_decode($this->input->raw_input_stream, true);
    $id_nasabah = $request['id_nasabah'] ?? '';

    if (empty($id_nasabah)) {
      echo json_encode(['status' => false, 'message' => 'ID Nasabah tidak valid.']);
      return;
    }

    $this->db->where('id_nasabah', $id_nasabah);
    $this->db->order_by('id', 'DESC');
    $data = $this->db->get('tb_target')->result_array();

    // Hitung persentase terkumpul
    $formatted_data = [];
    foreach ($data as $row) {
      $persentase = ($row['terkumpul'] / $row['nominal_target']) * 100;
      $row['persentase'] = round($persentase, 1);
      $formatted_data[] = $row;
    }

    echo json_encode(['status' => true, 'data' => $formatted_data]);
  }

  // B. Membuat target baru
  public function simpan_target()
  {
    header("Access-Control-Allow-Origin: *");
    header("Content-Type: application/json; charset=UTF-8");
    header("Access-Control-Allow-Methods: POST");

    $request = json_decode($this->input->raw_input_stream, true);

    $id_nasabah = $request['id_nasabah'] ?? '';
    $nama_target = $request['nama_target'] ?? '';
    $nominal_target = str_replace('.', '', $request['nominal_target'] ?? '0');

    if (empty($id_nasabah) || empty($nama_target) || empty($nominal_target)) {
      echo json_encode(['status' => false, 'message' => 'Data target tidak lengkap.']);
      return;
    }

    $data = [
      'id_nasabah' => $id_nasabah,
      'nama_target' => $nama_target,
      'nominal_target' => $nominal_target,
      'terkumpul' => 0, // Awal buat pasti 0
      'terdaftar' => date('Y-m-d H:i:s')
    ];

    $insert = $this->db->insert('tb_target', $data);

    if ($insert) {
      echo json_encode(['status' => true, 'message' => 'Tabungan impian berhasil dibuat! Ayo semangat menabung.']);
    } else {
      echo json_encode(['status' => false, 'message' => 'Gagal membuat target.']);
    }
  }
  // C. Top Up Target (Isi Celengan)
  public function topup_target()
  {
    header("Access-Control-Allow-Origin: *");
    header("Content-Type: application/json; charset=UTF-8");
    header("Access-Control-Allow-Methods: POST");

    $request = json_decode($this->input->raw_input_stream, true);

    $id_target = $request['id_target'] ?? '';
    $id_nasabah = $request['id_nasabah'] ?? '';
    $nominal = str_replace('.', '', $request['nominal'] ?? '0');

    if (empty($id_target) || empty($id_nasabah) || empty($nominal)) {
      echo json_encode(['status' => false, 'message' => 'Data tidak lengkap.']);
      return;
    }

    // Cek apakah target ada
    $this->db->where('id', $id_target);
    $target = $this->db->get('tb_target')->row();

    if (!$target) {
      echo json_encode(['status' => false, 'message' => 'Target tidak ditemukan.']);
      return;
    }

    // 1. Potong saldo utama dengan mencatat di tb_transaksi sebagai Keluar
    $insert_trx = [
      'idAdmin'           => 0,
      'idNasabah'         => $id_nasabah,
      'idPotongan'        => 0,
      'tanggal'           => date('Y-m-d'),
      'nominal'           => $nominal,
      'jenis'             => 'Keluar',
      'keterangan'        => 'Isi Tabungan: ' . $target->nama_target,
      'status_konfirmasi' => 'Sukses', // Otomatis sukses memotong saldo
      'terdaftar'         => date('Y-m-d H:i:s')
    ];
    $this->db->insert('tb_transaksi', $insert_trx);

    // 2. Tambahkan uang ke kolom terkumpul di tb_target
    $terkumpul_baru = $target->terkumpul + $nominal;
    $this->db->where('id', $id_target);
    $update_target = $this->db->update('tb_target', ['terkumpul' => $terkumpul_baru]);

    if ($update_target) {
      echo json_encode(['status' => true, 'message' => 'Alhamdulillah, tabungan berhasil diisi! Semangat terus nabungnya.']);
    } else {
      echo json_encode(['status' => false, 'message' => 'Gagal mengisi tabungan.']);
    }
  }

  // D. Hapus Target (Celengan) & Refund Saldo
  public function hapus_target()
  {
    header("Access-Control-Allow-Origin: *");
    header("Content-Type: application/json; charset=UTF-8");
    header("Access-Control-Allow-Methods: POST");

    $request = json_decode($this->input->raw_input_stream, true);
    $id_target = $request['id_target'] ?? '';

    if (empty($id_target)) {
      echo json_encode(['status' => false, 'message' => 'ID Target tidak valid.']);
      return;
    }

    // 1. Ambil info target sebelum dihapus
    $this->db->where('id', $id_target);
    $target = $this->db->get('tb_target')->row();

    if ($target) {
      // 2. Jika ada dana yang sudah terkumpul, kembalikan ke saldo utama (Refund)
      if ($target->terkumpul > 0) {
        $insert_trx = [
          'idAdmin'           => 0,
          'idNasabah'         => $target->id_nasabah,
          'idPotongan'        => 0,
          'tanggal'           => date('Y-m-d'),
          'nominal'           => $target->terkumpul,
          'jenis'             => 'Masuk', // Menambah saldo utama
          'keterangan'        => 'Refund Hapus Target: ' . $target->nama_target,
          'status_konfirmasi' => 'Sukses',
          'terdaftar'         => date('Y-m-d H:i:s')
        ];
        $this->db->insert('tb_transaksi', $insert_trx);
      }

      // 3. Hapus target dari database
      $this->db->where('id', $id_target);
      $delete = $this->db->delete('tb_target');

      if ($delete) {
        echo json_encode([
          'status' => true,
          'message' => 'Target berhasil dihapus. Dana yang terkumpul otomatis dikembalikan ke Saldo Utama.'
        ]);
      } else {
        echo json_encode(['status' => false, 'message' => 'Gagal menghapus target.']);
      }
    } else {
      echo json_encode(['status' => false, 'message' => 'Target tidak ditemukan.']);
    }
  }
  // ==========================================
  // E. Ambil Semua Target Untuk Admin (Pantau Target)
  // ==========================================
  public function get_all_target()
  {
    header("Access-Control-Allow-Origin: *");
    header("Content-Type: application/json; charset=UTF-8");
    header("Access-Control-Allow-Methods: POST");

    $request = json_decode($this->input->raw_input_stream, true);
    $level = $request['level'] ?? '';

    if ($level !== 'Administrator' && $level !== 'Super Admin') {
      echo json_encode(['status' => false, 'message' => 'Akses ditolak.']);
      return;
    }

    // Ambil data target beserta nama nasabahnya dari tb_user
    $this->db->select('tb_target.*, tb_user.nama as nama_nasabah');
    $this->db->from('tb_target');
    $this->db->join('tb_user', 'tb_target.id_nasabah = tb_user.id', 'left');
    $this->db->order_by('tb_target.id', 'DESC');
    $data = $this->db->get()->result_array();

    $formatted_data = [];
    foreach ($data as $row) {
      // Hindari pembagian dengan nol
      if ($row['nominal_target'] > 0) {
        $persentase = ($row['terkumpul'] / $row['nominal_target']) * 100;
      } else {
        $persentase = 0;
      }

      $row['persentase'] = round($persentase, 1);
      $formatted_data[] = $row;
    }

    echo json_encode(['status' => true, 'data' => $formatted_data]);
  }

  // ==========================================
  // F. Ambil Saldo Seluruh Nasabah (Khusus Admin)
  // ==========================================
  public function get_all_nasabah_saldo()
  {
    header("Access-Control-Allow-Origin: *");
    header("Content-Type: application/json; charset=UTF-8");
    header("Access-Control-Allow-Methods: POST");

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

    $data_saldo = [];
    foreach ($nasabah as $row) {
      $id_user = $row['id'];

      // Hitung rumus saldo masing-masing nasabah secara akurat
      $tbMsk = $this->db->query('SELECT SUM(nominal) AS total FROM tb_transaksi WHERE idNasabah="' . $id_user . '" AND jenis="Masuk" AND status_konfirmasi="Sukses"')->row()->total ?? 0;
      $tfMsk = $this->db->query('SELECT SUM(nominal) AS total FROM tb_transfer WHERE idPenerima="' . $id_user . '"')->row()->total ?? 0;
      $totalMasuk = $tbMsk + $tfMsk;

      $tbKlr = $this->db->query('SELECT SUM(nominal) AS total FROM tb_transaksi WHERE idNasabah="' . $id_user . '" AND jenis="Keluar" AND status_konfirmasi="Sukses"')->row()->total ?? 0;
      $tfKlr = $this->db->query('SELECT SUM(nominal) AS total FROM tb_transfer WHERE idPengirim="' . $id_user . '"')->row()->total ?? 0;
      $totalKeluar = $tbKlr + $tfKlr;

      $saldo = $totalMasuk - $totalKeluar;

      $data_saldo[] = [
        'id' => $id_user,
        'nama' => $row['nama'],
        'username' => $row['username'],
        'foto' => $row['foto'],
        'saldo' => $saldo
      ];
    }

    echo json_encode(['status' => true, 'data' => $data_saldo]);
  }

  // ==========================================
  // G. Validasi PIN Transaksi 6-Digit
  // ==========================================
  public function cek_pin()
  {
    header("Access-Control-Allow-Origin: *");
    header("Content-Type: application/json; charset=UTF-8");
    header("Access-Control-Allow-Methods: POST");

    $request = json_decode($this->input->raw_input_stream, true);
    $id_user = $request['id_user'] ?? '';
    $pin = $request['pin'] ?? '';

    if (empty($id_user) || empty($pin)) {
      echo json_encode(['status' => false, 'message' => 'PIN tidak boleh kosong.']);
      return;
    }

    $this->db->where('id', $id_user);
    $user = $this->db->get('tb_user')->row();

    // Cek apakah user ada dan PIN-nya cocok
    if ($user && $user->pin === $pin) {
      echo json_encode(['status' => true, 'message' => 'PIN Valid.']);
    } else {
      echo json_encode(['status' => false, 'message' => 'PIN yang Anda masukkan salah!']);
    }
  }

  // ==========================================
  // H. Ubah PIN Transaksi
  // ==========================================
  public function ubah_pin()
  {
    header("Access-Control-Allow-Origin: *");
    header("Content-Type: application/json; charset=UTF-8");
    header("Access-Control-Allow-Methods: POST");

    $request = json_decode($this->input->raw_input_stream, true);
    $id_user = $request['id_user'] ?? '';
    $pin_lama = $request['pin_lama'] ?? '';
    $pin_baru = $request['pin_baru'] ?? '';

    if (empty($id_user) || empty($pin_lama) || empty($pin_baru)) {
      echo json_encode(['status' => false, 'message' => 'Semua kolom wajib diisi.']);
      return;
    }

    if (strlen($pin_baru) !== 6) {
      echo json_encode(['status' => false, 'message' => 'PIN baru harus terdiri dari 6 digit angka.']);
      return;
    }

    // Ambil data user
    $this->db->where('id', $id_user);
    $user = $this->db->get('tb_user')->row();

    // Cocokkan PIN Lama
    if ($user && $user->pin === $pin_lama) {
      // Update ke PIN Baru
      $this->db->where('id', $id_user);
      $update = $this->db->update('tb_user', ['pin' => $pin_baru]);

      if ($update) {
        echo json_encode(['status' => true, 'message' => 'PIN transaksi berhasil diperbarui!']);
      } else {
        echo json_encode(['status' => false, 'message' => 'Terjadi kesalahan sistem, gagal mengubah PIN.']);
      }
    } else {
      echo json_encode(['status' => false, 'message' => 'PIN Lama yang Anda masukkan salah!']);
    }
  }

  public function export_laporan_kas()
  {
    // 1. Tangkap parameter tanggal dari React Native
    $start = $this->input->get('start');
    $end = $this->input->get('end');

    // 2. Buat nama file menjadi dinamis berdasarkan periode
    if (!empty($start) && !empty($end)) {
      $nama_file = "Laporan_Kas_{$start}_sd_{$end}.csv";
    } else {
      $nama_file = "Laporan_Kas_Semua_" . date('Y-m-d') . ".csv";
    }

    header("Content-Type: text/csv; charset=utf-8");
    header("Content-Disposition: attachment; filename={$nama_file}");

    $output = fopen('php://output', 'w');

    // BOM UTF-8 agar Excel mengenali enkripsi file
    fprintf($output, chr(0xEF) . chr(0xBB) . chr(0xBF));
    fputcsv($output, ['No', 'ID Transaksi', 'Tanggal', 'Nama Anggota', 'Jenis', 'Nominal', 'Keterangan', 'Status'], ';');

    // 3. Siapkan kondisi filter tanggal untuk SQL
    $where_date = "";
    if (!empty($start) && !empty($end)) {
      $where_date = " AND t.tanggal >= '{$start}' AND t.tanggal <= '{$end}' ";
    }

    // 4. Sisipkan kondisi tanggal ke dalam Query Utama
    $sql = "SELECT t.id, t.tanggal, u.nama, t.jenis, t.nominal, t.keterangan, t.status_konfirmasi 
            FROM tb_transaksi t 
            LEFT JOIN tb_user u ON t.idNasabah = u.id 
            WHERE t.status_konfirmasi = 'Sukses' 
            {$where_date} 
            ORDER BY t.tanggal DESC";

    $query = $this->db->query($sql)->result_array();

    $no = 1;
    foreach ($query as $row) {
      fputcsv($output, [
        $no++,
        'TX-' . $row['id'],
        $row['tanggal'],
        $row['nama'] ?? 'Nasabah Umum',
        $row['jenis'],
        $row['nominal'],
        $row['keterangan'],
        $row['status_konfirmasi']
      ], ';');
    }
    fclose($output);
  }

  // ==========================================
  // FITUR MARKETPLACE: MANAJEMEN TOKO
  // ==========================================

  // 1. Endpoint Cek Status Toko Nasabah
  public function cek_toko()
  {
    $request = json_decode($this->input->raw_input_stream, true);
    $id_user = $request['id_user'] ?? '';

    if (empty($id_user)) {
      echo json_encode(['status' => false, 'message' => 'ID User tidak valid.']);
      return;
    }

    // Cari toko berdasarkan ID Nasabah
    $this->db->where('id_user', $id_user);
    $toko = $this->db->get('tb_toko')->row();

    if ($toko) {
      echo json_encode(['status' => true, 'data' => $toko]);
    } else {
      echo json_encode(['status' => false, 'message' => 'Nasabah belum memiliki toko.']);
    }
  }

  // 2. Endpoint Buka Toko Baru
  public function buka_toko()
  {
    $request = json_decode($this->input->raw_input_stream, true);

    $id_user = $request['id_user'] ?? '';
    $nama_toko = $request['nama_toko'] ?? '';
    $deskripsi = $request['deskripsi'] ?? '';

    if (empty($id_user) || empty($nama_toko)) {
      echo json_encode(['status' => false, 'message' => 'Data tidak lengkap. Nama toko wajib diisi!']);
      return;
    }

    // Cek keamanan: Pastikan 1 nasabah hanya bisa punya 1 toko
    $this->db->where('id_user', $id_user);
    $cek_toko = $this->db->get('tb_toko')->num_rows();

    if ($cek_toko > 0) {
      echo json_encode(['status' => false, 'message' => 'Anda sudah memiliki toko yang terdaftar.']);
      return;
    }

    $data = [
      'id_user' => $id_user,
      'nama_toko' => $nama_toko,
      'deskripsi_toko' => $deskripsi,
      'terdaftar' => date('Y-m-d H:i:s')
    ];

    $insert = $this->db->insert('tb_toko', $data);

    if ($insert) {
      echo json_encode(['status' => true, 'message' => 'Alhamdulillah! Toko Anda berhasil dibuka.']);
    } else {
      echo json_encode(['status' => false, 'message' => 'Gagal membuka toko. Terjadi kesalahan server.']);
    }
  }
  // ==========================================
  // FITUR MARKETPLACE: MANAJEMEN TOKO
  // ==========================================

  // Endpoint Edit Toko (Sisi Penjual)
  public function edit_toko()
  {
    // 🔥 1. Bersihkan output sebelumnya agar JSON tidak rusak oleh Warning PHP
    if (ob_get_length()) ob_clean();
    header('Content-Type: application/json');
    header('Access-Control-Allow-Origin: *');

    $request = json_decode($this->input->raw_input_stream, true);

    $id_toko = $request['id_toko'] ?? '';
    $id_user = $request['id_user'] ?? '';
    $nama_toko = $request['nama_toko'] ?? '';
    $deskripsi = $request['deskripsi'] ?? '';
    $foto_base64 = $request['foto_toko_base64'] ?? ''; // Tangkap foto base64

    if (empty($id_toko) || empty($id_user) || empty($nama_toko)) {
      echo json_encode(['status' => false, 'message' => 'Data tidak lengkap.']);
      return;
    }

    $update_data = [
      'nama_toko' => $nama_toko,
      'deskripsi_toko' => $deskripsi
    ];

    // 🔥 LOGIKA UPLOAD FOTO TOKO DIPERBARUI
    if (!empty($foto_base64)) {
      // 🔥 2. Cek apakah folder toko sudah ada, jika belum otomatis buat foldernya
      $folder_path = FCPATH . 'assets/toko/';
      if (!is_dir($folder_path)) {
        mkdir($folder_path, 0755, true);
      }

      $image_parts = explode(";base64,", $foto_base64);
      if (count($image_parts) == 2) {
        $image_type_aux = explode("image/", $image_parts[0]);
        $image_type = $image_type_aux[1];
        $image_base64 = base64_decode($image_parts[1]);

        $file_name = 'toko_' . time() . '_' . rand(100, 999) . '.' . $image_type;
        $file_path = $folder_path . $file_name;

        // 🔥 3. Tambahkan @ agar kalaupun gagal simpan, tidak merusak output JSON
        if (@file_put_contents($file_path, $image_base64)) {
          $update_data['foto_toko'] = $file_name;
        }
      }
    }

    $this->db->where('id_toko', $id_toko);
    $this->db->where('id_user', $id_user);
    $update = $this->db->update('tb_toko', $update_data);

    // Walaupun data sama (tidak ada yang diubah), kita anggap sukses agar user tidak bingung
    if ($update || $this->db->affected_rows() >= 0) {
      echo json_encode(['status' => true, 'message' => 'Informasi toko berhasil disimpan.']);
    } else {
      echo json_encode(['status' => false, 'message' => 'Gagal memperbarui toko.']);
    }
    exit;
  }

  // Endpoint Ubah Status Toko (Nonaktif/Aktif - Sisi Admin)
  public function ubah_status_toko()
  {
    $request = json_decode($this->input->raw_input_stream, true);

    $id_toko = $request['id_toko'] ?? '';
    $status_baru = $request['status'] ?? ''; // 'Aktif' atau 'Nonaktif'

    if (empty($id_toko) || empty($status_baru)) {
      echo json_encode(['status' => false, 'message' => 'Data tidak valid.']);
      return;
    }

    $this->db->where('id_toko', $id_toko);
    $update = $this->db->update('tb_toko', ['status_toko' => $status_baru]);

    if ($update) {
      // 🔥 PERBAIKAN: Tangani status produk untuk kedua kondisi (Nonaktif dan Aktif)
      if ($status_baru === 'Nonaktif') {
        // Jika toko dinonaktifkan, arsipkan semua produk
        $this->db->where('id_toko', $id_toko);
        $this->db->update('tb_produk', ['status_produk' => 'Arsip']);
      } else if ($status_baru === 'Aktif') {
        // Jika toko diaktifkan kembali, kembalikan produk menjadi tersedia
        $this->db->where('id_toko', $id_toko);
        $this->db->update('tb_produk', ['status_produk' => 'Tersedia']);
      }

      echo json_encode(['status' => true, 'message' => "Toko berhasil di-{$status_baru}kan."]);
    } else {
      echo json_encode(['status' => false, 'message' => 'Gagal mengubah status toko.']);
    }
  }
  // Endpoint Hapus Toko Secara Permanen (Sisi Admin)
  public function hapus_toko()
  {
    $request = json_decode($this->input->raw_input_stream, true);
    $id_toko = $request['id_toko'] ?? '';

    if (empty($id_toko)) {
      echo json_encode(['status' => false, 'message' => 'ID Toko tidak valid.']);
      return;
    }

    // 1. Ambil data produk terkait untuk dihapus fotonya (Opsional jika ingin membersihkan server)
    // 2. Hapus semua produk dari toko ini
    $this->db->where('id_toko', $id_toko);
    $this->db->delete('tb_produk');

    // 3. Hapus Toko
    $this->db->where('id_toko', $id_toko);
    $delete = $this->db->delete('tb_toko');

    if ($delete) {
      echo json_encode(['status' => true, 'message' => 'Toko beserta seluruh produknya berhasil dihapus permanen.']);
    } else {
      echo json_encode(['status' => false, 'message' => 'Gagal menghapus toko.']);
    }
  }

  // Endpoint Admin: Ambil Semua Daftar Toko
  public function admin_get_semua_toko()
  {
    $request = json_decode($this->input->raw_input_stream, true);
    $level = $request['level'] ?? '';

    if ($level !== 'Administrator' && $level !== 'Super Admin') {
      echo json_encode(['status' => false, 'message' => 'Akses ditolak. Khusus Admin.']);
      return;
    }

    $this->db->select('tb_toko.*, tb_user.nama as nama_pemilik');
    $this->db->from('tb_toko');
    $this->db->join('tb_user', 'tb_toko.id_user = tb_user.id', 'left');
    $this->db->order_by('tb_toko.id_toko', 'DESC');
    $toko = $this->db->get()->result_array();

    echo json_encode(['status' => true, 'data' => $toko]);
  }
  // ==========================================
  // FITUR MARKETPLACE: MANAJEMEN PRODUK TOKO
  // ==========================================

  // 3. Endpoint Ambil Produk Milik Toko (Dasbor Penjual)
  public function get_produk_toko()
  {
    $request = json_decode($this->input->raw_input_stream, true);
    $id_toko = $request['id_toko'] ?? '';

    if (empty($id_toko)) {
      echo json_encode(['status' => false, 'message' => 'ID Toko tidak valid.']);
      return;
    }

    // Ambil semua produk yang dijual oleh toko tersebut
    $this->db->where('id_toko', $id_toko);
    $this->db->where('status_produk !=', 'Arsip');
    $this->db->order_by('id_produk', 'DESC');
    $produk = $this->db->get('tb_produk')->result_array();

    echo json_encode(['status' => true, 'data' => $produk]);
  }

  // 4. Endpoint Tambah Produk Baru ke Etalase (Mendukung 3 Foto, Harga Coret & Kategori)
  public function tambah_produk()
  {
    $request = json_decode($this->input->raw_input_stream, true);

    $id_toko = $request['id_toko'] ?? '';
    $nama_produk = $request['nama_produk'] ?? '';
    // 🔥 TAMBAHAN: Tangkap kategori
    $kategori = $request['kategori'] ?? 'Sembako';
    $deskripsi = $request['deskripsi_produk'] ?? '';
    $harga = str_replace('.', '', $request['harga'] ?? '0');
    $harga_coret = str_replace('.', '', $request['harga_coret'] ?? '0');
    $stok = $request['stok'] ?? 0;
    $berat = $request['berat'] ?? 1000;

    // Tangkap 3 Data Foto Base64
    $foto_base64 = $request['foto_base64'] ?? '';
    $foto_base64_2 = $request['foto_base64_2'] ?? '';
    $foto_base64_3 = $request['foto_base64_3'] ?? '';

    if (empty($id_toko) || empty($nama_produk) || empty($harga)) {
      echo json_encode(['status' => false, 'message' => 'Data produk tidak lengkap! Nama dan harga wajib diisi.']);
      return;
    }

    $upload_dir = FCPATH . 'assets/produk/';
    if (!is_dir($upload_dir)) {
      mkdir($upload_dir, 0777, true);
    }

    // Proses Foto 1 (Utama)
    $file_name_1 = 'no-product.png';
    if (!empty($foto_base64)) {
      $image_parts = explode(";base64,", $foto_base64);
      if (count($image_parts) == 2) {
        $image_base64 = base64_decode($image_parts[1]);
        $file_name_1 = 'produk_1_' . time() . '_' . uniqid() . '.jpg';
        file_put_contents($upload_dir . $file_name_1, $image_base64);
      }
    }

    // Proses Foto 2
    $file_name_2 = null;
    if (!empty($foto_base64_2)) {
      $image_parts = explode(";base64,", $foto_base64_2);
      if (count($image_parts) == 2) {
        $image_base64 = base64_decode($image_parts[1]);
        $file_name_2 = 'produk_2_' . time() . '_' . uniqid() . '.jpg';
        file_put_contents($upload_dir . $file_name_2, $image_base64);
      }
    }

    // Proses Foto 3
    $file_name_3 = null;
    if (!empty($foto_base64_3)) {
      $image_parts = explode(";base64,", $foto_base64_3);
      if (count($image_parts) == 2) {
        $image_base64 = base64_decode($image_parts[1]);
        $file_name_3 = 'produk_3_' . time() . '_' . uniqid() . '.jpg';
        file_put_contents($upload_dir . $file_name_3, $image_base64);
      }
    }

    $data = [
      'id_toko' => $id_toko,
      'nama_produk' => $nama_produk,
      'kategori' => $kategori, // 🔥 TAMBAHAN: Masukkan kategori ke database
      'deskripsi_produk' => $deskripsi,
      'harga' => $harga,
      'harga_coret' => $harga_coret,
      'stok' => $stok,
      'berat' => $berat,
      'foto_produk' => $file_name_1,
      'foto_2' => $file_name_2,
      'foto_3' => $file_name_3,
      'status_produk' => 'Tersedia',
      'terdaftar' => date('Y-m-d H:i:s')
    ];

    $insert = $this->db->insert('tb_produk', $data);

    if ($insert) {
      echo json_encode(['status' => true, 'message' => 'Produk berhasil ditambahkan ke etalase!']);
    } else {
      echo json_encode(['status' => false, 'message' => 'Gagal menambahkan produk. Terjadi kesalahan server.']);
    }
  }

  // 4B. Endpoint Edit Produk di Etalase (Mendukung 3 Foto, Harga Coret & Kategori)
  public function edit_produk()
  {
    $request = json_decode($this->input->raw_input_stream, true);

    $id_produk = $request['id_produk'] ?? '';
    $id_toko = $request['id_toko'] ?? '';
    $nama_produk = $request['nama_produk'] ?? '';
    // 🔥 TAMBAHAN: Tangkap kategori saat di-edit
    $kategori = $request['kategori'] ?? 'Sembako';
    $deskripsi = $request['deskripsi_produk'] ?? '';
    $harga = str_replace('.', '', $request['harga'] ?? '0');
    $harga_coret = str_replace('.', '', $request['harga_coret'] ?? '0');
    $stok = $request['stok'] ?? 0;
    $berat = $request['berat'] ?? 1000;

    // Tangkap 3 Data Foto Baru (Jika ada yang diunggah)
    $foto_base64 = $request['foto_base64'] ?? '';
    $foto_base64_2 = $request['foto_base64_2'] ?? '';
    $foto_base64_3 = $request['foto_base64_3'] ?? '';

    if (empty($id_produk) || empty($id_toko) || empty($nama_produk) || empty($harga)) {
      echo json_encode(['status' => false, 'message' => 'Data produk tidak lengkap! Nama dan harga wajib diisi.']);
      return;
    }

    $data = [
      'nama_produk' => $nama_produk,
      'kategori' => $kategori, // 🔥 TAMBAHAN: Update kategori di database
      'deskripsi_produk' => $deskripsi,
      'harga' => $harga,
      'harga_coret' => $harga_coret,
      'stok' => $stok,
      'berat' => $berat
    ];

    $upload_dir = FCPATH . 'assets/produk/';
    if (!is_dir($upload_dir)) {
      mkdir($upload_dir, 0777, true);
    }

    // Ambil data foto lama dari database untuk dihapus (agar hosting tidak penuh)
    $this->db->select('foto_produk, foto_2, foto_3');
    $this->db->where('id_produk', $id_produk);
    $old_foto = $this->db->get('tb_produk')->row();

    // 1. Proses Update Foto Utama (Foto 1)
    if (!empty($foto_base64)) {
      $image_parts = explode(";base64,", $foto_base64);
      if (count($image_parts) == 2) {
        $image_base64 = base64_decode($image_parts[1]);
        $file_name_1 = 'produk_1_' . time() . '_' . uniqid() . '.jpg';

        if (file_put_contents($upload_dir . $file_name_1, $image_base64)) {
          $data['foto_produk'] = $file_name_1;
          // Hapus foto 1 lama
          if ($old_foto && !empty($old_foto->foto_produk) && $old_foto->foto_produk !== 'no-product.png') {
            $old_path = $upload_dir . $old_foto->foto_produk;
            if (file_exists($old_path)) {
              unlink($old_path);
            }
          }
        }
      }
    }

    // 2. Proses Update Foto 2
    if (!empty($foto_base64_2)) {
      $image_parts = explode(";base64,", $foto_base64_2);
      if (count($image_parts) == 2) {
        $image_base64 = base64_decode($image_parts[1]);
        $file_name_2 = 'produk_2_' . time() . '_' . uniqid() . '.jpg';

        if (file_put_contents($upload_dir . $file_name_2, $image_base64)) {
          $data['foto_2'] = $file_name_2;
          // Hapus foto 2 lama
          if ($old_foto && !empty($old_foto->foto_2)) {
            $old_path = $upload_dir . $old_foto->foto_2;
            if (file_exists($old_path)) {
              unlink($old_path);
            }
          }
        }
      }
    }

    // 3. Proses Update Foto 3
    if (!empty($foto_base64_3)) {
      $image_parts = explode(";base64,", $foto_base64_3);
      if (count($image_parts) == 2) {
        $image_base64 = base64_decode($image_parts[1]);
        $file_name_3 = 'produk_3_' . time() . '_' . uniqid() . '.jpg';

        if (file_put_contents($upload_dir . $file_name_3, $image_base64)) {
          $data['foto_3'] = $file_name_3;
          // Hapus foto 3 lama
          if ($old_foto && !empty($old_foto->foto_3)) {
            $old_path = $upload_dir . $old_foto->foto_3;
            if (file_exists($old_path)) {
              unlink($old_path);
            }
          }
        }
      }
    }

    $this->db->where('id_produk', $id_produk);
    $this->db->where('id_toko', $id_toko); // Pastikan yang diedit benar-benar milik tokonya
    $update = $this->db->update('tb_produk', $data);

    if ($update) {
      echo json_encode(['status' => true, 'message' => 'Alhamdulillah, produk berhasil diperbarui!']);
    } else {
      echo json_encode(['status' => false, 'message' => 'Gagal memperbarui produk.']);
    }
  }

  // ==========================================
  // FITUR MARKETPLACE: SISI PEMBELI & CHECKOUT
  // ==========================================

  // 5. Endpoint Etalase Semua Toko (Beranda Marketplace)
  public function get_marketplace()
  {
    // 🔥 PERBAIKAN: Ubah menjadi POST agar bisa menangkap id_user dari aplikasi
    $request = json_decode($this->input->raw_input_stream, true);
    $id_user = $request['id_user'] ?? 0;

    $this->db->select('tb_produk.*, tb_toko.nama_toko, tb_toko.alamat_toko, tb_toko.foto_toko, tb_toko.deskripsi_toko, tb_user.alamat as alamat_penjual, tb_user.telp as no_hp_toko');

    // 🔥 TAMBAHAN BARU: Cek otomatis apakah barang ini sudah di-wishlist oleh user yang sedang login
    if (!empty($id_user)) {
      // Menggunakan subquery untuk menghasilkan nilai 1 (true) atau 0 (false)
      $this->db->select("(SELECT COUNT(id_wishlist) FROM tb_wishlist WHERE tb_wishlist.id_produk = tb_produk.id_produk AND tb_wishlist.id_pembeli = '$id_user') as is_wishlist");
    } else {
      $this->db->select("0 as is_wishlist");
    }

    // 🔥 TAMBAHAN BARU (UNTUK REKOMENDASI): Hitung TOTAL semua orang yang menjadikan produk ini wishlist
    $this->db->select("(SELECT COUNT(id_wishlist) FROM tb_wishlist WHERE tb_wishlist.id_produk = tb_produk.id_produk) as total_wishlist");

    $this->db->from('tb_produk');
    $this->db->join('tb_toko', 'tb_produk.id_toko = tb_toko.id_toko');
    $this->db->join('tb_user', 'tb_toko.id_user = tb_user.id', 'left');
    $this->db->where('tb_produk.stok >', 0);
    $this->db->where('tb_produk.status_produk', 'Tersedia');
    $this->db->where('tb_toko.status_toko', 'Aktif');
    $this->db->order_by('tb_produk.id_produk', 'DESC');
    $produk = $this->db->get()->result_array();

    echo json_encode(['status' => true, 'data' => $produk]);
  }

  // ==========================================
  // FITUR MARKETPLACE: VALIDASI KERANJANG
  // ==========================================
  public function cek_stok_keranjang()
  {
    $request = json_decode($this->input->raw_input_stream, true);
    $items = $request['items'] ?? [];

    if (empty($items)) {
      echo json_encode(['status' => false, 'message' => 'Keranjang kosong.']);
      return;
    }

    foreach ($items as $item) {
      $this->db->where('id_produk', $item['id_produk']);
      $this->db->where('status_produk', 'Tersedia'); // Pastikan produk tidak dihapus/diarsipkan
      $produk = $this->db->get('tb_produk')->row();

      if (!$produk) {
        echo json_encode(['status' => false, 'message' => 'Produk "' . $item['nama_produk'] . '" sudah ditarik atau dihapus oleh penjual. Silakan belanja ulang.']);
        return;
      }

      if ($produk->stok < $item['jumlah']) {
        echo json_encode(['status' => false, 'message' => 'Stok "' . $item['nama_produk'] . '" tidak mencukupi (Sisa: ' . $produk->stok . ').']);
        return;
      }
    }

    echo json_encode(['status' => true, 'message' => 'Aman']);
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
