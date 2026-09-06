<?php
defined('BASEPATH') or exit('No direct script access allowed');

class GoldCron extends CI_Controller
{
    public function __construct()
    {
        parent::__construct();
        date_default_timezone_set('Asia/Jakarta');
        $this->load->database();
    }

    public function fetch_api()
    {
        // Kunci menggunakan parameter rahasia agar tidak bisa diakses sembarang orang via URL
        $token = $this->input->get('token');
        if ($token !== 'RAHASIA123') {
            die(json_encode(['status' => false, 'message' => 'Akses ditolak!']));
        }

        // 🔥 1. Tarik Harga Emas dalam Dollar (USD) dari GoldAPI
        $url_gold = "https://www.goldapi.io/api/XAU/USD";
        $ch1 = curl_init();
        curl_setopt($ch1, CURLOPT_URL, $url_gold);
        curl_setopt($ch1, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch1, CURLOPT_HTTPHEADER, [
            "x-access-token: goldapi-e0cbfca02a57500a1f4f46ed15ab4d54-io",
            "Content-Type: application/json"
        ]);
        $response_gold = curl_exec($ch1);
        curl_close($ch1);

        // 🔥 2. Tarik Kurs Dollar ke Rupiah (USD to IDR) dari API Gratis (Tanpa Key)
        $url_forex = "https://open.er-api.com/v6/latest/USD";
        $ch2 = curl_init();
        curl_setopt($ch2, CURLOPT_URL, $url_forex);
        curl_setopt($ch2, CURLOPT_RETURNTRANSFER, true);
        $response_forex = curl_exec($ch2);
        curl_close($ch2);

        if ($response_gold && $response_forex) {
            $data_gold = json_decode($response_gold, true);
            $data_forex = json_decode($response_forex, true);
            
            // Pastikan kedua data berhasil ditarik
            if (isset($data_gold['price']) && isset($data_forex['rates']['IDR'])) {
                
                $harga_ounce_usd = $data_gold['price']; // Harga emas per Troy Ounce dalam USD
                $kurs_idr = $data_forex['rates']['IDR']; // Kurs USD ke IDR hari ini
                
                // Konversi ke Harga Ounce dalam Rupiah
                $harga_ounce_idr = $harga_ounce_usd * $kurs_idr;

                // Harga dari API adalah per Troy Ounce. 1 Troy Ounce = 31.1035 Gram
                $hargaPerGram = $harga_ounce_idr / 31.1035;

                $today = date('Y-m-d');
                
                // Kalkulasi harga dengan margin bank/aplikasi (Contoh: Harga Beli +3%, Harga Jual -3%)
                $data_insert = [
                    'harga_beli' => round($hargaPerGram * 1.03), 
                    'harga_jual' => round($hargaPerGram * 0.97),
                    'tanggal'    => $today
                ];

                $cek = $this->db->get_where('tb_harga_emas', ['tanggal' => $today])->row();

                if ($cek) {
                    $this->db->where('tanggal', $today);
                    $this->db->update('tb_harga_emas', $data_insert);
                } else {
                    $this->db->insert('tb_harga_emas', $data_insert);
                }

                echo json_encode([
                    'status' => true, 
                    'message' => "Harga emas hari ini ($today) berhasil diupdate!",
                    'detail_kalkulasi' => [
                        'harga_usd_ounce' => $harga_ounce_usd,
                        'kurs_idr_hari_ini' => $kurs_idr,
                        'harga_1_gram_idr' => round($hargaPerGram)
                    ]
                ]);
            } else {
                echo json_encode([
                    'status' => false, 
                    'message' => 'Gagal mengambil data USD atau kurs IDR.',
                    'debug_gold' => $data_gold,
                    'debug_forex' => $data_forex
                ]);
            }
        } else {
            echo json_encode(['status' => false, 'message' => 'Gagal terhubung ke API penyedia harga.']);
        }
    }
}