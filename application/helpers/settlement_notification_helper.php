<?php
defined('BASEPATH') or exit('No direct script access allowed');

if (!function_exists('settlement_notification_summary')) {
    /**
     * Ringkasan pekerjaan settlement yang masih membutuhkan perhatian.
     * Nilai disimpan selama satu request agar header dan sidebar tidak
     * menjalankan query yang sama dua kali.
     */
    function settlement_notification_summary()
    {
        static $summary = null;

        if ($summary !== null) {
            return $summary;
        }

        $summary = [
            'kewajiban_terbuka' => 0,
            'menunggu_verifikasi' => 0,
            'ditolak' => 0,
            'sengketa_escrow' => 0,
            'total_settlement' => 0,
            'total' => 0
        ];

        $ci = &get_instance();
        $level = strtolower(trim((string) $ci->session->userdata('level')));

        if (!in_array($level, ['administrator', 'super admin'], true)) {
            return $summary;
        }

        $isSuperAdmin = $level === 'super admin';
        $cabangId = (int) $ci->session->userdata('cabang_id');

        if (!$isSuperAdmin && $cabangId <= 0) {
            return $summary;
        }

        $ci->db->where('status', 'Terbuka');
        if (!$isSuperAdmin) {
            $ci->db->where('cabang_asal_id', $cabangId);
        }
        $summary['kewajiban_terbuka'] = (int) $ci->db
            ->count_all_results('tb_kewajiban_antar_cabang');

        $ci->db->where('status', 'MenungguVerifikasi');
        if (!$isSuperAdmin) {
            $ci->db->where('cabang_tujuan_id', $cabangId);
        }
        $summary['menunggu_verifikasi'] = (int) $ci->db
            ->count_all_results('tb_settlement_cabang');

        $ci->db->where('status', 'Ditolak');
        if (!$isSuperAdmin) {
            $ci->db->where('cabang_asal_id', $cabangId);
        }
        $summary['ditolak'] = (int) $ci->db
            ->count_all_results('tb_settlement_cabang');

        $ci->db->where('status', 'Sengketa');
        if (!$isSuperAdmin) {
            $ci->db->group_start();
            $ci->db->where('cabang_pembeli_id', $cabangId);
            $ci->db->or_where('cabang_penjual_id', $cabangId);
            $ci->db->group_end();
        }
        $summary['sengketa_escrow'] = (int) $ci->db
            ->count_all_results('tb_escrow_marketplace');

        $summary['total_settlement'] =
            $summary['kewajiban_terbuka'] +
            $summary['menunggu_verifikasi'] +
            $summary['ditolak'];

        $summary['total'] =
            $summary['total_settlement'] +
            $summary['sengketa_escrow'];

        return $summary;
    }
}
