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

        $summary['total'] =
            $summary['kewajiban_terbuka'] +
            $summary['menunggu_verifikasi'] +
            $summary['ditolak'];

        return $summary;
    }
}
