<?php
defined('BASEPATH') or exit('No direct script access allowed');

class Cabang_scope
{
    private $ci;
    private $cachedCoordinatorBranches = null;

    public function __construct()
    {
        $this->ci = &get_instance();
    }

    public function level()
    {
        return strtolower(trim(
            (string) $this->ci->session->userdata('level')
        ));
    }

    public function isSuperAdmin()
    {
        return $this->level() === 'super admin';
    }

    public function isKoordinator()
    {
        return $this->level() === 'koordinator';
    }

    public function cabangIds()
    {
        if ($this->isSuperAdmin()) {
            return [];
        }

        if (!$this->isKoordinator()) {
            $cabangId = (int) $this->ci->session->userdata('cabang_id');
            return $cabangId > 0 ? [$cabangId] : [];
        }

        if ($this->cachedCoordinatorBranches !== null) {
            return $this->cachedCoordinatorBranches;
        }

        if (!$this->ci->db->table_exists('tb_koordinator_cabang')) {
            $this->cachedCoordinatorBranches = [];
            return $this->cachedCoordinatorBranches;
        }

        $rows = $this->ci->db
            ->select('kc.cabang_id')
            ->from('tb_koordinator_cabang AS kc')
            ->join('tb_cabang AS c', 'c.id = kc.cabang_id', 'inner')
            ->where(
                'kc.id_koordinator',
                (int) $this->ci->session->userdata('id')
            )
            ->where('kc.status', 'Aktif')
            ->where('c.status', 'Aktif')
            ->order_by('c.is_pusat', 'DESC')
            ->order_by('c.nama', 'ASC')
            ->get()
            ->result_array();

        $ids = [];

        foreach ($rows as $row) {
            $id = (int) $row['cabang_id'];
            if ($id > 0) {
                $ids[$id] = $id;
            }
        }

        $this->cachedCoordinatorBranches = array_values($ids);
        return $this->cachedCoordinatorBranches;
    }

    public function apply($column)
    {
        if ($this->isSuperAdmin()) {
            return;
        }

        $ids = $this->cabangIds();

        if (empty($ids)) {
            $this->ci->db->where('1 = 0', null, false);
            return;
        }

        if (count($ids) === 1) {
            $this->ci->db->where($column, $ids[0]);
            return;
        }

        $this->ci->db->where_in($column, $ids);
    }

    public function canAccess($cabangId)
    {
        if ($this->isSuperAdmin()) {
            return true;
        }

        return in_array((int) $cabangId, $this->cabangIds(), true);
    }

    public function cabangOptions()
    {
        $this->ci->db
            ->select(['id', 'kode', 'nama', 'status', 'is_pusat'])
            ->from('tb_cabang');

        if (!$this->isSuperAdmin()) {
            $ids = $this->cabangIds();

            if (empty($ids)) {
                $this->ci->db->where('1 = 0', null, false);
            } else {
                $this->ci->db->where_in('id', $ids);
            }
        }

        return $this->ci->db
            ->order_by('is_pusat', 'DESC')
            ->order_by('nama', 'ASC')
            ->get()
            ->result_array();
    }
}
