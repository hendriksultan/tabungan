<?php
$userLevel = strtolower((string) $this->session->userdata('level'));

$namaCabang = $this->session->userdata('nama_cabang');
$kodeCabang = $this->session->userdata('kode_cabang');

if (empty($namaCabang)) {
    $namaCabang = 'Cabang belum ditentukan';
}

if (empty($kodeCabang)) {
    $kodeCabang = '-';
}

$isSuperAdmin = ($userLevel === 'super admin');
?>

<aside class="main-sidebar">
    <section class="sidebar">

        <!-- Informasi user dan cabang -->
        <div class="user-panel" style="min-height: 75px;">
            <div class="pull-left image">
                <div
                    style="
                        width: 45px;
                        height: 45px;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        border-radius: 50%;
                        background: rgba(255,255,255,.15);
                        color: #ffffff;
                        font-size: 20px;
                    ">
                    <i class="fa fa-building"></i>
                </div>
            </div>

            <div class="pull-left info">
                <p style="max-width: 165px; overflow: hidden; text-overflow: ellipsis;">
                    <?= html_escape($namaCabang) ?>
                </p>

                <a href="javascript:void(0)">
                    <i class="fa fa-circle text-success"></i>

                    <?php if ($isSuperAdmin): ?>
                        Pusat • Semua Cabang
                    <?php else: ?>
                        <?= html_escape($kodeCabang) ?>
                    <?php endif; ?>
                </a>
            </div>
        </div>

        <ul class="sidebar-menu" data-widget="tree">
            <li class="header">
                <?= $isSuperAdmin ? 'NAVIGASI PUSAT' : 'NAVIGASI CABANG' ?>
            </li>

            <li>
                <a href="<?= base_url('admin/dashboard') ?>">
                    <i class="fa fa-tachometer"></i>
                    <span>Dashboard</span>
                </a>
            </li>

            <li>
                <a href="<?= base_url('admin/transaksi') ?>">
                    <i class="fa fa-book"></i>
                    <span>Data Transaksi</span>
                </a>
            </li>

            <li>
                <a href="<?= base_url('admin/transfer') ?>">
                    <i class="fa fa-send"></i>
                    <span>Data Transfer</span>
                </a>
            </li>

            <?php if (
                $userLevel === 'administrator' ||
                $userLevel === 'super admin'
            ): ?>

                <li class="<?= $this->uri->segment(2) === 'laporan'
                    ? 'active'
                    : '' ?>">
                    <a href="<?= base_url('admin/laporan') ?>">
                        <i class="fa fa-bar-chart"></i>
                        <span>Laporan</span>
                    </a>
                </li>

                <li>
                    <a href="<?= base_url('admin/potongan') ?>">
                        <i class="fa fa-minus-circle"></i>
                        <span>Data Potongan</span>
                    </a>
                </li>

                <li class="treeview">
                    <a href="#">
                        <i class="fa fa-cogs"></i>
                        <span>Pengaturan</span>

                        <span class="pull-right-container">
                            <i class="fa fa-angle-left pull-right"></i>
                        </span>
                    </a>

                    <ul class="treeview-menu">
                        <li>
                            <a href="<?= base_url('admin/user') ?>">
                                <i class="fa fa-users"></i>
                                Manajemen User
                            </a>
                        </li>

                        <li>
                            <a href="<?= base_url('admin/rekening') ?>">
                                <i class="fa fa-credit-card"></i>
                                Rekening Penampungan
                            </a>
                        </li>

                        <?php if ($isSuperAdmin): ?>
                            <li>
                                <a href="<?= base_url('admin/cabang') ?>">
                                    <i class="fa fa-building"></i>
                                    Manajemen Cabang
                                </a>
                            </li>
                        <?php endif; ?>

                        <li>
                            <a href="<?= base_url('admin/aplikasi') ?>">
                                <i class="fa fa-info-circle"></i>
                                Tentang Aplikasi
                            </a>
                        </li>

                        <li>
                            <a href="<?= base_url('admin/backupdatabase') ?>">
                                <i class="fa fa-database"></i>
                                Backup Database
                            </a>
                        </li>

                        <li>
                            <a href="<?= base_url('admin/log') ?>">
                                <i class="fa fa-file"></i>
                                Log Status
                            </a>
                        </li>
                    </ul>
                </li>

            <?php endif; ?>

            <li>
                <a href="<?= base_url('admin/profil') ?>">
                    <i class="fa fa-user"></i>
                    <span>Profil</span>
                </a>
            </li>

            <li>
                <a
                    href="<?= base_url('home/logout') ?>"
                    class="tombol-yakin"
                    data-isidata="Ingin keluar dari sistem ini?">
                    <i class="fa fa-sign-out"></i>
                    <span>Sign Out</span>
                </a>
            </li>
        </ul>
    </section>
</aside>
