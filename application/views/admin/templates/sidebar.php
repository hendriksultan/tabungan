<aside class="main-sidebar">
    <section class="sidebar">
        <ul class="sidebar-menu" data-widget="tree">
            <li class="header">MAIN NAVIGATION</li>
            
            <li>
                <a href="<?= base_url('admin/dashboard') ?>">
                    <i class="fa fa-tachometer"></i> <span>Dashboard</span>
                </a>
            </li>
            <li>
                <a href="<?= base_url('admin/transaksi') ?>">
                    <i class="fa fa-book"></i> <span>Data Transaksi</span>
                </a>
            </li>
            <li>
                <a href="<?= base_url('admin/transfer') ?>">
                    <i class="fa fa-send"></i> <span>Data Transfer</span>
                </a>
            </li>
            
            <?php 
                $userLevel = strtolower($this->session->userdata('level'));
                if($userLevel == 'administrator' || $userLevel == 'super admin') { 
            ?>
                <li>
                    <a href="<?= base_url('admin/potongan') ?>">
                        <i class="fa fa-minus-circle"></i> <span>Data Potongan</span>
                    </a>
                </li>
                <li class="treeview">
                    <a href="#">
                        <i class="fa fa-cogs"></i> <span>Pengaturan</span>
                        <span class="pull-right-container">
                            <i class="fa fa-angle-left pull-right"></i>
                        </span>
                    </a>
                    <ul class="treeview-menu">
                        <li><a href="<?= base_url('admin/user') ?>"><i class="fa fa-users"></i> Manajemen User</a></li>
                        <li><a href="<?= base_url('admin/aplikasi') ?>"><i class="fa fa-info-circle"></i> Tentang Aplikasi</a></li>
                        <li><a href="<?= base_url('admin/backupdatabase') ?>"><i class="fa fa-database"></i> Backup Database</a></li>
                        <li><a href="<?= base_url('admin/log') ?>"><i class="fa fa-file"></i> Log Status</a></li>
                    </ul>
                </li>
            <?php } ?>
            
            <li>
                <a href="<?= base_url('admin/profil') ?>">
                    <i class="fa fa-user"></i> <span>Profil</span>
                </a>
            </li>

            <li>
                <a href="<?= base_url('home/logout') ?>" class="tombol-yakin" data-isidata="Ingin keluar dari sistem ini?">
                    <i class="fa fa-sign-out"></i> <span>Sign Out</span>
                </a>
            </li>
        </ul>
    </section>
</aside>