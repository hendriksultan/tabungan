<?php
$faviconDefault = 'Logo-1720958830.png';
$pengaturanFavicon = $this->db
  ->select('logo')
  ->order_by('id', 'DESC')
  ->limit(1)
  ->get('tb_aplikasi')
  ->row_array();

$faviconFile = !empty($pengaturanFavicon['logo'])
  ? basename((string) $pengaturanFavicon['logo'])
  : $faviconDefault;

$faviconPath = FCPATH . 'assets/logo/' . $faviconFile;

if (!is_file($faviconPath)) {
  $faviconFile = $faviconDefault;
  $faviconPath = FCPATH . 'assets/logo/' . $faviconFile;
}

$faviconExtension = strtolower(pathinfo($faviconFile, PATHINFO_EXTENSION));
$faviconMime = in_array($faviconExtension, ['jpg', 'jpeg'], true)
  ? 'image/jpeg'
  : 'image/png';
$faviconVersion = is_file($faviconPath) ? filemtime($faviconPath) : 1;
$faviconUrl = base_url('assets/logo/' . $faviconFile) .
  '?v=' . rawurlencode((string) $faviconVersion);
?>
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <title><?= $title; ?> | <?= $this->session->userdata('level') ?></title>
  <link
    rel="icon"
    type="<?= html_escape($faviconMime) ?>"
    href="<?= html_escape($faviconUrl) ?>">
  <!-- Tell the browser to be responsive to screen width -->
  <meta content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no" name="viewport">
  <!-- Bootstrap 3.3.7 -->
  <link rel="stylesheet" href="<?= base_url('assets') ?>/bower_components/bootstrap/dist/css/bootstrap.min.css">
  <!--date picker-->
  <link rel="stylesheet" href="<?= base_url('assets') ?>/bower_components/bootstrap-datepicker/dist/css/bootstrap-datepicker.min.css">
    <!--date range picker-->
  <link rel="stylesheet" href="<?= base_url('assets') ?>/bower_components/bootstrap-daterangepicker/daterangepicker.css">
  
  <!-- Font Awesome -->
  <link rel="stylesheet" href="<?= base_url('assets') ?>/bower_components/font-awesome/css/font-awesome.min.css">
  <!-- Ionicons -->
  <link rel="stylesheet" href="<?= base_url('assets') ?>/bower_components/Ionicons/css/ionicons.min.css">
  <!-- Theme style -->
  <link rel="stylesheet" href="<?= base_url('assets') ?>/dist/css/AdminLTE.min.css">
  <!-- AdminLTE Skins. Choose a skin from the css/skins
       folder instead of downloading all of them to reduce the load. -->
  <link rel="stylesheet" href="<?= base_url('assets') ?>/dist/css/skins/_all-skins.min.css">
  <!-- Data Table -->
  <link rel="stylesheet" href="<?= base_url('assets') ?>/bower_components/datatables.net-bs/css/dataTables.bootstrap.min.css">
  <!-- Pace style -->
  <link rel="stylesheet" href="<?= base_url('assets') ?>/plugins/pace/pace.min.css">
  <!-- Select2 -->
  <link rel="stylesheet" href="<?= base_url('assets') ?>/bower_components/select2/dist/css/select2.min.css">
  <!-- bootstrap wysihtml5 - text editor -->
  <link rel="stylesheet" href="<?= base_url('assets') ?>/plugins/bootstrap-wysihtml5/bootstrap3-wysihtml5.min.css">
  <link rel="stylesheet" href="<?= base_url('assets') ?>/bower_components/izitoast/iziToast.css">
  <!-- HTML5 Shim and Respond.js IE8 support of HTML5 elements and media queries -->
  <!-- WARNING: Respond.js doesn't work if you view the page via file:// -->
  <!--[if lt IE 9]>
  <script src="https://oss.maxcdn.com/html5shiv/3.7.3/html5shiv.min.js"></script>
  <script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>
  <![endif]-->

  <!-- Google Font -->
  <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Source+Sans+Pro:300,400,600,700,300italic,400italic,600italic">
  <!-- SweetAlert2 -->
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>

  
</head>
<!-- ADD THE CLASS fixed TO GET A FIXED HEADER AND SIDEBAR LAYOUT -->
<!-- the fixed layout is not compatible with sidebar-mini -->
<body class="hold-transition skin-<?= $this->session->userdata('skin') ?> fixed <?= ($title == 'Tambah Data Penjualan') ? 'sidebar-collapse' : '' ?>">
<?php
$settlementNotification = settlement_notification_summary();
$settlementNotificationLevel = strtolower(trim(
  (string) $this->session->userdata('level')
));
$canSeeSettlementNotification = in_array(
  $settlementNotificationLevel,
  ['administrator', 'super admin'],
  true
);
?>
<!-- Site wrapper -->
<div class="wrapper">

  <header class="main-header">
    <!-- Logo -->
    <a href="<?= base_url('home') ?>" class="logo">
      <!-- mini logo for sidebar mini 50x50 pixels -->
      <span class="logo-mini"><b>A</b>LT</span>
      <!-- logo for regular state and mobile devices -->
      <span class="logo-lg"><b><?= $this->session->userdata('level') ?></b></span>
    </a>
    <!-- Header Navbar: style can be found in header.less -->
    <nav class="navbar navbar-static-top">
      <!-- Sidebar toggle button-->
      <a href="#" class="sidebar-toggle" data-toggle="push-menu" role="button">
        <span class="sr-only">Toggle navigation</span>
        <span class="icon-bar"></span>
        <span class="icon-bar"></span>
        <span class="icon-bar"></span>
      </a>

      <div class="navbar-custom-menu">
        <ul class="nav navbar-nav">
          <?php if ($canSeeSettlementNotification): ?>
            <li class="dropdown notifications-menu">
              <a href="#" class="dropdown-toggle" data-toggle="dropdown" aria-label="Notifikasi settlement">
                <i class="fa fa-bell-o"></i>
                <?php if ($settlementNotification['total'] > 0): ?>
                  <span class="label label-warning">
                    <?= (int) $settlementNotification['total'] ?>
                  </span>
                <?php endif; ?>
              </a>
              <ul class="dropdown-menu">
                <li class="header">
                  <?php if ($settlementNotification['total'] > 0): ?>
                    Ada <?= (int) $settlementNotification['total'] ?> pekerjaan keuangan
                  <?php else: ?>
                    Tidak ada pekerjaan settlement baru
                  <?php endif; ?>
                </li>
                <li>
                  <ul class="menu">
                    <li>
                      <a href="<?= base_url('admin/settlement#kewajibanSettlement') ?>">
                        <i class="fa fa-exchange text-yellow"></i>
                        <?= (int) $settlementNotification['kewajiban_terbuka'] ?> kewajiban terbuka
                      </a>
                    </li>
                    <li>
                      <a href="<?= base_url('admin/settlement#riwayatSettlement') ?>">
                        <i class="fa fa-clock-o text-aqua"></i>
                        <?= (int) $settlementNotification['menunggu_verifikasi'] ?> menunggu verifikasi
                      </a>
                    </li>
                    <li>
                      <a href="<?= base_url('admin/settlement#riwayatSettlement') ?>">
                        <i class="fa fa-times-circle text-red"></i>
                        <?= (int) $settlementNotification['ditolak'] ?> settlement ditolak
                      </a>
                    </li>
                    <li>
                      <a href="<?= base_url('admin/escrow') ?>">
                        <i class="fa fa-shield text-red"></i>
                        <?= (int) $settlementNotification['sengketa_escrow'] ?> sengketa escrow
                      </a>
                    </li>
                  </ul>
                </li>
                <li class="footer">
                  <a href="<?= base_url('admin/settlement') ?>">Buka Settlement Cabang</a>
                </li>
              </ul>
            </li>
          <?php endif; ?>
          <li class="dropdown messages-menu">
              <!-- Menu toggle button -->
              <a href="#" class="dropdown-toggle" data-toggle="dropdown">
                  <?php
                  if (function_exists('date_default_timezone_set'))
                      date_default_timezone_set('Asia/Jakarta');
                  ?>
                  <span id="clock">&nbsp;</span>
              </a>
          </li>
          <!-- User Account: style can be found in dropdown.less -->
          <li class="dropdown user user-menu">
            <a href="#" class="dropdown-toggle" data-toggle="dropdown">
              <img src="<?= base_url('assets') ?>/profil/<?= $this->session->userdata('foto') ?>" class="user-image" alt="User Image">
              <span class="hidden-xs"><?= $this->session->userdata('nama') ?></span>
            </a>
            <ul class="dropdown-menu">
              <!-- User image -->
              <li class="user-header">
                <img src="<?= base_url('assets') ?>/profil/<?= $this->session->userdata('foto') ?>" class="img-circle" alt="User Image">

                <p>
                  <?= $this->session->userdata('nama') ?>
                  <small><?= $this->session->userdata('email') . ' - ' . $this->session->userdata('level') ?></small>
                </p>
              </li>
              <!-- Menu Footer-->
              <li class="user-footer">
                <div class="pull-left">
                  <a href="<?= base_url('admin/profil') ?>" class="btn btn-default btn-flat">
                    <div class="fa fa-user"></div> Profile
                  </a>
                </div>
                <div class="pull-right">
                  <a href="<?= base_url('home/logout') ?>" class="btn btn-default btn-flat tombol-yakin" data-isidata="Ingin keluar dari sistem ini?">
                    <div class="fa fa-sign-out"></div> Sign out
                  </a>
                </div>
              </li>
            </ul>
          </li>
        </ul>
      </div>
    </nav>
  </header>

  <div class="flash-data" data-flashdata="<?= $this->session->flashdata('pesan') ?>"></div>
  <div class="flash-data-error" data-flashdataerror="<?= $this->session->flashdata('pesanError') ?>"></div>
  <!-- =============================================== -->
