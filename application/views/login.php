<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <title><?= $title; ?> Tabungan Umat </title>
  <link rel="icon" type="image/x-icon" href="assets/logo/Logo-1720958830.png">
  <meta content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no" name="viewport">
  <link rel="stylesheet" href="<?= base_url('assets') ?>/bower_components/bootstrap/dist/css/bootstrap.min.css">
  <link rel="stylesheet" href="<?= base_url('assets') ?>/bower_components/font-awesome/css/font-awesome.min.css">
  <link rel="stylesheet" href="<?= base_url('assets') ?>/bower_components/Ionicons/css/ionicons.min.css">
  <link rel="stylesheet" href="<?= base_url('assets') ?>/dist/css/AdminLTE.min.css">
  <link rel="stylesheet" href="<?= base_url('assets') ?>/plugins/iCheck/square/blue.css">
  <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Source+Sans+Pro:300,400,600,700,300italic,400italic,600italic">

  <style>
    /* -------- MEMPOSISIKAN LOGIN BOX DI TENGAH -------- */
    .login-page {
      background-image: url("assets/gambar/back.webp") !important;
      background-size: cover !important;
      background-repeat: no-repeat !important;
      background-attachment: fixed;
      background-position: center;

      display: flex;               /* aktifkan flexbox */
      justify-content: center;     /* center horizontal */
      align-items: center;         /* center vertical */
      min-height: 100vh;           /* penuh layar */
      margin: 0;
    }

    h2 {
      font-weight: bold;
      color: #ffffff;
    }

    .login-box {
      margin: 0; /* reset margin */
    }

    .login-box-body {
      background: transparent;
      border-radius: 20px;
      padding: 13px;
    }

    .panel-info {
      background: transparent;
      padding: 10px;
    }

    .form-control {
      border-radius: 5px;
      font-size: 15px;
      height: 40px;
      font-weight: normal;
      box-shadow: none;
      border-color: #d2d6de;
    }

    .form-control-feedback {
      color: #999999;
      display: flex;
      align-items: center;
      position: absolute;
      pointer-events: none;
    }

    #mybutton {
      position: relative;
      z-index: 1;
      left: 90%;
      top: -29px;
      cursor: pointer;
    }

    .myform {
      margin-top: 0;
      background: #fafafa;
      padding: 20px;
      border: 1px solid #f4f4f4;
    }

    .btn.btn-flat {
      border-radius: 5px;
    }

    .login-box-msg {
      color: #fafafa;
    }

    hr {
      border-top: 1px solid white;
    }

    p {
      color: white;
      font-size: 18px;
    }

    .col-xs-8 {
      color: white;
    }
  </style>
</head>
<body class="hold-transition login-page">
  <div class="login-box">
    <div class="login-logo">
      <?php foreach ($aplikasi->result_array() as $row) { ?>
        <center>
            <img src="<?= base_url('assets/logo/').$row['logo'] ?>" alt="" class="img-responsive" width="30%" style="margin-bottom: 15px; border-radius: 22%; box-shadow: 0px 4px 10px rgba(0,0,0,0.2);">
        </center>
        <a href="<?= base_url('home') ?>"><h2><?= $row['nama'] ?></h2></a>
      <?php } ?>
    </div>

    <div class="login-box-body">
      <div class="flash-data" data-flashdata="<?php echo $this->session->flashdata('pesan') ?>"></div>

      <form action="<?= base_url('home/auth') ?>" method="POST">
        <input type="hidden" name="<?= $this->security->get_csrf_token_name();?>" value="<?=$this->security->get_csrf_hash();?>" style="display: none">
        <div class="form-group has-feedback"> 
          <input type="text" class="form-control" name="username" placeholder="Username" required autofocus>
          <span class="glyphicon glyphicon-user form-control-feedback"></span>
        </div>
        <div class="form-group has-feedback">
          <input type="password" class="form-control" name="password" id="password" placeholder="Password" required>
          <span class="glyphicon glyphicon-lock form-control-feedback"></span>
        </div>
        <hr>
        <p><?= $captcha ?></p>
        <div class="form-group">
          <input type="text" class="form-control" style="border-radius: 5px" name="jawaban" placeholder="Hitung angka diatas">
        </div>
        <div class="row">
          <div class="col-xs-8">
            <input type="checkbox" id="checkbox">&nbsp; Show Password
          </div>
          <div class="col-xs-4">
            <button type="submit" class="btn btn-success btn-block btn-flat" style="border-radius: 5px">
              <div class="fa fa-sign-in"></div>&nbsp; Sign In
            </button>
          </div>
        </div>
      </form>
    </div>
  </div>

  <script src="<?= base_url('assets') ?>/bower_components/sweetalert/sweetalert.min.js"></script>
  <script src="<?= base_url('assets') ?>/bower_components/jquery/dist/jquery.min.js"></script>
  <script src="<?= base_url('assets') ?>/bower_components/bootstrap/dist/js/bootstrap.min.js"></script>
  <script src="<?= base_url('assets') ?>/plugins/iCheck/icheck.min.js"></script>
  <script>
    const flashData = $('.flash-data').data('flashdata');
    if (flashData){
      swal({
        title: "Failed!",
        text: flashData,
        icon: "error",
      });
    }

    $(document).ready(function() {
      $('#checkbox').click(function() {
        $('#password').attr('type', $(this).is(':checked') ? 'text' : 'password');
      });
    });
  </script>
</body>
</html>