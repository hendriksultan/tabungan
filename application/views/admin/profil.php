<div class="content-wrapper">
    <section class="content-header">
        <h1>
            <?= $title ?>
            <small><?= $subtitle ?></small>
        </h1>
        <ol class="breadcrumb">
            <li><a href="<?= base_url('admin/dashboard') ?>"><i class="fa fa-dashboard"></i> Dashboard</a></li>
            <li class="active"><?= $title ?></li>
        </ol>
    </section>

    <section class="content">

        <div class="row">
            <div class="col-md-3">
                <div class="box">
                    <div class="box-body box-profile">
                        <img class="profile-user-img img-responsive img-circle" src="<?= base_url('assets/profil/').$this->session->userdata('foto') ?>" alt="User profile picture">

                        <h3 class="profile-username text-center"><?= $this->session->userdata('nama') ?></h3>

                        <p class="text-muted text-center"><?= $this->session->userdata('level') ?></p>

                        <ul class="list-group list-group-unbordered">
                            <li class="list-group-item">
                                <b>Last Login</b> <a class="pull-right">
                                    <?php
                                        $this->db->limit('1');
                                        $this->db->order_by('id', 'DESC');
                                        $this->db->where('idUser', $this->session->userdata('id'));
                                        foreach ($this->db->get('tb_log')->result() as $dLast) {
                                            echo date('d M Y H:i:s', strtotime($dLast->terdaftar));
                                        }
                                    ?>
                                </a>
                            </li>
                            <li class="list-group-item">
                                <b>Terdaftar</b> <a class="pull-right"><?= date('d M Y H:i:s', strtotime($this->session->userdata('terdaftar'))) ?></a>
                            </li>
                        </ul>

                        <a href="<?= base_url('home/logout') ?>" class="btn btn-danger btn-block tombol-yakin" data-isidata="Ingin keluar dari sistem ini?">
                            <div class="fa fa-sign-out"></div> Sign out
                        </a>
                    </div>
                </div>
            </div>
            <div class="col-md-9">
                <div class="nav-tabs-custom">
                    <ul class="nav nav-tabs">
                        <li class="active"><a href="#account" data-toggle="tab"><div class="fa fa-user"></div> Account</a></li>
                        <li><a href="#log" data-toggle="tab"><div class="fa fa-history"></div> Log Status</a></li>
                    </ul>

                    <!-- Tab Account -->
                    <div class="tab-content">
                        <div class="active tab-pane" id="account">
                            <form class="form-horizontal" action="<?= base_url('admin/profil/update/').$this->session->userdata('id') ?>" method="POST" enctype="multipart/form-data">
                                <input type="hidden" name="<?= $this->security->get_csrf_token_name();?>" value="<?=$this->security->get_csrf_hash();?>" style="display: none">
                                <div class="box-body">
                                    <div class="form-group">
                                        <label class="col-sm-2 control-label">Nama Lengkap</label>

                                        <div class="col-sm-10">
                                            <input type="text" name="nama" class="form-control" value="<?= $this->session->userdata('nama'); ?>" placeholder="Nama Lengkap" required>
                                        </div>
                                    </div>
                                    <div class="form-group">
                                        <label class="col-sm-2 control-label">Jenis Kelamin</label>

                                        <div class="col-sm-10">
                                            <select name="jenisKelamin" class="form-control" required>
                                                <option value="Laki-Laki" <?= ($this->session->userdata('jenisKelamin') == 'Laki-Laki') ? 'selected' : '' ?>>Laki-Laki</option>
                                                <option value="Perempuan" <?= ($this->session->userdata('jenisKelamin') == 'Perempuan') ? 'selected' : '' ?>>Perempuan</option>
                                            </select>
                                        </div>
                                    </div>
                                    <div class="form-group">
                                        <label class="col-sm-2 control-label">No. Telephone</label>

                                        <div class="col-sm-10">
                                            <input type="number" name="telp" class="form-control" value="<?= $this->session->userdata('telp'); ?>" placeholder="No. Telephone" required>
                                        </div>
                                    </div>
                                    <div class="form-group">
                                        <label class="col-sm-2 control-label">Email</label>

                                        <div class="col-sm-10">
                                            <input type="email" name="email" class="form-control" value="<?= $this->session->userdata('email'); ?>" placeholder="Email" required>
                                        </div>
                                    </div>
                                    <div class="form-group">
                                        <label class="col-sm-2 control-label">Alamat</label>

                                        <div class="col-sm-10">
                                            <input type="text" name="alamat" class="form-control" value="<?= $this->session->userdata('alamat'); ?>" placeholder="Alamat" required>
                                        </div>
                                    </div>
                                    <div class="form-group">
                                        <label class="col-sm-2 control-label">Username</label>

                                        <div class="col-sm-10">
                                            <input type="text" name="username" class="form-control" value="<?= $this->session->userdata('username'); ?>" placeholder="Username" required>
                                        </div>
                                    </div>
                                    <div class="form-group">
                                        <label class="col-sm-2 control-label">New Password <font color="red">*)</font></label>

                                        <div class="col-sm-10">
                                            <input type="password" name="password" class="form-control" placeholder="New Password">
                                        </div>
                                    </div>
                                    <div class="form-group">
                                        <label class="col-sm-2 control-label">Skin</label>

                                        <div class="col-sm-10">
                                            <select name="skin" class="form-control" required>
                                                <option value="<?= $this->session->userdata('skin') ?>" selected><?= $this->session->userdata('skin') ?></option>
                                                <option value="" disabled> -- Pilih Skin Lain -- </option>
                                                <option value="yellow">yellow</option>
                                                <option value="red">red</option>
                                                <option value="green">green</option>
                                                <option value="purple">purple</option>
                                                <option value="blue">blue</option>
                                            </select>
                                        </div>
                                    </div>
                                    <div class="form-group">
                                        <label class="col-sm-2 control-label">Level</label>

                                        <div class="col-sm-10">
                                            <input type="text" class="form-control" value="<?= $this->session->userdata('level') ?>" disabled>
                                        </div>
                                    </div>
                                    <div class="form-group">
                                        <label class="col-sm-2 control-label">Foto <font color="red">*)</font></label>

                                        <div class="col-sm-10">
                                            <input type="file" name="foto" class="form-control-file">
                                        </div>
                                    </div>
                                </div>
                                <div class="box-footer">
                                    <small><b><i><font color="red">*) Kosongkan jika tidak ingin diubah!</font></i></b></small>
                                    <div class="pull-right">
                                        <button type="reset" class="btn btn-danger">
                                            <div class="fa fa-trash"></div> Reset
                                        </button>
                                        <button type="submit" class="btn btn-primary">
                                            <div class="fa fa-save"></div> Update
                                        </button>
                                    </div>
                                </div>
                            </form>
                        </div>

                        <!-- Tab Log Status -->
                        <div class="tab-pane" id="log">
                            <div class="table-responsive">
                                <table class="table table-bordered table-striped table-hover" id="dataTable">
                                    <thead>
                                        <tr>
                                            <th>IP Address</th>
                                            <th>Device</th>
                                            <th>Status</th>
                                            <th>Waktu</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($log->result_array() as $row) { ?>
                                            <tr>
                                                <td><?= $row['ipAddress'] ?></td>
                                                <td><?= $row['device'] ?></td>
                                                <td>
                                                    <?php
                                                        if($row['status'] == 'Login') {
                                                            echo '<div class="label label-success">'.$row['status'].'</div>';
                                                        } else {
                                                            echo '<div class="label label-danger">'.$row['status'].'</div>';
                                                        }
                                                    ?>
                                                </td>
                                                <td><?= date('d M Y H:i:s', strtotime($row['terdaftar'])) ?></td>
                                            </tr>
                                        <?php } ?>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

    </section>
</div>