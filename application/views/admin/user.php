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
        <div class="box">
            <div class="box-header">
                <button class="btn btn-primary" data-toggle="modal" data-target="#tambahData">
                    <div class="fa fa-plus"></div> Tambah Data
                </button>
            </div>
            <div class="box-body">
                <div class="table-responsive">
                    <table class="table table-bordered table-striped table-hover" id="dataTable">
                        <thead>
                            <tr>
                                <th width="10px">#</th>
                                <th>Nama Lengkap</th>
                                <th>Jenis Kelamin</th>
                                <th>Username</th>
                                <th>Telp</th>
                                <th>Email</th>
                                <th>Alamat</th>
                                <th>Login?</th>
                                <th>Sebagai</th>
                                <th>Terdaftar</th>
                                <th>Aksi</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php
                                $no = 1;
                                foreach ($user->result_array() as $row) {
                            ?>
                                <tr>
                                    <td><?= $no++ ?></td>
                                    <td><?= $row['nama'] ?></td>
                                    <td><?= $row['jenisKelamin'] ?></td>
                                    <td><?= $row['username'] ?></td>
                                    <td><?= $row['telp'] ?></td>
                                    <td><?= $row['email'] ?></td>
                                    <td><?= $row['alamat'] ?></td>
                                    <td>
                                        <?php
                                            if($row['login'] == 'Ya') {
                                                echo '<div class="label label-success">'.$row['login'].'</div>';
                                            } else {
                                                echo '<div class="label label-danger">'.$row['login'].'</div>';
                                            }
                                        ?>
                                    </td>
                                    <td><?= $row['level'] ?></td>
                                    <td><?= date('d F Y H:i:s', strtotime($row['terdaftar'])) ?></td>
                                    <td>
                                    <?php if($this->session->userdata('id') == $row['id']) { ?>
                                        <a href="<?= base_url('admin/profil') ?>" class="btn btn-info btn-xs">
                                            <div class="fa fa-user"></div> My Profil
                                        </a>
                                    <?php } elseif (strtolower($row['level']) == 'super admin') { ?>
                                        <span class="label label-default"><i class="fa fa-shield"></i> Akses Dibatasi</span>
                                    <?php } else { ?>
                                        <button class="btn btn-warning btn-xs" data-toggle="modal" data-target="#editData<?= $row['id'] ?>">
                                            <div class="fa fa-edit"></div> Edit
                                        </button>
                                        <button class="btn btn-success btn-xs" data-toggle="modal" data-target="#resetPassword<?= $row['id'] ?>">
                                            <div class="fa fa-lock"></div> Reset Password
                                        </button>
                                        <a href="<?= base_url('admin/user/delete/').$row['id'] ?>" class="btn btn-danger btn-xs tombol-yakin" data-isidata="Account tidak bisa dipulihkan setelah dihapus">
                                            <div class="fa fa-trash"></div> Delete
                                        </a>
                                    <?php } ?>
                                </td>
                                </tr>
                            <?php } ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </section>
</div>

<!-- Modal Tambah Data -->
<div class="modal fade" id="tambahData" tabindex="-1" role="dialog" aria-labelledby="myModalLabel">
    <div class="modal-dialog" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                <h4 class="modal-title" id="myModalLabel">Tambah User</h4>
            </div>
            <form action="<?= base_url('admin/user/insert') ?>" method="POST">
                <div class="modal-body">
                    <div class="form-group">
                        <label>Nama Lengkap</label>
                        <input type="hidden" name="<?= $this->security->get_csrf_token_name();?>" value="<?=$this->security->get_csrf_hash();?>" style="display: none">
                        <input type="text" name="nama" class="form-control" placeholder="Nama Lengkap" required>
                    </div>
                    <div class="form-group">
                        <label>Jenis Kelamin</label>
                        <select name="jenisKelamin" class="form-control" required>
                            <option value="" disabled selected> -- Pilih Jenis Kelamin -- </option>
                            <option value="Laki-Laki">Laki-Laki</option>
                            <option value="Perempuan">Perempuan</option>
                        </select>
                    </div>
                    <div class="row">
                        <div class="col-md-6">
                            <div class="form-group">
                                <label>Telp</label>
                                <input type="number" name="telp" class="form-control" placeholder="Telp" required>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="form-group">
                                <label>Email</label>
                                <input type="email" name="email" class="form-control" placeholder="Email" required>
                            </div>
                        </div>
                    </div>
                    <div class="form-group">
                        <label>Alamat</label>
                        <input type="text" name="alamat" class="form-control" placeholder="Alamat" required>
                    </div>
                    <div class="form-group">
                        <label>Login?</label>
                        <select name="login" class="form-control" required>
                            <option value=""> -- Pilih Login -- </option>
                            <option value="Ya">Ya</option>
                            <option value="Tidak">Tidak</option>
                        </select>
                    </div>
                    <div class="row">
                        <div class="col-md-6">
                            <div class="form-group">
                                <label>Username</label>
                                <input type="text" name="username" class="form-control" placeholder="Username" required>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="form-group">
                                <label>Password</label>
                                <input type="password" name="password" class="form-control" placeholder="Password" required>
                            </div>
                        </div>
                    </div>
                    <div class="form-group">
                        <label>Sebagai</label>
                        <select name="level" class="form-control" required>
                            <option value="" disabled selected> -- Pilih Sebagai -- </option>
                            <option value="Administrator">Administrator</option>
                            <option value="Nasabah">Nasabah</option>
                        </select>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="reset" class="btn btn-danger"><div class="fa fa-trash"></div> Reset</button>
                    <button type="submit" class="btn btn-primary"><div class="fa fa-save"></div> Save</button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Modal Reset Password -->
<?php foreach ($user->result() as $reset) { ?>
    <div class="modal fade" id="resetPassword<?= $reset->id ?>" tabindex="-1" role="dialog" aria-labelledby="myModalLabel">
        <div class="modal-dialog" role="document">
            <div class="modal-content">
                <div class="modal-header">
                    <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                    <h4 class="modal-title" id="myModalLabel">Reset Password : <?= $reset->nama ?></h4>
                </div>
                <form action="<?= base_url('admin/user/resetpassword/').$reset->id ?>" method="POST">
                    <div class="modal-body">
                        <div class="form-group">
                            <label>New Password</label>
                            <input type="hidden" name="<?= $this->security->get_csrf_token_name();?>" value="<?=$this->security->get_csrf_hash();?>" style="display: none">
                            <input type="password" name="password" class="form-control" placeholder="New Password" required>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="reset" class="btn btn-danger"><div class="fa fa-trash"></div> Reset</button>
                        <button type="submit" class="btn btn-primary"><div class="fa fa-lock"></div> Reset Password</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
<?php } ?>

<!-- Modal Edit Data -->
<?php foreach ($user->result() as $edit) { ?>
    <div class="modal fade" id="editData<?= $edit->id ?>" tabindex="-1" role="dialog" aria-labelledby="myModalLabel">
        <div class="modal-dialog" role="document">
            <div class="modal-content">
                <div class="modal-header">
                    <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                    <h4 class="modal-title" id="myModalLabel">Edit <?= $title ?></h4>
                </div>
                <form action="<?= base_url('admin/user/update/').$edit->id ?>" method="POST">
                    <div class="modal-body">
                        <div class="form-group">
                            <label>Nama Lengkap</label>
                            <input type="hidden" name="<?= $this->security->get_csrf_token_name();?>" value="<?=$this->security->get_csrf_hash();?>" style="display: none">
                            <input type="text" name="nama" class="form-control" placeholder="Nama Lengkap" value="<?= $edit->nama ?>" required>
                        </div>
                        <div class="form-group">
                            <label>Jenis Kelamin</label>
                            <select name="jenisKelamin" class="form-control" required>
                                <option value="Laki-Laki" <?= ($edit->jenisKelamin == 'Laki-Laki') ? 'selected' : '' ?>>Laki-Laki</option>
                                <option value="Perempuan" <?= ($edit->jenisKelamin == 'Perempuan') ? 'selected' : '' ?>>Perempuan</option>
                            </select>
                        </div>
                        <div class="row">
                            <div class="col-md-6">
                                <div class="form-group">
                                    <label>Telp</label>
                                    <input type="number" name="telp" class="form-control" placeholder="Telp" value="<?= $edit->telp ?>" required>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="form-group">
                                    <label>Email</label>
                                    <input type="email" name="email" class="form-control" placeholder="Email" value="<?= $edit->email ?>" required>
                                </div>
                            </div>
                        </div>
                        <div class="form-group">
                            <label>Alamat</label>
                            <input type="text" name="alamat" class="form-control" placeholder="Alamat" value="<?= $edit->alamat ?>" required>
                        </div>
                                <div class="form-group">
                                    <label>Username</label>
                                    <input type="text" name="username" class="form-control" placeholder="Username" value="<?= $edit->username ?>" required>
                                </div>
                            
                        <div class="form-group">
                            <label>Login?</label>
                            <select name="login" class="form-control" required>
                                <option value="Ya" <?= ($edit->login == 'Ya') ? 'selected' : '' ?>>Ya</option>
                                <option value="Tidak" <?= ($edit->login == 'Tidak') ? 'selected' : '' ?>>Tidak</option>
                            </select>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="reset" class="btn btn-danger"><div class="fa fa-trash"></div> Reset</button>
                        <button type="submit" class="btn btn-primary"><div class="fa fa-save"></div> Save</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
<?php } ?>