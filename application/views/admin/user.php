<?php
$userRows = $user->result_array();
?>

<div class="content-wrapper">
    <section class="content-header">
        <h1>
            <?= html_escape($title) ?>
            <small><?= html_escape($subtitle) ?></small>
        </h1>

        <ol class="breadcrumb">
            <li>
                <a href="<?= base_url('admin/dashboard') ?>">
                    <i class="fa fa-dashboard"></i> Dashboard
                </a>
            </li>
            <li class="active">Manajemen User</li>
        </ol>
    </section>

    <section class="content">
        <div class="box box-primary">
            <div class="box-header with-border">
                <button
                    class="btn btn-primary"
                    data-toggle="modal"
                    data-target="#tambahData">
                    <i class="fa fa-plus"></i>
                    Tambah User
                </button>
            </div>

            <div class="box-body">
                <div class="table-responsive">
                    <table
                        class="table table-bordered table-striped table-hover"
                        id="dataTable">
                        <thead>
                            <tr>
                                <th width="40">No.</th>
                                <th>Nama</th>
                                <th>Cabang</th>
                                <th>Username</th>
                                <th>Kontak</th>
                                <th>Login</th>
                                <th>Level</th>
                                <th>Terdaftar</th>
                                <th width="190">Tindakan</th>
                            </tr>
                        </thead>

                        <tbody>
                            <?php $no = 1; ?>

                            <?php foreach ($userRows as $row): ?>
                                <?php
                                $idUser = (int) $row['id'];
                                $isCurrentUser = (
                                    (int) $this->session->userdata('id') ===
                                    $idUser
                                );

                                $isTargetSuperAdmin = (
                                    strtolower($row['level']) ===
                                    'super admin'
                                );
                                ?>

                                <tr>
                                    <td><?= $no++ ?></td>

                                    <td>
                                        <strong>
                                            <?= html_escape($row['nama']) ?>
                                        </strong>
                                        <br>
                                        <small class="text-muted">
                                            <?= html_escape(
                                                $row['jenisKelamin']
                                            ) ?>
                                        </small>
                                    </td>

                                    <td>
                                        <?php if (!empty($row['nama_cabang'])): ?>
                                            <strong>
                                                <?= html_escape(
                                                    $row['nama_cabang']
                                                ) ?>
                                            </strong>
                                            <br>
                                            <span class="label label-info">
                                                <?= html_escape(
                                                    $row['kode_cabang']
                                                ) ?>
                                            </span>
                                        <?php else: ?>
                                            <span class="label label-danger">
                                                Belum ada cabang
                                            </span>
                                        <?php endif; ?>
                                    </td>

                                    <td>
                                        <?= html_escape($row['username']) ?>
                                    </td>

                                    <td>
                                        <i class="fa fa-phone"></i>
                                        <?= html_escape($row['telp']) ?>
                                        <br>
                                        <i class="fa fa-envelope"></i>
                                        <?= html_escape($row['email']) ?>
                                    </td>

                                    <td>
                                        <?php if ($row['login'] === 'Ya'): ?>
                                            <span class="label label-success">
                                                Ya
                                            </span>
                                        <?php else: ?>
                                            <span class="label label-danger">
                                                Tidak
                                            </span>
                                        <?php endif; ?>
                                    </td>

                                    <td>
                                        <?= html_escape($row['level']) ?>
                                    </td>

                                    <td>
                                        <?= date(
                                            'd-m-Y H:i',
                                            strtotime($row['terdaftar'])
                                        ) ?>
                                    </td>

                                    <td>
                                        <?php if ($isCurrentUser): ?>
                                            <a
                                                href="<?= base_url(
                                                            'admin/profil'
                                                        ) ?>"
                                                class="btn btn-info btn-xs">
                                                <i class="fa fa-user"></i>
                                                Profil Saya
                                            </a>

                                        <?php elseif ($isTargetSuperAdmin): ?>
                                            <span class="label label-default">
                                                <i class="fa fa-shield"></i>
                                                Dilindungi
                                            </span>

                                        <?php else: ?>
                                            <button
                                                class="btn btn-warning btn-xs"
                                                data-toggle="modal"
                                                data-target="#editData<?= $idUser ?>">
                                                <i class="fa fa-edit"></i>
                                                Edit
                                            </button>

                                            <button
                                                class="btn btn-success btn-xs"
                                                data-toggle="modal"
                                                data-target="#resetPassword<?= $idUser ?>">
                                                <i class="fa fa-lock"></i>
                                                Password
                                            </button>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </section>
</div>

<!-- Modal tambah user -->
<div class="modal fade" id="tambahData" tabindex="-1" role="dialog">
    <div class="modal-dialog" role="document">
        <div class="modal-content">
            <form
                action="<?= base_url('admin/user/insert') ?>"
                method="post">
                <input
                    type="hidden"
                    name="<?= $this->security->get_csrf_token_name() ?>"
                    value="<?= $this->security->get_csrf_hash() ?>">

                <div class="modal-header">
                    <button
                        type="button"
                        class="close"
                        data-dismiss="modal">
                        <span>&times;</span>
                    </button>

                    <h4 class="modal-title">Tambah User</h4>
                </div>

                <div class="modal-body">
                    <div class="form-group">
                        <label>Nama lengkap</label>
                        <input
                            type="text"
                            name="nama"
                            class="form-control"
                            required>
                    </div>

                    <div class="form-group">
                        <label>Jenis kelamin</label>
                        <select
                            name="jenisKelamin"
                            class="form-control"
                            required>
                            <option value="">-- Pilih --</option>
                            <option value="Laki-Laki">Laki-Laki</option>
                            <option value="Perempuan">Perempuan</option>
                        </select>
                    </div>

                    <div class="row">
                        <div class="col-md-6">
                            <div class="form-group">
                                <label>Telepon</label>
                                <input
                                    type="text"
                                    name="telp"
                                    class="form-control">
                            </div>
                        </div>

                        <div class="col-md-6">
                            <div class="form-group">
                                <label>Email</label>
                                <input
                                    type="email"
                                    name="email"
                                    class="form-control">
                            </div>
                        </div>
                    </div>

                    <div class="form-group">
                        <label>Alamat</label>
                        <textarea
                            name="alamat"
                            class="form-control"
                            rows="3"></textarea>
                    </div>

                    <?php if ($is_super_admin): ?>
                        <div class="form-group">
                            <label>Cabang</label>
                            <select
                                name="cabang_id"
                                class="form-control"
                                required>
                                <option value="">
                                    -- Pilih Cabang --
                                </option>

                                <?php foreach ($cabang as $item): ?>
                                    <option value="<?= (int) $item['id'] ?>">
                                        <?= html_escape(
                                            $item['kode'] . ' - ' .
                                                $item['nama']
                                        ) ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>

                        <div class="form-group">
                            <label>Level</label>
                            <select
                                name="level"
                                class="form-control"
                                required>
                                <option value="">
                                    -- Pilih Level --
                                </option>
                                <option value="Administrator">
                                    Administrator
                                </option>
                                <option value="Nasabah">
                                    Nasabah
                                </option>
                            </select>
                        </div>
                    <?php else: ?>
                        <div class="alert alert-info">
                            User baru otomatis menjadi Nasabah pada
                            <strong>
                                <?= html_escape(
                                    $this->session->userdata('nama_cabang')
                                ) ?>
                            </strong>.
                        </div>
                    <?php endif; ?>

                    <div class="form-group">
                        <label>Status login</label>
                        <select
                            name="login"
                            class="form-control"
                            required>
                            <option value="Ya">Ya</option>
                            <option value="Tidak">Tidak</option>
                        </select>
                    </div>

                    <div class="row">
                        <div class="col-md-6">
                            <div class="form-group">
                                <label>Username</label>
                                <input
                                    type="text"
                                    name="username"
                                    class="form-control"
                                    required>
                            </div>
                        </div>

                        <div class="col-md-6">
                            <div class="form-group">
                                <label>Password</label>
                                <input
                                    type="password"
                                    name="password"
                                    class="form-control"
                                    minlength="6"
                                    required>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="modal-footer">
                    <button
                        type="button"
                        class="btn btn-default"
                        data-dismiss="modal">
                        Batal
                    </button>

                    <button type="submit" class="btn btn-primary">
                        <i class="fa fa-save"></i>
                        Simpan
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Modal edit dan reset password -->
<?php foreach ($userRows as $edit): ?>
    <?php
    $idEdit = (int) $edit['id'];

    if (
        strtolower($edit['level']) === 'super admin' ||
        (int) $this->session->userdata('id') === $idEdit
    ) {
        continue;
    }
    ?>

    <div
        class="modal fade"
        id="editData<?= $idEdit ?>"
        tabindex="-1"
        role="dialog">
        <div class="modal-dialog" role="document">
            <div class="modal-content">
                <form
                    action="<?= base_url(
                                'admin/user/update/' . $idEdit
                            ) ?>"
                    method="post">
                    <input
                        type="hidden"
                        name="<?= $this->security->get_csrf_token_name() ?>"
                        value="<?= $this->security->get_csrf_hash() ?>">

                    <div class="modal-header">
                        <button
                            type="button"
                            class="close"
                            data-dismiss="modal">
                            <span>&times;</span>
                        </button>

                        <h4 class="modal-title">
                            Edit <?= html_escape($edit['nama']) ?>
                        </h4>
                    </div>

                    <div class="modal-body">
                        <div class="form-group">
                            <label>Nama lengkap</label>
                            <input
                                type="text"
                                name="nama"
                                class="form-control"
                                value="<?= html_escape($edit['nama']) ?>"
                                required>
                        </div>

                        <div class="form-group">
                            <label>Jenis kelamin</label>
                            <select
                                name="jenisKelamin"
                                class="form-control"
                                required>
                                <option
                                    value="Laki-Laki"
                                    <?= $edit['jenisKelamin'] === 'Laki-Laki'
                                        ? 'selected'
                                        : ''
                                    ?>>
                                    Laki-Laki
                                </option>

                                <option
                                    value="Perempuan"
                                    <?= $edit['jenisKelamin'] === 'Perempuan'
                                        ? 'selected'
                                        : ''
                                    ?>>
                                    Perempuan
                                </option>
                            </select>
                        </div>

                        <?php if ($is_super_admin): ?>
                            <div class="form-group">
                                <label>Cabang</label>
                                <select
                                    name="cabang_id"
                                    class="form-control"
                                    required>
                                    <?php foreach ($cabang as $item): ?>
                                        <option
                                            value="<?= (int) $item['id'] ?>"
                                            <?= (int) $edit['cabang_id'] ===
                                                (int) $item['id']
                                                ? 'selected'
                                                : ''
                                            ?>>
                                            <?= html_escape(
                                                $item['kode'] . ' - ' .
                                                    $item['nama']
                                            ) ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                            </div>
                        <?php endif; ?>

                        <div class="row">
                            <div class="col-md-6">
                                <div class="form-group">
                                    <label>Telepon</label>
                                    <input
                                        type="text"
                                        name="telp"
                                        class="form-control"
                                        value="<?= html_escape(
                                                    $edit['telp']
                                                ) ?>">
                                </div>
                            </div>

                            <div class="col-md-6">
                                <div class="form-group">
                                    <label>Email</label>
                                    <input
                                        type="email"
                                        name="email"
                                        class="form-control"
                                        value="<?= html_escape(
                                                    $edit['email']
                                                ) ?>">
                                </div>
                            </div>
                        </div>

                        <div class="form-group">
                            <label>Alamat</label>
                            <textarea
                                name="alamat"
                                class="form-control"
                                rows="3"><?= html_escape($edit['alamat']) ?></textarea>
                        </div>

                        <div class="form-group">
                            <label>Username</label>
                            <input
                                type="text"
                                name="username"
                                class="form-control"
                                value="<?= html_escape(
                                            $edit['username']
                                        ) ?>"
                                required>
                        </div>

                        <div class="form-group">
                            <label>Status login</label>
                            <select
                                name="login"
                                class="form-control"
                                required>
                                <option
                                    value="Ya"
                                    <?= $edit['login'] === 'Ya'
                                        ? 'selected'
                                        : ''
                                    ?>>
                                    Ya
                                </option>

                                <option
                                    value="Tidak"
                                    <?= $edit['login'] === 'Tidak'
                                        ? 'selected'
                                        : ''
                                    ?>>
                                    Tidak
                                </option>
                            </select>
                        </div>
                    </div>

                    <div class="modal-footer">
                        <button
                            type="button"
                            class="btn btn-default"
                            data-dismiss="modal">
                            Batal
                        </button>

                        <button
                            type="submit"
                            class="btn btn-primary">
                            <i class="fa fa-save"></i>
                            Simpan
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <div
        class="modal fade"
        id="resetPassword<?= $idEdit ?>"
        tabindex="-1"
        role="dialog">
        <div class="modal-dialog" role="document">
            <div class="modal-content">
                <form
                    action="<?= base_url(
                                'admin/user/resetpassword/' . $idEdit
                            ) ?>"
                    method="post">
                    <input
                        type="hidden"
                        name="<?= $this->security->get_csrf_token_name() ?>"
                        value="<?= $this->security->get_csrf_hash() ?>">

                    <div class="modal-header">
                        <button
                            type="button"
                            class="close"
                            data-dismiss="modal">
                            <span>&times;</span>
                        </button>

                        <h4 class="modal-title">
                            Reset Password
                        </h4>
                    </div>

                    <div class="modal-body">
                        <p>
                            User:
                            <strong>
                                <?= html_escape($edit['nama']) ?>
                            </strong>
                        </p>

                        <div class="form-group">
                            <label>Password baru</label>
                            <input
                                type="password"
                                name="password"
                                class="form-control"
                                minlength="6"
                                required>
                        </div>
                    </div>

                    <div class="modal-footer">
                        <button
                            type="button"
                            class="btn btn-default"
                            data-dismiss="modal">
                            Batal
                        </button>

                        <button
                            type="submit"
                            class="btn btn-success">
                            <i class="fa fa-lock"></i>
                            Reset Password
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>
<?php endforeach; ?>