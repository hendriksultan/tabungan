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
      <li class="active">Manajemen Cabang</li>
    </ol>
  </section>

  <section class="content">
    <div class="box box-primary">
      <div class="box-header with-border">
        <h3 class="box-title">
          <i class="fa fa-building"></i>
          Daftar Cabang
        </h3>

        <div class="box-tools pull-right">
          <button
            type="button"
            class="btn btn-primary btn-sm"
            data-toggle="modal"
            data-target="#modalTambahCabang">
            <i class="fa fa-plus"></i>
            Tambah Cabang
          </button>
        </div>
      </div>

      <div class="box-body">
        <div class="table-responsive">
          <table
            id="tableCabang"
            class="table table-bordered table-striped">
            <thead>
              <tr>
                <th width="50">No.</th>
                <th>Kode</th>
                <th>Nama Cabang</th>
                <th>Kontak</th>
                <th>Alamat</th>
                <th>Status</th>
                <th width="155">Tindakan</th>
              </tr>
            </thead>

            <tbody>
              <?php $no = 1; ?>

              <?php foreach ($cabang->result_array() as $row): ?>
                <?php
                $idCabang = (int) $row['id'];
                $isPusat = (int) $row['is_pusat'] === 1;
                $isAktif = strtolower($row['status']) === 'aktif';
                ?>

                <tr>
                  <td><?= $no++ ?></td>

                  <td>
                    <strong>
                      <?= html_escape($row['kode']) ?>
                    </strong>

                    <?php if ($isPusat): ?>
                      <br>
                      <span class="label label-primary">
                        Kantor Pusat
                      </span>
                    <?php endif; ?>
                  </td>

                  <td>
                    <?= html_escape($row['nama']) ?>
                  </td>

                  <td>
                    <?php if (!empty($row['telp'])): ?>
                      <i class="fa fa-phone"></i>
                      <?= html_escape($row['telp']) ?>
                      <br>
                    <?php endif; ?>

                    <?php if (!empty($row['email'])): ?>
                      <i class="fa fa-envelope"></i>
                      <?= html_escape($row['email']) ?>
                    <?php endif; ?>

                    <?php if (
                      empty($row['telp']) &&
                      empty($row['email'])
                    ): ?>
                      <span class="text-muted">-</span>
                    <?php endif; ?>
                  </td>

                  <td>
                    <?= !empty($row['alamat'])
                      ? nl2br(html_escape($row['alamat']))
                      : '<span class="text-muted">-</span>'
                    ?>
                  </td>

                  <td>
                    <?php if ($isAktif): ?>
                      <span class="label label-success">
                        Aktif
                      </span>
                    <?php else: ?>
                      <span class="label label-danger">
                        Nonaktif
                      </span>
                    <?php endif; ?>
                  </td>

                  <td>
                    <button
                      type="button"
                      class="btn btn-warning btn-xs"
                      data-toggle="modal"
                      data-target="#modalEditCabang<?= $idCabang ?>">
                      <i class="fa fa-pencil"></i>
                      Edit
                    </button>

                    <?php if (!$isPusat): ?>
                      <form
                        method="post"
                        action="<?= base_url(
                                  'admin/cabang/toggle_status/' .
                                    $idCabang
                                ) ?>"
                        style="display:inline-block;"
                        onsubmit="return confirm(
                                                    'Yakin ingin mengubah status cabang ini?'
                                                );">
                        <input
                          type="hidden"
                          name="<?= $this->security->get_csrf_token_name() ?>"
                          value="<?= $this->security->get_csrf_hash() ?>">

                        <?php if ($isAktif): ?>
                          <button
                            type="submit"
                            class="btn btn-danger btn-xs">
                            <i class="fa fa-ban"></i>
                            Nonaktifkan
                          </button>
                        <?php else: ?>
                          <button
                            type="submit"
                            class="btn btn-success btn-xs">
                            <i class="fa fa-check"></i>
                            Aktifkan
                          </button>
                        <?php endif; ?>
                      </form>
                    <?php endif; ?>
                  </td>
                </tr>

                <!-- Modal edit -->
                <div
                  class="modal fade"
                  id="modalEditCabang<?= $idCabang ?>"
                  tabindex="-1"
                  role="dialog">
                  <div
                    class="modal-dialog"
                    role="document">
                    <div class="modal-content">
                      <form
                        method="post"
                        action="<?= base_url(
                                  'admin/cabang/update/' .
                                    $idCabang
                                ) ?>">
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
                            Edit Cabang
                          </h4>
                        </div>

                        <div class="modal-body">
                          <div class="form-group">
                            <label>Kode Cabang</label>

                            <input
                              type="text"
                              class="form-control"
                              value="<?= html_escape(
                                        $row['kode']
                                      ) ?>"
                              disabled>

                            <small class="text-muted">
                              Kode cabang tidak dapat diubah.
                            </small>
                          </div>

                          <div class="form-group">
                            <label>Nama Cabang</label>

                            <input
                              type="text"
                              name="nama"
                              class="form-control"
                              maxlength="150"
                              value="<?= html_escape(
                                        $row['nama']
                                      ) ?>"
                              required>
                          </div>

                          <div class="form-group">
                            <label>Nomor Telepon</label>

                            <input
                              type="text"
                              name="telp"
                              class="form-control"
                              maxlength="20"
                              value="<?= html_escape(
                                        $row['telp']
                                      ) ?>">
                          </div>

                          <div class="form-group">
                            <label>Email</label>

                            <input
                              type="email"
                              name="email"
                              class="form-control"
                              maxlength="150"
                              value="<?= html_escape(
                                        $row['email']
                                      ) ?>">
                          </div>

                          <div class="form-group">
                            <label>Alamat</label>

                            <textarea
                              name="alamat"
                              class="form-control"
                              rows="3"><?= html_escape(
                                          $row['alamat']
                                        ) ?></textarea>
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
                            Simpan Perubahan
                          </button>
                        </div>
                      </form>
                    </div>
                  </div>
                </div>
              <?php endforeach; ?>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </section>
</div>

<!-- Modal tambah cabang -->
<div
  class="modal fade"
  id="modalTambahCabang"
  tabindex="-1"
  role="dialog">
  <div class="modal-dialog" role="document">
    <div class="modal-content">
      <form
        method="post"
        action="<?= base_url('admin/cabang/insert') ?>">
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
            Tambah Cabang Baru
          </h4>
        </div>

        <div class="modal-body">
          <div class="form-group">
            <label>Kode Cabang</label>

            <input
              type="text"
              name="kode"
              class="form-control"
              maxlength="20"
              placeholder="Contoh: CBG-BDG"
              required>

            <small class="text-muted">
              Gunakan huruf, angka, atau tanda hubung.
            </small>
          </div>

          <div class="form-group">
            <label>Nama Cabang</label>

            <input
              type="text"
              name="nama"
              class="form-control"
              maxlength="150"
              placeholder="Contoh: Cabang Bandung"
              required>
          </div>

          <div class="form-group">
            <label>Nomor Telepon</label>

            <input
              type="text"
              name="telp"
              class="form-control"
              maxlength="20">
          </div>

          <div class="form-group">
            <label>Email</label>

            <input
              type="email"
              name="email"
              class="form-control"
              maxlength="150">
          </div>

          <div class="form-group">
            <label>Alamat</label>

            <textarea
              name="alamat"
              class="form-control"
              rows="3"></textarea>
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
            Simpan Cabang
          </button>
        </div>
      </form>
    </div>
  </div>
</div>