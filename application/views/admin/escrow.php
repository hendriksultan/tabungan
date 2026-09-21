<?php
$classes = [
    'Ditahan' => 'label-warning',
    'MenungguSettlement' => 'label-info',
    'Cair' => 'label-success',
    'Dikembalikan' => 'label-primary',
    'Sengketa' => 'label-danger',
    'Dibatalkan' => 'label-default'
];
$statusLabels = [
    'MenungguSettlement' => 'Menunggu'
];
$rows = $escrow->result_array();
$ditahan = 0;
$sengketa = 0;
$nominalDitahan = 0;
foreach ($rows as $item) {
    if (in_array($item['status'], ['Ditahan', 'Sengketa'], true)) {
        $ditahan++;
        $nominalDitahan += (int) $item['total_dana'];
    }
    if ($item['status'] === 'Sengketa') {
        $sengketa++;
    }
}
?>
<div class="content-wrapper">
    <section class="content-header">
        <h1><?= html_escape($title) ?> <small><?= html_escape($subtitle) ?></small></h1>
        <ol class="breadcrumb">
            <li><a href="<?= base_url('admin/dashboard') ?>"><i class="fa fa-dashboard"></i> Dashboard</a></li>
            <li class="active">Escrow Marketplace</li>
        </ol>
    </section>

    <section class="content">
        <div class="alert alert-info">
            <i class="fa fa-shield"></i>
            Dana ditahan sampai pesanan diterima. Keputusan sengketa hanya dapat
            dilakukan Super Admin.
        </div>
        <div class="row">
            <div class="col-md-4 col-sm-6">
                <div class="info-box">
                    <span class="info-box-icon bg-yellow"><i class="fa fa-lock"></i></span>
                    <div class="info-box-content">
                        <span class="info-box-text">Dana Masih Ditahan</span>
                        <span class="info-box-number"><?= $ditahan ?></span>
                    </div>
                </div>
            </div>
            <div class="col-md-4 col-sm-6">
                <div class="info-box">
                    <span class="info-box-icon bg-red"><i class="fa fa-warning"></i></span>
                    <div class="info-box-content">
                        <span class="info-box-text">Sengketa</span>
                        <span class="info-box-number"><?= $sengketa ?></span>
                    </div>
                </div>
            </div>
            <div class="col-md-4 col-sm-6">
                <div class="info-box">
                    <span class="info-box-icon bg-aqua"><i class="fa fa-money"></i></span>
                    <div class="info-box-content">
                        <span class="info-box-text">Nominal Ditahan</span>
                        <span class="info-box-number">Rp <?= number_format($nominalDitahan, 0, ',', '.') ?></span>
                    </div>
                </div>
            </div>
        </div>

        <div class="box box-primary">
            <div class="box-header with-border">
                <h3 class="box-title"><i class="fa fa-shopping-cart"></i> Daftar Escrow</h3>
            </div>
            <div class="box-body table-responsive">
                <table class="table table-bordered table-striped table-hover dataTable">
                    <thead><tr>
                        <th>Pesanan</th><th>Pembeli</th><th>Penjual</th>
                        <th>Nominal</th><th>Status</th><th>Settlement</th>
                        <th>Waktu</th><th>Aksi</th>
                    </tr></thead>
                    <tbody>
                    <?php foreach ($rows as $row): ?>
                        <tr>
                            <td>
                                <strong><?= html_escape($row['invoice_pesanan']) ?></strong><br>
                                <small class="text-muted">Pesanan: <?= html_escape($row['status_pesanan']) ?></small>
                            </td>
                            <td>
                                <?= html_escape($row['nama_pembeli']) ?><br>
                                <small><?= html_escape($row['kode_cabang_pembeli']) ?> • <?= html_escape($row['nama_cabang_pembeli']) ?></small>
                            </td>
                            <td>
                                <?= html_escape($row['nama_penjual']) ?><br>
                                <small><?= html_escape($row['nama_toko']) ?> • <?= html_escape($row['kode_cabang_penjual']) ?></small>
                            </td>
                            <td>
                                <strong>Rp <?= number_format((int) $row['total_dana'], 0, ',', '.') ?></strong><br>
                                <small class="text-muted">
                                    Barang Rp <?= number_format((int) $row['nominal_barang'], 0, ',', '.') ?>
                                    + ongkir Rp <?= number_format((int) $row['ongkir'], 0, ',', '.') ?>
                                </small>
                            </td>
                            <td>
                                <span class="label <?= $classes[$row['status']] ?? 'label-default' ?>">
                                    <?= html_escape($statusLabels[$row['status']] ?? $row['status']) ?>
                                </span>
                                <?php if (!empty($row['alasan_sengketa'])): ?>
                                    <br><small class="text-danger"><?= html_escape($row['alasan_sengketa']) ?></small>
                                <?php endif; ?>
                            </td>
                            <td>
                                <?php if (!empty($row['kode_kewajiban'])): ?>
                                    <?= html_escape($row['kode_kewajiban']) ?><br>
                                    <small><?= html_escape($row['status_kewajiban']) ?></small>
                                <?php else: ?><span class="text-muted">-</span><?php endif; ?>
                            </td>
                            <td>
                                Ditahan:<br><small><?= html_escape($row['ditahan_pada']) ?></small>
                                <?php if (!empty($row['sengketa_pada'])): ?>
                                    <br>Sengketa:<br><small><?= html_escape($row['sengketa_pada']) ?></small>
                                <?php endif; ?>
                            </td>
                            <td style="min-width:145px">
                                <?php if ($isSuperAdmin && $row['status'] === 'Sengketa'): ?>
                                    <?php if ($row['status_pesanan'] === 'Dikirim'): ?>
                                        <form action="<?= base_url('admin/escrow/cairkan/' . (int) $row['id_escrow']) ?>"
                                            method="POST" style="display:inline-block;margin-bottom:4px"
                                            onsubmit="return confirm('Cairkan dana kepada penjual?');">
                                            <input type="hidden" name="<?= $this->security->get_csrf_token_name() ?>"
                                                value="<?= $this->security->get_csrf_hash() ?>">
                                            <button class="btn btn-success btn-xs" type="submit"><i class="fa fa-check"></i> Cairkan</button>
                                        </form>
                                    <?php endif; ?>
                                    <button class="btn btn-danger btn-xs" type="button" data-toggle="modal"
                                        data-target="#refund<?= (int) $row['id_escrow'] ?>">
                                        <i class="fa fa-undo"></i> Refund
                                    </button>
                                <?php else: ?><span class="text-muted">-</span><?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
                <?php if (empty($rows)): ?>
                    <p class="text-center text-muted" style="margin:20px 0">Belum ada dana escrow marketplace.</p>
                <?php endif; ?>
            </div>
        </div>
    </section>
</div>

<?php if ($isSuperAdmin): ?>
<?php foreach ($rows as $row): if ($row['status'] !== 'Sengketa') continue; ?>
    <div class="modal fade" id="refund<?= (int) $row['id_escrow'] ?>" tabindex="-1" role="dialog">
        <div class="modal-dialog" role="document"><div class="modal-content">
            <form action="<?= base_url('admin/escrow/refund/' . (int) $row['id_escrow']) ?>" method="POST">
                <input type="hidden" name="<?= $this->security->get_csrf_token_name() ?>"
                    value="<?= $this->security->get_csrf_hash() ?>">
                <div class="modal-header">
                    <button type="button" class="close" data-dismiss="modal">&times;</button>
                    <h4 class="modal-title">Refund Dana Escrow</h4>
                </div>
                <div class="modal-body">
                    <p>Dana <strong><?= html_escape($row['invoice_pesanan']) ?></strong> akan dikembalikan kepada pembeli.</p>
                    <div class="form-group">
                        <label>Alasan keputusan</label>
                        <textarea name="alasan" class="form-control" rows="4"
                            minlength="10" maxlength="500" required></textarea>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-default" data-dismiss="modal">Batal</button>
                    <button type="submit" class="btn btn-danger"><i class="fa fa-undo"></i> Proses Refund</button>
                </div>
            </form>
        </div></div>
    </div>
<?php endforeach; ?>
<?php endif; ?>
